use std::collections::VecDeque;

use crate::kv::Hash;
use rpp_pruning::{
    BlockHeight, Commitment, Envelope, ParameterVersion, ProofSegment, SchemaVersion, SegmentIndex,
    Snapshot, TaggedDigest, COMMITMENT_TAG, ENVELOPE_TAG, PROOF_SEGMENT_TAG, SNAPSHOT_STATE_TAG,
};

const SNAPSHOT_PREFIX: &[u8] = b"fw-pruning-snapshot";
const SEGMENT_PREFIX: &[u8] = b"fw-pruning-segment";
const COMMITMENT_PREFIX: &[u8] = b"fw-pruning-commit";
const ENVELOPE_PREFIX: &[u8] = b"fw-pruning-envelope";

#[derive(Clone, Debug)]
struct SnapshotRecord {
    block_height: BlockHeight,
    state_commitment: TaggedDigest,
}

fn schema_version_from_digest(digest: &Hash) -> SchemaVersion {
    SchemaVersion::new(u16::from_be_bytes([digest[0], digest[1]]))
}

fn parameter_version_from_digest(digest: &Hash) -> ParameterVersion {
    ParameterVersion::new(u16::from_be_bytes([digest[0], digest[1]]))
}

fn compute_state_commitment(
    schema_digest: &Hash,
    parameter_digest: &Hash,
    block_height: BlockHeight,
    root: &Hash,
) -> TaggedDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SNAPSHOT_PREFIX);
    hasher.update(schema_digest);
    hasher.update(parameter_digest);
    hasher.update(&block_height.as_u64().to_be_bytes());
    hasher.update(root);
    TaggedDigest::new(SNAPSHOT_STATE_TAG, hasher.finalize().into())
}

fn compute_segment_commitment(
    schema_digest: &Hash,
    parameter_digest: &Hash,
    segment_index: SegmentIndex,
    start_height: BlockHeight,
    end_height: BlockHeight,
    state_commitment: TaggedDigest,
) -> TaggedDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SEGMENT_PREFIX);
    hasher.update(schema_digest);
    hasher.update(parameter_digest);
    hasher.update(&segment_index.as_u32().to_be_bytes());
    hasher.update(&start_height.as_u64().to_be_bytes());
    hasher.update(&end_height.as_u64().to_be_bytes());
    hasher.update(&state_commitment.prefixed_bytes());
    TaggedDigest::new(PROOF_SEGMENT_TAG, hasher.finalize().into())
}

fn compute_aggregate_commitment(
    schema_digest: &Hash,
    parameter_digest: &Hash,
    snapshot: &Snapshot,
    segments: &[ProofSegment],
) -> TaggedDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(COMMITMENT_PREFIX);
    hasher.update(schema_digest);
    hasher.update(parameter_digest);
    hasher.update(&snapshot.block_height().as_u64().to_be_bytes());
    hasher.update(&snapshot.state_commitment().prefixed_bytes());
    for segment in segments {
        hasher.update(&segment.segment_index().as_u32().to_be_bytes());
        hasher.update(&segment.start_height().as_u64().to_be_bytes());
        hasher.update(&segment.end_height().as_u64().to_be_bytes());
        hasher.update(&segment.segment_commitment().prefixed_bytes());
    }
    TaggedDigest::new(COMMITMENT_TAG, hasher.finalize().into())
}

fn compute_binding_digest(
    schema_digest: &Hash,
    parameter_digest: &Hash,
    snapshot: &Snapshot,
    segments: &[ProofSegment],
    commitment: &Commitment,
) -> TaggedDigest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ENVELOPE_PREFIX);
    hasher.update(schema_digest);
    hasher.update(parameter_digest);
    hasher.update(&snapshot.block_height().as_u64().to_be_bytes());
    hasher.update(&snapshot.state_commitment().prefixed_bytes());
    for segment in segments {
        hasher.update(&segment.segment_index().as_u32().to_be_bytes());
        hasher.update(&segment.start_height().as_u64().to_be_bytes());
        hasher.update(&segment.end_height().as_u64().to_be_bytes());
        hasher.update(&segment.segment_commitment().prefixed_bytes());
    }
    hasher.update(&commitment.aggregate_commitment().prefixed_bytes());
    TaggedDigest::new(ENVELOPE_TAG, hasher.finalize().into())
}

fn verify_with_digests(
    schema_digest: &Hash,
    parameter_digest: &Hash,
    root: Hash,
    proof: &PruningProof,
) -> bool {
    let schema_version = schema_version_from_digest(schema_digest);
    let parameter_version = parameter_version_from_digest(parameter_digest);

    if proof.schema_version() != schema_version || proof.parameter_version() != parameter_version {
        return false;
    }

    let snapshot = proof.snapshot();
    if snapshot.schema_version() != schema_version
        || snapshot.parameter_version() != parameter_version
    {
        return false;
    }

    let block_height = snapshot.block_height();
    let expected_state_commitment =
        compute_state_commitment(schema_digest, parameter_digest, block_height, &root);
    if snapshot.state_commitment() != expected_state_commitment {
        return false;
    }

    let segments = proof.segments();
    if segments.len() != 1 {
        return false;
    }

    let segment = &segments[0];
    if segment.schema_version() != schema_version
        || segment.parameter_version() != parameter_version
    {
        return false;
    }

    if segment.start_height() != block_height || segment.end_height() != block_height {
        return false;
    }

    let expected_segment_commitment = compute_segment_commitment(
        schema_digest,
        parameter_digest,
        segment.segment_index(),
        segment.start_height(),
        segment.end_height(),
        expected_state_commitment,
    );
    if segment.segment_commitment() != expected_segment_commitment {
        return false;
    }

    let expected_commitment_digest =
        compute_aggregate_commitment(schema_digest, parameter_digest, snapshot, segments);
    let Ok(expected_commitment) = Commitment::new(
        schema_version,
        parameter_version,
        expected_commitment_digest,
    ) else {
        return false;
    };

    if proof.commitment() != &expected_commitment {
        return false;
    }

    let expected_binding = compute_binding_digest(
        schema_digest,
        parameter_digest,
        snapshot,
        segments,
        proof.commitment(),
    );

    proof.binding_digest() == expected_binding
}

pub type PruningProof = Envelope;

/// Lightweight pruning manager that tracks block snapshots and constructs canonical envelopes.
#[derive(Debug)]
pub struct FirewoodPruner {
    snapshots: VecDeque<SnapshotRecord>,
    retain: usize,
    schema_digest: Hash,
    parameter_digest: Hash,
    schema_version: SchemaVersion,
    parameter_version: ParameterVersion,
}

impl FirewoodPruner {
    pub const DEFAULT_SCHEMA_DIGEST: Hash = [0x11; 32];
    pub const DEFAULT_PARAMETER_DIGEST: Hash = [0x22; 32];

    pub fn new(retain: usize) -> Self {
        Self::with_digests(
            retain,
            Self::DEFAULT_SCHEMA_DIGEST,
            Self::DEFAULT_PARAMETER_DIGEST,
        )
    }

    pub fn with_digests(retain: usize, schema_digest: Hash, parameter_digest: Hash) -> Self {
        let schema_version = schema_version_from_digest(&schema_digest);
        let parameter_version = parameter_version_from_digest(&parameter_digest);
        FirewoodPruner {
            snapshots: VecDeque::new(),
            retain: retain.max(1),
            schema_digest,
            parameter_digest,
            schema_version,
            parameter_version,
        }
    }

    pub fn prune_block(&mut self, block_id: u64, root: Hash) -> PruningProof {
        let block_height = BlockHeight::new(block_id);
        let state_commitment = compute_state_commitment(
            &self.schema_digest,
            &self.parameter_digest,
            block_height,
            &root,
        );
        let record = SnapshotRecord {
            block_height,
            state_commitment,
        };
        self.snapshots.push_back(record.clone());
        while self.snapshots.len() > self.retain {
            self.snapshots.pop_front();
        }

        let snapshot = Snapshot::new(
            self.schema_version,
            self.parameter_version,
            record.block_height,
            record.state_commitment,
        )
        .expect("state commitment must carry the snapshot tag");

        let segments = vec![ProofSegment::new(
            self.schema_version,
            self.parameter_version,
            SegmentIndex::new(0),
            record.block_height,
            record.block_height,
            compute_segment_commitment(
                &self.schema_digest,
                &self.parameter_digest,
                SegmentIndex::new(0),
                record.block_height,
                record.block_height,
                record.state_commitment,
            ),
        )
        .expect("segment commitment must carry the proof tag")];

        let commitment_digest = compute_aggregate_commitment(
            &self.schema_digest,
            &self.parameter_digest,
            &snapshot,
            &segments,
        );
        let commitment = Commitment::new(
            self.schema_version,
            self.parameter_version,
            commitment_digest,
        )
        .expect("aggregate commitment must carry the commitment tag");

        let binding_digest = compute_binding_digest(
            &self.schema_digest,
            &self.parameter_digest,
            &snapshot,
            &segments,
            &commitment,
        );

        Envelope::new(
            self.schema_version,
            self.parameter_version,
            snapshot,
            segments,
            commitment,
            binding_digest,
        )
        .expect("binding digest must carry the envelope tag")
    }

    pub fn verify_with_config(&self, root: Hash, proof: &PruningProof) -> bool {
        verify_with_digests(&self.schema_digest, &self.parameter_digest, root, proof)
    }

    pub fn verify_pruned_state(root: Hash, proof: &PruningProof) -> bool {
        Self::verify_pruned_state_with_digests(
            Self::DEFAULT_SCHEMA_DIGEST,
            Self::DEFAULT_PARAMETER_DIGEST,
            root,
            proof,
        )
    }

    pub fn verify_pruned_state_with_digests(
        schema_digest: Hash,
        parameter_digest: Hash,
        root: Hash,
        proof: &PruningProof,
    ) -> bool {
        verify_with_digests(&schema_digest, &parameter_digest, root, proof)
    }
}

#[cfg(test)]
mod tests_prop;
