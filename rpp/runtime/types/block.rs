use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::Arc;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher as Blake3Hasher;
use hex;

use crate::proof_backend::Blake2sHasher;
use ed25519_dalek::{PublicKey, Signature};
use malachite::Natural;
use serde::{Deserialize, Serialize};

use crate::consensus::{verify_vrf, BftVoteKind, ConsensusCertificate, SignedBftVote};
use crate::crypto::{
    signature_from_hex, signature_to_hex, verify_signature, vrf_public_key_from_hex,
};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::ReputationAudit;
#[cfg(feature = "backend-plonky3")]
use crate::plonky3::circuit::transaction::TransactionWitness as Plonky3TransactionWitness;
use crate::proof_system::ProofVerifierRegistry;
use crate::rpp::{ModuleWitnessBundle, ProofArtifact};
use crate::state::merkle::compute_merkle_root;
use crate::stwo::aggregation::StateCommitmentSnapshot;
use crate::stwo::proof::ProofPayload;
use crate::vrf::VrfProof;

use serde_json;

use storage_firewood::pruning::FirewoodPruner;

use super::{
    identity::{IDENTITY_ATTESTATION_GOSSIP_MIN, IDENTITY_ATTESTATION_QUORUM},
    Address, AttestedIdentityRequest, BlockProofBundle, ChainProof, SignedTransaction, UptimeProof,
};
use self::pruning_ext::PruningProofExt;

use rpp_pruning::{
    BlockHeight, Commitment, DomainTag, ParameterVersion, ProofSegment, SchemaVersion,
    SegmentIndex, Snapshot, TaggedDigest, COMMITMENT_TAG, DIGEST_LENGTH, DOMAIN_TAG_LENGTH,
    ENVELOPE_TAG, PROOF_SEGMENT_TAG, SNAPSHOT_STATE_TAG,
};

const ZERO_DIGEST_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const PRUNING_SCHEMA_VERSION: SchemaVersion = SchemaVersion::new(1);
const PRUNING_PARAMETER_VERSION: ParameterVersion = ParameterVersion::new(0);
const PRUNING_SEGMENT_INDEX: SegmentIndex = SegmentIndex::new(0);
const PRUNING_AGGREGATE_PREFIX: &[u8] = b"rpp:prune:aggregate:v1";
const PRUNING_BINDING_PREFIX: &[u8] = b"rpp:prune:binding:v1";
const RECURSIVE_ANCHOR_SEED: &[u8] = b"rpp-recursive-anchor";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: u64,
    pub previous_hash: String,
    pub tx_root: String,
    pub state_root: String,
    pub utxo_root: String,
    pub reputation_root: String,
    pub timetoke_root: String,
    pub zsi_root: String,
    pub proof_root: String,
    pub total_stake: String,
    pub randomness: String,
    pub vrf_public_key: String,
    pub vrf_preoutput: String,
    pub vrf_proof: String,
    pub timestamp: u64,
    pub proposer: Address,
    pub leader_tier: String,
    pub leader_timetoke: u64,
}

impl BlockHeader {
    pub fn new(
        height: u64,
        previous_hash: String,
        tx_root: String,
        state_root: String,
        utxo_root: String,
        reputation_root: String,
        timetoke_root: String,
        zsi_root: String,
        proof_root: String,
        total_stake: String,
        randomness: String,
        vrf_public_key: String,
        vrf_preoutput: String,
        vrf_proof: String,
        proposer: Address,
        leader_tier: String,
        leader_timetoke: u64,
    ) -> Self {
        Self {
            height,
            previous_hash,
            tx_root,
            state_root,
            utxo_root,
            reputation_root,
            timetoke_root,
            zsi_root,
            proof_root,
            total_stake,
            randomness,
            vrf_public_key,
            vrf_preoutput,
            vrf_proof,
            proposer,
            leader_tier,
            leader_timetoke,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializing block header")
    }

    pub fn hash(&self) -> [u8; 32] {
        let bytes = self.canonical_bytes();
        Blake2sHasher::hash(bytes.as_slice()).into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimetokeUpdate {
    pub identity: Address,
    pub window_start: u64,
    pub window_end: u64,
    pub credited_hours: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationUpdate {
    pub identity: Address,
    pub new_score: f64,
    pub new_tier: String,
    pub uptime_hours: u64,
    pub consensus_success: u64,
    pub peer_feedback: i64,
    pub zsi_validated: bool,
}

impl From<ReputationAudit> for ReputationUpdate {
    fn from(audit: ReputationAudit) -> Self {
        Self {
            identity: audit.address,
            new_score: audit.score,
            new_tier: audit.tier.to_string(),
            uptime_hours: audit.uptime_hours,
            consensus_success: audit.consensus_success,
            peer_feedback: audit.peer_feedback,
            zsi_validated: audit.zsi_validated,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofSystem {
    Stwo,
    Plonky3,
    RppStark,
}

impl Default for ProofSystem {
    fn default() -> Self {
        ProofSystem::Stwo
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct TaggedDigestHex(String);

impl TaggedDigestHex {
    pub fn from_tagged_digest(digest: &TaggedDigest) -> Self {
        Self(hex::encode(digest.prefixed_bytes()))
    }

    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_tagged_digest(
        &self,
        label: &str,
        expected_tag: DomainTag,
    ) -> ChainResult<TaggedDigest> {
        Self::parse(expected_tag, label, &self.0)
    }

    pub fn parse(expected_tag: DomainTag, label: &str, value: &str) -> ChainResult<TaggedDigest> {
        parse_tagged_digest_hex(expected_tag, label, value)
    }
}

impl From<TaggedDigestHex> for String {
    fn from(value: TaggedDigestHex) -> Self {
        value.into_inner()
    }
}

impl From<&TaggedDigest> for TaggedDigestHex {
    fn from(digest: &TaggedDigest) -> Self {
        Self::from_tagged_digest(digest)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruningSnapshotMetadata {
    pub schema_version: u16,
    pub parameter_version: u16,
    pub block_height: u64,
    pub state_commitment: TaggedDigestHex,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruningSegmentMetadata {
    pub schema_version: u16,
    pub parameter_version: u16,
    pub segment_index: u32,
    pub start_height: u64,
    pub end_height: u64,
    pub segment_commitment: TaggedDigestHex,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruningCommitmentMetadata {
    pub schema_version: u16,
    pub parameter_version: u16,
    pub aggregate_commitment: TaggedDigestHex,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruningEnvelopeMetadata {
    pub schema_version: u16,
    pub parameter_version: u16,
    pub snapshot: PruningSnapshotMetadata,
    pub segments: Vec<PruningSegmentMetadata>,
    pub commitment: PruningCommitmentMetadata,
    pub binding_digest: TaggedDigestHex,
}

mod pruning_ext {
    use super::{
        compute_pruning_aggregate, compute_pruning_binding, decode_hex_digest,
        decode_tagged_digest, derive_version_digest, encode_tagged_digest_hex, Block, BlockHeader,
        ChainError, ChainResult, PruningCommitmentMetadata, PruningEnvelopeMetadata,
        PruningSegmentMetadata, PruningSnapshotMetadata, TaggedDigestHex, ZERO_DIGEST_HEX,
        PRUNING_PARAMETER_VERSION, PRUNING_SCHEMA_VERSION, PRUNING_SEGMENT_INDEX,
    };
    use crate::PruningProof;
    use rpp_pruning::{
        BlockHeight, Commitment, ParameterVersion, ProofSegment, SchemaVersion, SegmentIndex,
        Snapshot, TaggedDigest, COMMITMENT_TAG, ENVELOPE_TAG, PROOF_SEGMENT_TAG, SNAPSHOT_STATE_TAG,
    };
    use storage_firewood::pruning::FirewoodPruner;

    pub trait PruningProofExt {
        fn envelope_metadata(&self) -> PruningEnvelopeMetadata;
        fn binding_digest(&self) -> TaggedDigest;
        fn aggregate_commitment(&self) -> TaggedDigest;
        fn snapshot_metadata(&self) -> PruningSnapshotMetadata;
        fn segment_metadata(&self) -> Vec<PruningSegmentMetadata>;
        fn commitment_metadata(&self) -> PruningCommitmentMetadata;
        fn binding_digest_hex(&self) -> String;
        fn aggregate_commitment_hex(&self) -> String;
        fn schema_version(&self) -> u16;
        fn parameter_version(&self) -> u16;
        fn snapshot_height(&self) -> u64;
        fn snapshot_state_root_hex(&self) -> String;
        fn pruned_transaction_root_hex(&self) -> Option<String>;
        fn verify(&self, previous: Option<&Block>, header: &BlockHeader) -> ChainResult<()>;
    }

    impl PruningProofExt for PruningProof {
        fn envelope_metadata(&self) -> PruningEnvelopeMetadata {
            let snapshot = self.snapshot();
            let snapshot_metadata = PruningSnapshotMetadata {
                schema_version: u16::from(snapshot.schema_version()),
                parameter_version: u16::from(snapshot.parameter_version()),
                block_height: snapshot.block_height().as_u64(),
                state_commitment: TaggedDigestHex::from(&snapshot.state_commitment()),
            };
            let segment_metadata = self.segments()
                .iter()
                .map(|segment| PruningSegmentMetadata {
                    schema_version: u16::from(segment.schema_version()),
                    parameter_version: u16::from(segment.parameter_version()),
                    segment_index: u32::from(segment.segment_index()),
                    start_height: segment.start_height().as_u64(),
                    end_height: segment.end_height().as_u64(),
                    segment_commitment: TaggedDigestHex::from(&segment.segment_commitment()),
                })
                .collect();
            let commitment = self.commitment();
            let commitment_metadata = PruningCommitmentMetadata {
                schema_version: u16::from(commitment.schema_version()),
                parameter_version: u16::from(commitment.parameter_version()),
                aggregate_commitment: TaggedDigestHex::from(&commitment.aggregate_commitment()),
            };
            PruningEnvelopeMetadata {
                schema_version: u16::from(self.schema_version()),
                parameter_version: u16::from(self.parameter_version()),
                snapshot: snapshot_metadata,
                segments: segment_metadata,
                commitment: commitment_metadata,
                binding_digest: TaggedDigestHex::from(&self.binding_digest()),
            }
        }

        fn binding_digest(&self) -> TaggedDigest {
            self.binding_digest()
        }

        fn aggregate_commitment(&self) -> TaggedDigest {
            self.commitment().aggregate_commitment()
        }

        fn snapshot_metadata(&self) -> PruningSnapshotMetadata {
            let snapshot = self.snapshot();
            PruningSnapshotMetadata {
                schema_version: u16::from(snapshot.schema_version()),
                parameter_version: u16::from(snapshot.parameter_version()),
                block_height: snapshot.block_height().as_u64(),
                state_commitment: TaggedDigestHex::from(&snapshot.state_commitment()),
            }
        }

        fn segment_metadata(&self) -> Vec<PruningSegmentMetadata> {
            self.segments()
                .iter()
                .map(|segment| PruningSegmentMetadata {
                    schema_version: u16::from(segment.schema_version()),
                    parameter_version: u16::from(segment.parameter_version()),
                    segment_index: u32::from(segment.segment_index()),
                    start_height: segment.start_height().as_u64(),
                    end_height: segment.end_height().as_u64(),
                    segment_commitment: TaggedDigestHex::from(&segment.segment_commitment()),
                })
                .collect()
        }

        fn commitment_metadata(&self) -> PruningCommitmentMetadata {
            let commitment = self.commitment();
            PruningCommitmentMetadata {
                schema_version: u16::from(commitment.schema_version()),
                parameter_version: u16::from(commitment.parameter_version()),
                aggregate_commitment: TaggedDigestHex::from(&commitment.aggregate_commitment()),
            }
        }

        fn binding_digest_hex(&self) -> String {
            encode_tagged_digest_hex(&self.binding_digest())
        }

        fn aggregate_commitment_hex(&self) -> String {
            encode_tagged_digest_hex(&self.commitment().aggregate_commitment())
        }

        fn schema_version(&self) -> u16 {
            u16::from(self.schema_version())
        }

        fn parameter_version(&self) -> u16 {
            u16::from(self.parameter_version())
        }

        fn snapshot_height(&self) -> u64 {
            self.snapshot().block_height().as_u64()
        }

        fn snapshot_state_root_hex(&self) -> String {
            TaggedDigestHex::from(&self.snapshot().state_commitment()).into_inner()
        }

        fn pruned_transaction_root_hex(&self) -> Option<String> {
            self.segments()
                .iter()
                .find(|segment| segment.segment_index() == PRUNING_SEGMENT_INDEX)
                .map(|segment| TaggedDigestHex::from(&segment.segment_commitment()).into_inner())
        }

        fn verify(&self, previous: Option<&Block>, header: &BlockHeader) -> ChainResult<()> {
            if self.schema_version() != PRUNING_SCHEMA_VERSION {
                return Err(ChainError::Crypto(
                    "pruning proof schema version mismatch".into(),
                ));
            }
            if self.parameter_version() != PRUNING_PARAMETER_VERSION {
                return Err(ChainError::Crypto(
                    "pruning proof parameter version mismatch".into(),
                ));
            }

            let snapshot = self.snapshot();
            if snapshot.schema_version() != PRUNING_SCHEMA_VERSION
                || snapshot.parameter_version() != PRUNING_PARAMETER_VERSION
            {
                return Err(ChainError::Crypto(
                    "pruning proof snapshot version mismatch".into(),
                ));
            }

            let snapshot_height = snapshot.block_height().as_u64();
            let expected_snapshot_height = previous
                .map(|block| block.header.height)
                .unwrap_or_else(|| header.height.saturating_sub(1));
            if snapshot_height != expected_snapshot_height {
                return Err(ChainError::Crypto("pruning proof height mismatch".into()));
            }

            let snapshot_state_digest = *snapshot.state_commitment().digest();

            if let Some(prev_block) = previous {
                if hex::encode(snapshot_state_digest) != prev_block.header.state_root {
                    return Err(ChainError::Crypto(
                        "pruning proof previous state root mismatch".into(),
                    ));
                }
            } else if header.height == 0 && snapshot_height != 0 {
                return Err(ChainError::Crypto(
                    "genesis pruning proof references non-zero height".into(),
                ));
            }

            let segments = self.segments();
            if segments.len() != 1 {
                return Err(ChainError::Crypto(
                    "pruning proof must carry exactly one proof segment".into(),
                ));
            }

            let segment = &segments[0];
            if segment.schema_version() != PRUNING_SCHEMA_VERSION
                || segment.parameter_version() != PRUNING_PARAMETER_VERSION
            {
                return Err(ChainError::Crypto(
                    "pruning proof segment version mismatch".into(),
                ));
            }
            if segment.segment_index() != PRUNING_SEGMENT_INDEX {
                return Err(ChainError::Crypto(
                    "pruning proof segment index mismatch".into(),
                ));
            }
            if segment.start_height().as_u64() != snapshot_height
                || segment.end_height().as_u64() != snapshot_height
            {
                return Err(ChainError::Crypto(
                    "pruning proof segment height range mismatch".into(),
                ));
            }

            let segment_commitment = *segment.segment_commitment().digest();

            if let Some(prev_block) = previous {
                if hex::encode(segment_commitment) != prev_block.header.tx_root {
                    return Err(ChainError::Crypto(
                        "pruning proof transaction commitment mismatch".into(),
                    ));
                }
            }

            let previous_hash = decode_hex_digest("previous block hash", &header.previous_hash)?;
            let aggregate = compute_pruning_aggregate(
                snapshot_height,
                &previous_hash,
                &snapshot_state_digest,
                &segment_commitment,
            );

            let commitment = self.commitment();
            if commitment.schema_version() != PRUNING_SCHEMA_VERSION
                || commitment.parameter_version() != PRUNING_PARAMETER_VERSION
            {
                return Err(ChainError::Crypto(
                    "pruning proof commitment version mismatch".into(),
                ));
            }
            if commitment.aggregate_commitment() != aggregate {
                return Err(ChainError::Crypto(
                    "pruning proof aggregate commitment mismatch".into(),
                ));
            }

            let resulting_state_root = decode_hex_digest("resulting state root", &header.state_root)?;
            let expected_binding = compute_pruning_binding(&aggregate, &resulting_state_root);
            if self.binding_digest() != expected_binding {
                return Err(ChainError::Crypto(
                    "pruning proof binding digest mismatch".into(),
                ));
            }

            if let Some(_) = previous {
                let schema_digest = derive_version_digest(u16::from(self.schema_version()));
                let parameter_digest = derive_version_digest(u16::from(self.parameter_version()));
                let firewood_envelope: &storage_firewood::pruning::PruningProof = self;

                if !FirewoodPruner::verify_pruned_state_with_digests(
                    schema_digest,
                    parameter_digest,
                    snapshot_state_digest,
                    firewood_envelope,
                ) {
                    return Err(ChainError::Crypto(
                        "pruning proof inconsistent with pruning state digests".into(),
                    ));
                }
            }

            Ok(())
        }
    }

    pub fn pruning_from_metadata(metadata: PruningEnvelopeMetadata) -> ChainResult<PruningProof> {
        let snapshot_meta = metadata.snapshot;
        let state_commitment = snapshot_meta
            .state_commitment
            .to_tagged_digest("snapshot state commitment", SNAPSHOT_STATE_TAG)?;
        let snapshot = Snapshot::new(
            SchemaVersion::new(snapshot_meta.schema_version),
            ParameterVersion::new(snapshot_meta.parameter_version),
            BlockHeight::new(snapshot_meta.block_height),
            state_commitment,
        )
        .map_err(|err| ChainError::Crypto(format!("invalid pruning snapshot: {err}")))?;

        let mut segments = Vec::with_capacity(metadata.segments.len());
        for segment_meta in metadata.segments {
            let segment_commitment = segment_meta
                .segment_commitment
                .to_tagged_digest("pruning segment commitment", PROOF_SEGMENT_TAG)?;
            let segment = ProofSegment::new(
                SchemaVersion::new(segment_meta.schema_version),
                ParameterVersion::new(segment_meta.parameter_version),
                SegmentIndex::new(segment_meta.segment_index),
                BlockHeight::new(segment_meta.start_height),
                BlockHeight::new(segment_meta.end_height),
                segment_commitment,
            )
            .map_err(|err| ChainError::Crypto(format!("invalid pruning segment: {err}")))?;
            segments.push(segment);
        }

        let commitment_meta = metadata.commitment;
        let aggregate_commitment = commitment_meta
            .aggregate_commitment
            .to_tagged_digest("pruning aggregate commitment", COMMITMENT_TAG)?;
        let commitment = Commitment::new(
            SchemaVersion::new(commitment_meta.schema_version),
            ParameterVersion::new(commitment_meta.parameter_version),
            aggregate_commitment,
        )
        .map_err(|err| ChainError::Crypto(format!("invalid pruning commitment: {err}")))?;

        let binding = metadata
            .binding_digest
            .to_tagged_digest("pruning binding digest", ENVELOPE_TAG)?;

        let envelope = rpp_pruning::Envelope::new(
            SchemaVersion::new(metadata.schema_version),
            ParameterVersion::new(metadata.parameter_version),
            snapshot,
            segments,
            commitment,
            binding,
        )
        .map_err(|err| ChainError::Crypto(format!("invalid pruning envelope: {err}")))?;

        Ok(Arc::new(envelope))
    }

    pub fn pruning_genesis(state_root: &str) -> PruningProof {
        canonical_pruning_genesis(state_root)
            .expect("genesis pruning envelope must be valid")
    }

    pub fn canonical_pruning_genesis(state_root: &str) -> ChainResult<PruningProof> {
        canonical_pruning_from_parts(
            0,
            ZERO_DIGEST_HEX,
            state_root,
            ZERO_DIGEST_HEX,
            state_root,
        )
    }

    pub fn pruning_from_previous(
        previous: Option<&Block>,
        current_header: &BlockHeader,
    ) -> PruningProof {
        canonical_pruning_from_block(previous, current_header)
            .expect("pruning envelope must be valid")
    }

    pub fn canonical_pruning_from_block(
        previous: Option<&Block>,
        current_header: &BlockHeader,
    ) -> ChainResult<PruningProof> {
        match previous {
            Some(block) => canonical_pruning_from_parts(
                block.header.height,
                &block.hash,
                &block.header.state_root,
                &block.header.tx_root,
                &current_header.state_root,
            ),
            None => canonical_pruning_from_parts(
                current_header.height.saturating_sub(1),
                &current_header.previous_hash,
                &current_header.state_root,
                ZERO_DIGEST_HEX,
                &current_header.state_root,
            ),
        }
    }

    pub fn canonical_pruning_from_parts(
        pruned_height: u64,
        previous_block_hash: &str,
        previous_state_root: &str,
        pruned_tx_root: &str,
        resulting_state_root: &str,
    ) -> ChainResult<PruningProof> {
        build_pruning_envelope(
            pruned_height,
            previous_block_hash,
            previous_state_root,
            pruned_tx_root,
            resulting_state_root,
        )
    }

    fn build_pruning_envelope(
        pruned_height: u64,
        previous_block_hash: &str,
        previous_state_root: &str,
        pruned_tx_root: &str,
        resulting_state_root: &str,
    ) -> ChainResult<PruningProof> {
        let block_height = BlockHeight::new(pruned_height);
        let state_digest = decode_tagged_digest(
            SNAPSHOT_STATE_TAG,
            "previous state root",
            previous_state_root,
        )?;
        let snapshot = Snapshot::new(
            PRUNING_SCHEMA_VERSION,
            PRUNING_PARAMETER_VERSION,
            block_height,
            state_digest,
        )
        .map_err(|err| ChainError::Crypto(format!("invalid pruning snapshot: {err}")))?;

        let segment_digest =
            decode_tagged_digest(PROOF_SEGMENT_TAG, "pruned transaction root", pruned_tx_root)?;
        let segment = ProofSegment::new(
            PRUNING_SCHEMA_VERSION,
            PRUNING_PARAMETER_VERSION,
            PRUNING_SEGMENT_INDEX,
            block_height,
            block_height,
            segment_digest,
        )
        .map_err(|err| ChainError::Crypto(format!("invalid pruning segment: {err}")))?;

        let previous_hash = decode_hex_digest("previous block hash", previous_block_hash)?;
        let aggregate = super::compute_pruning_aggregate(
            pruned_height,
            &previous_hash,
            snapshot.state_commitment().digest(),
            segment.segment_commitment().digest(),
        );
        let commitment =
            Commitment::new(PRUNING_SCHEMA_VERSION, PRUNING_PARAMETER_VERSION, aggregate)
                .map_err(|err| ChainError::Crypto(format!("invalid pruning commitment: {err}")))?;

        let resulting_state = decode_hex_digest("resulting state root", resulting_state_root)?;
        let binding = super::compute_pruning_binding(
            &commitment.aggregate_commitment(),
            &resulting_state,
        );

        Ok(Arc::new(rpp_pruning::Envelope::new(
            PRUNING_SCHEMA_VERSION,
            PRUNING_PARAMETER_VERSION,
            snapshot,
            vec![segment],
            commitment,
            binding,
        )
        .map_err(|err| ChainError::Crypto(format!("invalid pruning envelope: {err}")))?))
    }
}

pub use pruning_ext::{
    canonical_pruning_from_block, canonical_pruning_from_parts, canonical_pruning_genesis,
    pruning_from_metadata, pruning_from_previous, pruning_genesis, PruningProofExt,
};

fn decode_hex_digest(label: &str, value: &str) -> ChainResult<[u8; 32]> {
    let bytes = hex::decode(value)
        .map_err(|err| ChainError::Crypto(format!("{label} is not valid hex encoding: {err}")))?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ChainError::Crypto(format!("{label} must encode exactly 32 bytes")))?;
    Ok(array)
}

fn encode_tagged_digest_hex(digest: &TaggedDigest) -> String {
    hex::encode(digest.prefixed_bytes())
}

fn derive_version_digest(version: u16) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest[..2].copy_from_slice(&version.to_be_bytes());
    digest
}

fn parse_tagged_digest_hex(
    expected_tag: DomainTag,
    label: &str,
    value: &str,
) -> ChainResult<TaggedDigest> {
    let bytes = hex::decode(value)
        .map_err(|err| ChainError::Crypto(format!("{label} is not valid hex encoding: {err}")))?;
    let expected_length = DOMAIN_TAG_LENGTH + DIGEST_LENGTH;
    if bytes.len() != expected_length {
        return Err(ChainError::Crypto(format!(
            "{label} must encode exactly {expected_length} bytes"
        )));
    }
    let (tag_bytes, digest_bytes) = bytes.split_at(DOMAIN_TAG_LENGTH);
    let tag_bytes: [u8; DOMAIN_TAG_LENGTH] = tag_bytes.try_into().map_err(|_| {
        ChainError::Crypto(format!(
            "{label} must encode exactly {expected_length} bytes"
        ))
    })?;
    let digest_bytes: [u8; DIGEST_LENGTH] = digest_bytes.try_into().map_err(|_| {
        ChainError::Crypto(format!(
            "{label} must encode exactly {expected_length} bytes"
        ))
    })?;
    let digest = TaggedDigest::new(DomainTag::new(tag_bytes), digest_bytes);
    digest
        .ensure_tag(expected_tag)
        .map_err(|err| ChainError::Crypto(format!("{label} has invalid domain tag: {err}")))?;
    Ok(digest)
}

fn decode_tagged_digest(
    tag: rpp_pruning::DomainTag,
    label: &str,
    value: &str,
) -> ChainResult<TaggedDigest> {
    Ok(TaggedDigest::new(tag, decode_hex_digest(label, value)?))
}

fn parse_tagged_digest_with_legacy(
    expected_tag: DomainTag,
    label: &str,
    value: &str,
) -> ChainResult<TaggedDigest> {
    let expected_length = (DOMAIN_TAG_LENGTH + DIGEST_LENGTH) * 2;
    if value.len() == expected_length {
        TaggedDigestHex::parse(expected_tag, label, value)
    } else {
        decode_tagged_digest(expected_tag, label, value)
    }
}

pub(super) fn compute_pruning_aggregate(
    pruned_height: u64,
    previous_hash: &[u8; 32],
    previous_state_root: &[u8; 32],
    pruned_tx_root: &[u8; 32],
) -> TaggedDigest {
    let mut hasher = Blake3Hasher::new();
    hasher.update(PRUNING_AGGREGATE_PREFIX);
    hasher.update(&pruned_height.to_be_bytes());
    hasher.update(previous_hash);
    hasher.update(previous_state_root);
    hasher.update(pruned_tx_root);
    TaggedDigest::new(COMMITMENT_TAG, hasher.finalize().into())
}

pub(super) fn compute_pruning_binding(
    aggregate: &TaggedDigest,
    resulting_state_root: &[u8; 32],
) -> TaggedDigest {
    let mut hasher = Blake3Hasher::new();
    hasher.update(PRUNING_BINDING_PREFIX);
    hasher.update(&aggregate.prefixed_bytes());
    hasher.update(resulting_state_root);
    TaggedDigest::new(ENVELOPE_TAG, hasher.finalize().into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveProof {
    pub system: ProofSystem,
    pub commitment: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_commitment: Option<String>,
    pub proof: ChainProof,
}

impl RecursiveProof {
    pub fn anchor() -> String {
        hex::encode::<[u8; 32]>(Blake2sHasher::hash(RECURSIVE_ANCHOR_SEED).into())
    }

    pub fn genesis(
        header: &BlockHeader,
        pruning: &PruningProof,
        proof: &ChainProof,
    ) -> ChainResult<Self> {
        Self::from_proof(header, pruning, None, proof)
    }

    pub fn from_parts(
        system: ProofSystem,
        commitment: String,
        previous_commitment: Option<String>,
        proof: ChainProof,
    ) -> ChainResult<Self> {
        #[cfg(not(feature = "backend-plonky3"))]
        if matches!(system, ProofSystem::Plonky3) {
            return Err(ChainError::Crypto(
                "Plonky3 backend not enabled for recursive proof verification".into(),
            ));
        }

        #[cfg(not(feature = "backend-rpp-stark"))]
        if matches!(system, ProofSystem::RppStark) {
            return Err(ChainError::Crypto(
                "RPP-STARK backend not enabled for recursive proof verification".into(),
            ));
        }

        let derived = match &proof {
            ChainProof::Stwo(_) => ProofSystem::Stwo,
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => ProofSystem::Plonky3,
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => ProofSystem::RppStark,
        };

        if derived != system {
            return Err(ChainError::Crypto(
                "recursive proof system does not match embedded artifact".into(),
            ));
        }

        let expected = Self::extract_commitment(&proof)?;
        if expected != commitment {
            return Err(ChainError::Crypto(
                "recursive proof commitment does not match embedded proof".into(),
            ));
        }

        Ok(Self {
            system,
            commitment,
            previous_commitment,
            proof,
        })
    }

    pub fn extend(
        previous: &RecursiveProof,
        header: &BlockHeader,
        pruning: &PruningProof,
        proof: &ChainProof,
    ) -> ChainResult<Self> {
        Self::from_proof(header, pruning, Some(previous), proof)
    }

    fn from_proof(
        header: &BlockHeader,
        pruning: &PruningProof,
        previous: Option<&RecursiveProof>,
        proof: &ChainProof,
    ) -> ChainResult<Self> {
        let commitment = Self::extract_commitment(proof)?;
        let previous_commitment = previous.map(|proof| proof.commitment.clone());
        let previous_commitment = if header.height == 0 {
            Some(Self::anchor())
        } else {
            previous_commitment
        };
        let system = match proof {
            ChainProof::Stwo(_) => ProofSystem::Stwo,
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => ProofSystem::Plonky3,
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => ProofSystem::RppStark,
        };
        let instance = Self {
            system,
            commitment,
            previous_commitment,
            proof: proof.clone(),
        };
        instance.verify(header, pruning, previous)?;
        Ok(instance)
    }

    fn extract_commitment(proof: &ChainProof) -> ChainResult<String> {
        match proof {
            ChainProof::Stwo(inner) => Ok(inner.commitment.clone()),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(value) => value
                .get("payload")
                .and_then(|payload| payload.get("commitment"))
                .and_then(|commitment| commitment.as_str())
                .map(|commitment| commitment.to_string())
                .ok_or_else(|| {
                    ChainError::Crypto("plonky3 recursive proof payload missing commitment".into())
                }),
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => Err(ChainError::Crypto(
                "rpp-stark recursive proofs do not encode commitments".into(),
            )),
        }
    }

    pub fn verify(
        &self,
        header: &BlockHeader,
        pruning: &PruningProof,
        previous: Option<&RecursiveProof>,
    ) -> ChainResult<()> {
        self.ensure_system_matches()?;
        self.verify_previous_link(previous)?;
        self.verify_commitment_matches_proof()?;
        match self.system {
            ProofSystem::Stwo => self.verify_stwo(header, pruning, previous),
            ProofSystem::Plonky3 => self.verify_plonky3(previous),
            ProofSystem::RppStark => Err(ChainError::Crypto(
                "rpp-stark recursive proof verification is not supported".into(),
            )),
        }?;
        Ok(())
    }

    fn ensure_system_matches(&self) -> ChainResult<()> {
        let derived = match &self.proof {
            ChainProof::Stwo(_) => ProofSystem::Stwo,
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => ProofSystem::Plonky3,
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => ProofSystem::RppStark,
        };
        if derived != self.system {
            return Err(ChainError::Crypto(
                "recursive proof system does not match embedded artifact".into(),
            ));
        }
        Ok(())
    }

    fn verify_previous_link(&self, previous: Option<&RecursiveProof>) -> ChainResult<()> {
        match previous {
            Some(prev) => {
                let expected = &prev.commitment;
                match self.previous_commitment.as_deref() {
                    Some(actual) if actual == expected => Ok(()),
                    Some(_) => Err(ChainError::Crypto(
                        "recursive proof previous commitment mismatch".into(),
                    )),
                    None => Err(ChainError::Crypto(
                        "recursive proof missing previous commitment".into(),
                    )),
                }
            }
            None => match self.previous_commitment.as_deref() {
                Some(previous) => {
                    if previous != Self::anchor() {
                        Err(ChainError::Crypto("recursive proof anchor mismatch".into()))
                    } else {
                        Ok(())
                    }
                }
                None => Err(ChainError::Crypto(
                    "recursive proof missing anchor commitment".into(),
                )),
            },
        }
    }

    fn verify_commitment_matches_proof(&self) -> ChainResult<()> {
        let expected = Self::extract_commitment(&self.proof)?;
        if expected != self.commitment {
            return Err(ChainError::Crypto(
                "recursive proof commitment does not match embedded proof".into(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "prover-stwo")]
    fn verify_stwo(
        &self,
        header: &BlockHeader,
        pruning: &PruningProof,
        previous: Option<&RecursiveProof>,
    ) -> ChainResult<()> {
        #[cfg(not(test))]
        {
            use crate::proof_system::ProofVerifier;
            use crate::stwo::verifier::NodeVerifier;
            let verifier = NodeVerifier::new();
            verifier.verify_recursive(&self.proof)?;
        }

        let stark = self.proof.expect_stwo()?;
        let witness = match &stark.payload {
            ProofPayload::Recursive(witness) => witness,
            _ => {
                return Err(ChainError::Crypto(
                    "recursive proof missing recursive witness payload".into(),
                ));
            }
        };

        if witness.aggregated_commitment != self.commitment {
            return Err(ChainError::Crypto(
                "recursive witness aggregated commitment mismatch".into(),
            ));
        }

        match (previous, witness.previous_commitment.as_deref()) {
            (Some(prev), Some(actual)) if actual == prev.commitment => {}
            (Some(_), Some(_)) => {
                return Err(ChainError::Crypto(
                    "recursive witness previous commitment mismatch".into(),
                ));
            }
            (Some(_), None) => {
                return Err(ChainError::Crypto(
                    "recursive witness missing previous commitment".into(),
                ));
            }
            (None, Some(actual)) => {
                if actual != Self::anchor() {
                    return Err(ChainError::Crypto(
                        "recursive witness anchor mismatch".into(),
                    ));
                }
            }
            (None, None) => {
                return Err(ChainError::Crypto(
                    "recursive witness missing anchor".into(),
                ));
            }
        }

        let witness_pruning_commitment = parse_tagged_digest_with_legacy(
            ENVELOPE_TAG,
            "recursive witness pruning commitment",
            &witness.pruning_commitment,
        )?;

        if witness_pruning_commitment != pruning.binding_digest() {
            return Err(ChainError::Crypto(
                "recursive witness pruning commitment mismatch".into(),
            ));
        }

        let expected_state = [
            (
                &witness.global_state_root,
                &header.state_root,
                "global state root",
            ),
            (&witness.utxo_root, &header.utxo_root, "utxo root"),
            (
                &witness.reputation_root,
                &header.reputation_root,
                "reputation root",
            ),
            (
                &witness.timetoke_root,
                &header.timetoke_root,
                "timetoke root",
            ),
            (&witness.zsi_root, &header.zsi_root, "zsi root"),
            (&witness.proof_root, &header.proof_root, "proof root"),
        ];
        for (actual, expected, label) in expected_state {
            if actual != expected {
                return Err(ChainError::Crypto(format!(
                    "recursive witness {label} mismatch"
                )));
            }
        }

        if witness.block_height != header.height {
            return Err(ChainError::Crypto(
                "recursive witness block height mismatch".into(),
            ));
        }
        Ok(())
    }

    #[cfg(not(feature = "prover-stwo"))]
    fn verify_stwo(
        &self,
        _header: &BlockHeader,
        _pruning: &PruningProof,
        _previous: Option<&RecursiveProof>,
    ) -> ChainResult<()> {
        Err(ChainError::Crypto(
            "STWO backend not enabled for recursive proof verification".into(),
        ))
    }

    #[cfg(feature = "backend-plonky3")]
    fn verify_plonky3(&self, _previous: Option<&RecursiveProof>) -> ChainResult<()> {
        use crate::plonky3::verifier::Plonky3Verifier;
        use crate::proof_system::ProofVerifier;

        let verifier = Plonky3Verifier::default();
        verifier.verify_recursive(&self.proof)
    }

    #[cfg(not(feature = "backend-plonky3"))]
    fn verify_plonky3(&self, _previous: Option<&RecursiveProof>) -> ChainResult<()> {
        Err(ChainError::Crypto(
            "Plonky3 backend not enabled for recursive proof verification".into(),
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub identities: Vec<AttestedIdentityRequest>,
    pub transactions: Vec<SignedTransaction>,
    pub uptime_proofs: Vec<UptimeProof>,
    pub timetoke_updates: Vec<TimetokeUpdate>,
    pub reputation_updates: Vec<ReputationUpdate>,
    pub bft_votes: Vec<SignedBftVote>,
    pub module_witnesses: ModuleWitnessBundle,
    pub proof_artifacts: Vec<ProofArtifact>,
    pub pruning_proof: PruningProof,
    pub recursive_proof: RecursiveProof,
    pub stark: BlockProofBundle,
    pub signature: String,
    pub consensus: ConsensusCertificate,
    #[serde(default)]
    pub consensus_proof: Option<ChainProof>,
    pub hash: String,
    #[serde(default)]
    pub pruned: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VerifyMode {
    Full,
    WithoutStark,
}

impl Block {
    pub fn new(
        header: BlockHeader,
        identities: Vec<AttestedIdentityRequest>,
        transactions: Vec<SignedTransaction>,
        uptime_proofs: Vec<UptimeProof>,
        timetoke_updates: Vec<TimetokeUpdate>,
        reputation_updates: Vec<ReputationUpdate>,
        bft_votes: Vec<SignedBftVote>,
        module_witnesses: ModuleWitnessBundle,
        proof_artifacts: Vec<ProofArtifact>,
        pruning_proof: PruningProof,
        recursive_proof: RecursiveProof,
        stark: BlockProofBundle,
        signature: Signature,
        consensus: ConsensusCertificate,
        consensus_proof: Option<ChainProof>,
    ) -> Self {
        let hash = header.hash();
        Self {
            header,
            identities,
            transactions,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            bft_votes,
            module_witnesses,
            proof_artifacts,
            pruning_proof,
            recursive_proof,
            stark,
            signature: signature_to_hex(&signature),
            consensus,
            consensus_proof,
            hash: hex::encode(hash),
            pruned: false,
        }
    }

    pub fn verify_signature(&self, public_key: &PublicKey) -> ChainResult<()> {
        let signature = signature_from_hex(&self.signature)?;
        verify_signature(public_key, &self.header.canonical_bytes(), &signature)
    }

    pub fn block_hash(&self) -> [u8; 32] {
        self.header.hash()
    }

    pub fn verify(
        &self,
        previous: Option<&Block>,
        proposer_public_key: &PublicKey,
    ) -> ChainResult<()> {
        self.verify_internal(previous, VerifyMode::Full, proposer_public_key)
    }

    pub fn verify_without_stark(
        &self,
        previous: Option<&Block>,
        proposer_public_key: &PublicKey,
    ) -> ChainResult<()> {
        self.verify_internal(previous, VerifyMode::WithoutStark, proposer_public_key)
    }

    fn verify_internal(
        &self,
        previous: Option<&Block>,
        mode: VerifyMode,
        proposer_public_key: &PublicKey,
    ) -> ChainResult<()> {
        let registry = ProofVerifierRegistry::default();
        self.verify_signature(proposer_public_key)?;
        if self.pruned {
            self.verify_pruned_payload()?;
        } else {
            self.verify_full_payload(mode == VerifyMode::Full, &registry)?;
        }

        self.verify_header_commitments()?;

        self.verify_pruning(previous)?;

        if let Some(prev_block) = previous {
            if self.header.height != prev_block.header.height + 1 {
                return Err(ChainError::Crypto(
                    "invalid block height progression".into(),
                ));
            }
            if self.header.previous_hash != prev_block.hash {
                return Err(ChainError::Crypto("invalid previous block hash".into()));
            }
        }
        let previous_proof = previous.map(|block| &block.recursive_proof);
        self.recursive_proof
            .verify(&self.header, &self.pruning_proof, previous_proof)?;

        if mode == VerifyMode::Full {
            let expected_previous_commitment =
                previous.and_then(|block| match &block.stark.recursive_proof {
                    ChainProof::Stwo(stark) => Some(stark.commitment.as_str()),
                    #[cfg(feature = "backend-plonky3")]
                    ChainProof::Plonky3(_) => None,
                    #[cfg(feature = "backend-rpp-stark")]
                    ChainProof::RppStark(_) => None,
                });
            let identity_proofs: Vec<ChainProof> = self
                .identities
                .iter()
                .map(|request| request.declaration.proof.zk_proof.clone())
                .collect();
            let uptime_proofs: Vec<ChainProof> = self
                .uptime_proofs
                .iter()
                .map(|proof| proof.proof().map(|inner| inner.clone()))
                .collect::<ChainResult<_>>()?;
            let consensus_proofs: Vec<ChainProof> = self.consensus_proof.iter().cloned().collect();
            let state_commitments = StateCommitmentSnapshot::from_header_fields(
                self.header.state_root.clone(),
                self.header.utxo_root.clone(),
                self.header.reputation_root.clone(),
                self.header.timetoke_root.clone(),
                self.header.zsi_root.clone(),
                self.header.proof_root.clone(),
            );
            registry.verify_block_bundle(
                &self.stark,
                &identity_proofs,
                &uptime_proofs,
                &consensus_proofs,
                &state_commitments,
                expected_previous_commitment,
            )?;
        }

        self.verify_transaction_proofs()?;

        for (module, commitment, payload) in self.module_witnesses.expected_artifacts()? {
            let artifact = self
                .proof_artifacts
                .iter()
                .find(|artifact| artifact.module == module && artifact.commitment == commitment)
                .ok_or_else(|| {
                    ChainError::Crypto(format!("missing module witness artifact for {:?}", module))
                })?;
            if artifact.proof != payload {
                return Err(ChainError::Crypto(format!(
                    "module witness payload mismatch for {:?}",
                    module
                )));
            }
        }

        match mode {
            VerifyMode::Full => self.verify_consensus(previous, &registry)?,
            VerifyMode::WithoutStark => self.verify_consensus_light()?,
        }

        Ok(())
    }

    fn verify_header_commitments(&self) -> ChainResult<()> {
        ensure_digest("state root", &self.header.state_root)?;
        ensure_digest("utxo root", &self.header.utxo_root)?;
        ensure_digest("reputation root", &self.header.reputation_root)?;
        ensure_digest("timetoke root", &self.header.timetoke_root)?;
        ensure_digest("zsi root", &self.header.zsi_root)?;
        ensure_digest("proof root", &self.header.proof_root)?;
        Ok(())
    }

    fn verify_pruning(&self, previous: Option<&Block>) -> ChainResult<()> {
        self.pruning_proof.verify(previous, &self.header)
    }

    fn verify_full_payload(
        &self,
        verify_stark: bool,
        registry: &ProofVerifierRegistry,
    ) -> ChainResult<()> {
        for request in &self.identities {
            request.verify(
                self.header.height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            )?;
        }
        if verify_stark {
            for request in &self.identities {
                registry.verify_identity(&request.declaration.proof.zk_proof)?;
            }
        }

        for proof in &self.uptime_proofs {
            if !proof.verify_commitment() {
                return Err(ChainError::Crypto(
                    "uptime proof commitment mismatch".into(),
                ));
            }
        }
        if verify_stark {
            for proof in &self.uptime_proofs {
                if let Some(zk) = &proof.proof {
                    registry.verify_uptime(zk)?;
                } else {
                    return Err(ChainError::Crypto(
                        "uptime proof missing zk proof payload".into(),
                    ));
                }
            }
        }

        for vote in &self.bft_votes {
            vote.verify()?;
        }

        let mut operation_hashes =
            Vec::with_capacity(self.identities.len() + self.transactions.len());
        for request in &self.identities {
            operation_hashes.push(request.declaration.hash()?);
        }
        for tx in &self.transactions {
            tx.verify()?;
            operation_hashes.push(tx.hash());
        }
        let computed_root = compute_merkle_root(&mut operation_hashes);
        if hex::encode(computed_root) != self.header.tx_root {
            return Err(ChainError::Crypto("transaction root mismatch".into()));
        }
        Ok(())
    }

    fn verify_pruned_payload(&self) -> ChainResult<()> {
        if !(self.identities.is_empty()
            && self.transactions.is_empty()
            && self.uptime_proofs.is_empty()
            && self.timetoke_updates.is_empty()
            && self.reputation_updates.is_empty()
            && self.bft_votes.is_empty())
        {
            return Err(ChainError::Crypto(
                "pruned block retains payload data".into(),
            ));
        }
        Ok(())
    }

    fn verify_transaction_proofs(&self) -> ChainResult<()> {
        let expected_count = if self.pruned {
            self.module_witnesses.transactions.len()
        } else {
            self.transactions.len()
        };
        if expected_count != self.stark.transaction_proofs.len() {
            return Err(ChainError::Crypto(
                "transaction/proof count mismatch in block".into(),
            ));
        }

        if self.pruned {
            for proof in &self.stark.transaction_proofs {
                match proof {
                    ChainProof::Stwo(stark) => match &stark.payload {
                        ProofPayload::Transaction(witness) => {
                            witness.signed_tx.verify()?;
                        }
                        _ => {
                            return Err(ChainError::Crypto(
                                "transaction proof payload does not match transaction".into(),
                            ));
                        }
                    },
                    #[cfg(feature = "backend-plonky3")]
                    ChainProof::Plonky3(value) => {
                        let witness = Self::decode_plonky3_transaction_witness(value)?;
                        witness.transaction.verify()?;
                    }
                    #[cfg(feature = "backend-rpp-stark")]
                    ChainProof::RppStark(_) => {}
                }
            }
        } else {
            for (tx, proof) in self
                .transactions
                .iter()
                .zip(self.stark.transaction_proofs.iter())
            {
                match proof {
                    ChainProof::Stwo(stark) => match &stark.payload {
                        ProofPayload::Transaction(witness) if &witness.signed_tx == tx => {}
                        _ => {
                            return Err(ChainError::Crypto(
                                "transaction proof payload does not match transaction".into(),
                            ));
                        }
                    },
                    #[cfg(feature = "backend-plonky3")]
                    ChainProof::Plonky3(value) => {
                        let witness = Self::decode_plonky3_transaction_witness(value)?;
                        if &witness.transaction != tx {
                            return Err(ChainError::Crypto(
                                "transaction proof payload does not match transaction".into(),
                            ));
                        }
                    }
                    #[cfg(feature = "backend-rpp-stark")]
                    ChainProof::RppStark(_) => {}
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "backend-plonky3")]
    fn decode_plonky3_transaction_witness(
        proof: &serde_json::Value,
    ) -> ChainResult<Plonky3TransactionWitness> {
        let public_inputs = proof
            .get("public_inputs")
            .and_then(|inputs| inputs.get("witness"))
            .cloned()
            .ok_or_else(|| {
                ChainError::Crypto("plonky3 transaction proof missing witness payload".into())
            })?;
        serde_json::from_value(public_inputs).map_err(|err| {
            ChainError::Crypto(format!(
                "failed to decode plonky3 transaction witness: {err}"
            ))
        })
    }

    fn verify_consensus(
        &self,
        previous: Option<&Block>,
        registry: &ProofVerifierRegistry,
    ) -> ChainResult<()> {
        let seed = self.consensus_seed(previous)?;
        self.verify_consensus_certificate(seed)?;
        if let Some(proof) = &self.consensus_proof {
            registry.verify_consensus(proof)?;
        }
        Ok(())
    }

    fn verify_consensus_light(&self) -> ChainResult<()> {
        let seed = if self.header.height == 0 {
            [0u8; 32]
        } else {
            Self::decode_consensus_seed(&self.header.previous_hash)?
        };
        self.verify_consensus_certificate(seed)
    }

    fn consensus_seed(&self, previous: Option<&Block>) -> ChainResult<[u8; 32]> {
        if self.header.height == 0 {
            return Ok([0u8; 32]);
        }
        let hash_hex = previous
            .map(|block| block.hash.as_str())
            .unwrap_or(&self.header.previous_hash);
        Self::decode_consensus_seed(hash_hex)
    }

    fn decode_consensus_seed(hash_hex: &str) -> ChainResult<[u8; 32]> {
        let seed_bytes = hex::decode(hash_hex)
            .map_err(|err| ChainError::Crypto(format!("invalid previous hash encoding: {err}")))?;
        if seed_bytes.len() != 32 {
            return Err(ChainError::Crypto("invalid VRF seed length".into()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&seed_bytes);
        Ok(seed)
    }

    fn verify_consensus_certificate(&self, seed: [u8; 32]) -> ChainResult<()> {
        let randomness = parse_natural(&self.header.randomness)?;
        let proof = VrfProof {
            randomness,
            preoutput: self.header.vrf_preoutput.clone(),
            proof: self.header.vrf_proof.clone(),
        };
        let public_key = if self.header.vrf_public_key.trim().is_empty() {
            None
        } else {
            Some(vrf_public_key_from_hex(&self.header.vrf_public_key)?)
        };
        if !verify_vrf(
            &seed,
            self.header.height,
            &self.header.proposer,
            self.header.leader_timetoke,
            &proof,
            public_key.as_ref(),
        ) {
            return Err(ChainError::Crypto("invalid VRF proof".into()));
        }

        if self.consensus.round != self.header.height {
            return Err(ChainError::Crypto(
                "consensus certificate references incorrect round".into(),
            ));
        }

        let expected_block_hash = hex::encode(self.block_hash());
        let mut prevote_voters = HashSet::new();
        let mut computed_prevote = Natural::from(0u32);
        for record in &self.consensus.pre_votes {
            record.vote.verify()?;
            let vote = &record.vote.vote;
            if vote.kind != BftVoteKind::PreVote {
                return Err(ChainError::Crypto(
                    "consensus certificate contains non-prevote in prevote set".into(),
                ));
            }
            if vote.round != self.consensus.round {
                return Err(ChainError::Crypto(
                    "prevote references incorrect consensus round".into(),
                ));
            }
            if vote.height != self.header.height {
                return Err(ChainError::Crypto(
                    "prevote references incorrect block height".into(),
                ));
            }
            if vote.block_hash != expected_block_hash {
                return Err(ChainError::Crypto(
                    "prevote references unexpected block hash".into(),
                ));
            }
            if !prevote_voters.insert(vote.voter.clone()) {
                return Err(ChainError::Crypto("duplicate prevote detected".into()));
            }
            let weight = parse_natural(&record.weight)?;
            computed_prevote += weight;
        }

        if computed_prevote.to_string() != self.consensus.pre_vote_power {
            return Err(ChainError::Crypto(
                "prevote power does not match recorded aggregate".into(),
            ));
        }

        let total = parse_natural(&self.consensus.total_power)?;
        let quorum = parse_natural(&self.consensus.quorum_threshold)?;
        let commit_total = parse_natural(&self.consensus.commit_power)?;

        if computed_prevote < quorum {
            return Err(ChainError::Crypto(
                "insufficient pre-vote power for quorum".into(),
            ));
        }

        let mut precommit_voters = HashSet::new();
        let mut computed_precommit = Natural::from(0u32);
        for record in &self.consensus.pre_commits {
            record.vote.verify()?;
            let vote = &record.vote.vote;
            if vote.kind != BftVoteKind::PreCommit {
                return Err(ChainError::Crypto(
                    "consensus certificate contains non-precommit in precommit set".into(),
                ));
            }
            if vote.round != self.consensus.round {
                return Err(ChainError::Crypto(
                    "precommit references incorrect consensus round".into(),
                ));
            }
            if vote.height != self.header.height {
                return Err(ChainError::Crypto(
                    "precommit references incorrect block height".into(),
                ));
            }
            if vote.block_hash != expected_block_hash {
                return Err(ChainError::Crypto(
                    "precommit references unexpected block hash".into(),
                ));
            }
            if !prevote_voters.contains(&vote.voter) {
                return Err(ChainError::Crypto(
                    "precommit without corresponding prevote".into(),
                ));
            }
            if !precommit_voters.insert(vote.voter.clone()) {
                return Err(ChainError::Crypto("duplicate precommit detected".into()));
            }
            let weight = parse_natural(&record.weight)?;
            computed_precommit += weight;
        }

        if computed_precommit.to_string() != self.consensus.pre_commit_power {
            return Err(ChainError::Crypto(
                "precommit power does not match recorded aggregate".into(),
            ));
        }

        if computed_precommit < quorum {
            return Err(ChainError::Crypto(
                "insufficient pre-commit power for quorum".into(),
            ));
        }

        if commit_total != computed_precommit {
            return Err(ChainError::Crypto(
                "commit power does not match accumulated precommit power".into(),
            ));
        }

        if commit_total < quorum {
            return Err(ChainError::Crypto(
                "insufficient commit power for quorum".into(),
            ));
        }

        if total < quorum {
            return Err(ChainError::Crypto("invalid quorum configuration".into()));
        }

        let mut commit_participants: Vec<_> = precommit_voters.into_iter().collect();
        commit_participants.sort();
        let mut witnesses = self.module_witnesses.consensus.iter().filter(|witness| {
            witness.height == self.header.height && witness.round == self.consensus.round
        });
        let witness = witnesses.next().ok_or_else(|| {
            ChainError::Crypto("missing consensus witness for committed round".into())
        })?;
        if witnesses.next().is_some() {
            return Err(ChainError::Crypto(
                "multiple consensus witnesses recorded for committed round".into(),
            ));
        }
        let mut recorded_participants = witness.participants.clone();
        recorded_participants.sort();
        if recorded_participants != commit_participants {
            return Err(ChainError::Crypto(
                "consensus witness participants do not match commit set".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BlockPayload {
    pub identities: Vec<AttestedIdentityRequest>,
    pub transactions: Vec<SignedTransaction>,
    pub uptime_proofs: Vec<UptimeProof>,
    pub timetoke_updates: Vec<TimetokeUpdate>,
    pub reputation_updates: Vec<ReputationUpdate>,
    pub bft_votes: Vec<SignedBftVote>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct BlockEnvelope {
    pub header: BlockHeader,
    pub module_witnesses: ModuleWitnessBundle,
    pub proof_artifacts: Vec<ProofArtifact>,
    pub pruning_proof: PruningProof,
    pub recursive_proof: RecursiveProof,
    pub stark: BlockProofBundle,
    pub signature: String,
    pub consensus: ConsensusCertificate,
    #[serde(default)]
    pub consensus_proof: Option<ChainProof>,
    pub hash: String,
    #[serde(default)]
    pub pruned: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct StoredBlock {
    pub envelope: BlockEnvelope,
    pub payload: Option<BlockPayload>,
}

impl BlockPayload {
    pub fn from_block(block: &Block) -> Self {
        Self {
            identities: block.identities.clone(),
            transactions: block.transactions.clone(),
            uptime_proofs: block.uptime_proofs.clone(),
            timetoke_updates: block.timetoke_updates.clone(),
            reputation_updates: block.reputation_updates.clone(),
            bft_votes: block.bft_votes.clone(),
        }
    }
}

impl BlockEnvelope {
    pub fn from_block(block: &Block) -> Self {
        Self {
            header: block.header.clone(),
            module_witnesses: block.module_witnesses.clone(),
            proof_artifacts: block.proof_artifacts.clone(),
            pruning_proof: block.pruning_proof.clone(),
            recursive_proof: block.recursive_proof.clone(),
            stark: block.stark.clone(),
            signature: block.signature.clone(),
            consensus: block.consensus.clone(),
            consensus_proof: block.consensus_proof.clone(),
            hash: block.hash.clone(),
            pruned: block.pruned,
        }
    }

    pub fn pruning_commitment(&self) -> String {
        self.pruning_proof.binding_digest_hex()
    }

    pub fn pruning_aggregate_commitment(&self) -> String {
        self.pruning_proof.aggregate_commitment_hex()
    }

    pub fn pruning_schema_version(&self) -> u16 {
        self.pruning_proof.schema_version()
    }

    pub fn pruning_parameter_version(&self) -> u16 {
        self.pruning_proof.parameter_version()
    }
}

impl StoredBlock {
    pub fn from_block(block: &Block) -> Self {
        Self {
            envelope: BlockEnvelope::from_block(block),
            payload: Some(BlockPayload::from_block(block)),
        }
    }

    pub fn into_block(self) -> Block {
        let StoredBlock { envelope, payload } = self;
        let was_pruned = payload.is_none();
        let payload = payload.unwrap_or_default();
        let BlockPayload {
            identities,
            transactions,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            bft_votes,
        } = payload;
        Block {
            header: envelope.header,
            identities,
            transactions,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            bft_votes,
            module_witnesses: envelope.module_witnesses,
            proof_artifacts: envelope.proof_artifacts,
            pruning_proof: envelope.pruning_proof,
            recursive_proof: envelope.recursive_proof,
            stark: envelope.stark,
            signature: envelope.signature,
            consensus: envelope.consensus,
            consensus_proof: envelope.consensus_proof,
            hash: envelope.hash,
            pruned: envelope.pruned || was_pruned,
        }
    }

    pub fn into_block_with_payload(mut self, payload: BlockPayload) -> Block {
        self.payload = Some(payload);
        self.envelope.pruned = false;
        self.into_block()
    }

    pub fn prune_payload(&mut self) {
        self.payload = None;
        self.envelope.pruned = true;
    }

    pub fn is_pruned(&self) -> bool {
        self.payload.is_none() || self.envelope.pruned
    }

    pub fn height(&self) -> u64 {
        self.envelope.header.height
    }

    pub fn hash(&self) -> &str {
        &self.envelope.hash
    }

    pub fn pruning_metadata(&self) -> PruningEnvelopeMetadata {
        self.envelope.pruning_proof.envelope_metadata()
    }

    pub fn aggregated_commitment(&self) -> ChainResult<String> {
        Ok(self.envelope.pruning_proof.aggregate_commitment_hex())
    }

    pub fn previous_recursive_commitment(&self) -> ChainResult<Option<String>> {
        Ok(self.envelope.recursive_proof.previous_commitment.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{
        evaluate_vrf, BftVote, BftVoteKind, ConsensusCertificate, SignedBftVote, VoteRecord,
    };
    use crate::crypto::{address_from_public_key, generate_vrf_keypair, vrf_public_key_to_hex};
    use crate::errors::ChainError;
    use crate::ledger::{Ledger, DEFAULT_EPOCH_LENGTH};
    use crate::proof_backend::Blake2sHasher;
    use crate::reputation::{ReputationWeights, Tier};
    use crate::rpp::{ConsensusWitness, ModuleWitnessBundle};
    use crate::state::merkle::compute_merkle_root;
    use crate::stwo::circuit::{
        consensus::{ConsensusWitness as CircuitConsensusWitness, VotePower},
        identity::{IdentityCircuit, IdentityWitness},
        pruning::PruningWitness,
        recursive::RecursiveWitness,
        state::StateWitness,
        string_to_field,
        uptime::UptimeWitness,
        ExecutionTrace, StarkCircuit,
    };
    use crate::stwo::fri::FriProver;
    use crate::stwo::params::StarkParameters;
    use crate::stwo::proof::{
        CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
    };
    use crate::types::{
        AttestedIdentityRequest, ChainProof, IdentityDeclaration, IdentityGenesis, IdentityProof,
        IDENTITY_ATTESTATION_GOSSIP_MIN, IDENTITY_ATTESTATION_QUORUM,
    };
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
    use rand::rngs::OsRng;

    fn seeded_keypair(seed: u8) -> Keypair {
        let secret = SecretKey::from_bytes(&[seed; 32]).expect("secret");
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }

    fn sign_identity_vote(keypair: &Keypair, height: u64, hash: &str) -> SignedBftVote {
        let voter = address_from_public_key(&keypair.public);
        let vote = BftVote {
            round: 0,
            height,
            block_hash: hash.to_string(),
            voter: voter.clone(),
            kind: BftVoteKind::PreCommit,
        };
        let signature = keypair.sign(&vote.message_bytes());
        SignedBftVote {
            vote,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(signature.to_bytes()),
        }
    }

    fn sample_identity_declaration(ledger: &Ledger) -> IdentityDeclaration {
        ledger.sync_epoch_for_height(1);
        let pk_bytes = vec![1u8; 32];
        let wallet_pk = hex::encode(&pk_bytes);
        let wallet_addr = hex::encode::<[u8; 32]>(Blake2sHasher::hash(&pk_bytes).into());
        let epoch_nonce_bytes = ledger.current_epoch_nonce();
        let vrf_keypair = generate_vrf_keypair().expect("generate vrf keypair");
        let vrf = evaluate_vrf(
            &epoch_nonce_bytes,
            0,
            &wallet_addr,
            0,
            Some(&vrf_keypair.secret),
        )
        .expect("evaluate vrf");
        let commitment_proof = ledger.identity_commitment_proof(&wallet_addr);
        let genesis = IdentityGenesis {
            wallet_pk,
            wallet_addr,
            vrf_public_key: vrf_public_key_to_hex(&vrf_keypair.public),
            vrf_proof: vrf.clone(),
            epoch_nonce: hex::encode(epoch_nonce_bytes),
            state_root: hex::encode(ledger.state_root()),
            identity_root: hex::encode(ledger.identity_root()),
            initial_reputation: 0,
            commitment_proof: commitment_proof.clone(),
        };
        let parameters = StarkParameters::blueprint_default();
        let expected_commitment = genesis.expected_commitment().expect("commitment");
        let witness = IdentityWitness {
            wallet_pk: genesis.wallet_pk.clone(),
            wallet_addr: genesis.wallet_addr.clone(),
            vrf_tag: genesis.vrf_tag().to_string(),
            epoch_nonce: genesis.epoch_nonce.clone(),
            state_root: genesis.state_root.clone(),
            identity_root: genesis.identity_root.clone(),
            initial_reputation: genesis.initial_reputation,
            commitment: expected_commitment.clone(),
            identity_leaf: commitment_proof.leaf.clone(),
            identity_path: commitment_proof.siblings.clone(),
        };
        let circuit = IdentityCircuit::new(witness.clone());
        circuit.evaluate_constraints().expect("constraints");
        let trace = circuit
            .generate_trace(&parameters)
            .expect("trace generation");
        circuit
            .verify_air(&parameters, &trace)
            .expect("air verification");
        let inputs = vec![
            string_to_field(&parameters, &witness.wallet_addr),
            string_to_field(&parameters, &witness.vrf_tag),
            string_to_field(&parameters, &witness.identity_root),
            string_to_field(&parameters, &witness.state_root),
        ];
        let hasher = parameters.poseidon_hasher();
        let fri_prover = FriProver::new(&parameters);
        let air = circuit
            .define_air(&parameters, &trace)
            .expect("air definition");
        let fri_output = fri_prover.prove(&air, &trace, &inputs);
        let proof = StarkProof::new(
            ProofKind::Identity,
            ProofPayload::Identity(witness),
            inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        );
        IdentityDeclaration {
            genesis,
            proof: IdentityProof {
                commitment: expected_commitment,
                zk_proof: ChainProof::Stwo(proof),
            },
        }
    }

    fn attested_request(ledger: &Ledger, height: u64) -> AttestedIdentityRequest {
        let declaration = sample_identity_declaration(ledger);
        let identity_hash = hex::encode(declaration.hash().expect("hash"));
        let voters: Vec<Keypair> = (0..IDENTITY_ATTESTATION_QUORUM)
            .map(|idx| seeded_keypair(20 + idx as u8))
            .collect();
        let attested_votes = voters
            .iter()
            .map(|kp| sign_identity_vote(kp, height, &identity_hash))
            .collect();
        let gossip_confirmations = voters
            .iter()
            .take(IDENTITY_ATTESTATION_GOSSIP_MIN)
            .map(|kp| address_from_public_key(&kp.public))
            .collect();
        AttestedIdentityRequest {
            declaration,
            attested_votes,
            gossip_confirmations,
        }
    }

    fn build_identity_block(
        request: AttestedIdentityRequest,
        height: u64,
        proposer: &Keypair,
    ) -> Block {
        let mut operations = vec![request.declaration.hash().expect("hash")];
        let tx_root = compute_merkle_root(&mut operations);
        let state_root = request.declaration.genesis.state_root.clone();
        let proposer_address = address_from_public_key(&proposer.public);
        let header = BlockHeader::new(
            height,
            "00".repeat(32),
            hex::encode(tx_root),
            state_root.clone(),
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
            "44".repeat(32),
            "55".repeat(32),
            "0".to_string(),
            "0".to_string(),
            "66".repeat(32),
            "77".repeat(32),
            "88".repeat(crate::vrf::VRF_PROOF_LENGTH),
            proposer_address,
            Tier::Tl5.to_string(),
            0,
        );
        let pruning_proof = pruning_from_previous(None, &header);
        let recursive_chain = dummy_recursive_chain_proof(&header, &pruning_proof, None);
        let recursive_proof = RecursiveProof::genesis(&header, &pruning_proof, &recursive_chain)
            .expect("recursive genesis");
        let stark_bundle = BlockProofBundle::new(
            Vec::new(),
            ChainProof::Stwo(dummy_proof(ProofKind::State)),
            ChainProof::Stwo(dummy_proof(ProofKind::Pruning)),
            recursive_chain,
        );
        let mut consensus = ConsensusCertificate::genesis();
        consensus.round = height;
        let signature = proposer.sign(&header.canonical_bytes());
        Block::new(
            header,
            vec![request],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ModuleWitnessBundle::default(),
            Vec::new(),
            pruning_proof,
            recursive_proof,
            stark_bundle,
            signature,
            consensus,
            None,
        )
    }
    fn dummy_recursive_chain_proof(
        header: &BlockHeader,
        pruning: &PruningProof,
        previous: Option<String>,
    ) -> ChainProof {
        let aggregated_commitment = "77".repeat(32);
        ChainProof::Stwo(StarkProof {
            kind: ProofKind::Recursive,
            commitment: aggregated_commitment.clone(),
            public_inputs: Vec::new(),
            payload: ProofPayload::Recursive(RecursiveWitness {
                previous_commitment: previous.or_else(|| Some(RecursiveProof::anchor())),
                aggregated_commitment,
                identity_commitments: Vec::new(),
                tx_commitments: Vec::new(),
                uptime_commitments: Vec::new(),
                consensus_commitments: Vec::new(),
                state_commitment: header.state_root.clone(),
                global_state_root: header.state_root.clone(),
                utxo_root: header.utxo_root.clone(),
                reputation_root: header.reputation_root.clone(),
                timetoke_root: header.timetoke_root.clone(),
                zsi_root: header.zsi_root.clone(),
                proof_root: header.proof_root.clone(),
                pruning_commitment: pruning.binding_digest_hex(),
                block_height: header.height,
            }),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        })
    }

    #[test]
    fn block_accepts_valid_identity_attestation() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let height = 1;
        let request = attested_request(&ledger, height);
        let proposer = seeded_keypair(42);
        let block = build_identity_block(request, height, &proposer);
        block
            .verify_without_stark(None, &proposer.public)
            .expect("block verifies");
    }

    #[test]
    fn block_rejects_insufficient_gossip() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let height = 1;
        let mut request = attested_request(&ledger, height);
        request
            .gossip_confirmations
            .truncate(IDENTITY_ATTESTATION_GOSSIP_MIN - 1);
        let proposer = seeded_keypair(43);
        let block = build_identity_block(request, height, &proposer);
        let err = block
            .verify_without_stark(None, &proposer.public)
            .expect_err("block must reject attestation");
        match err {
            ChainError::Transaction(message) => {
                assert!(message.contains("gossip"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn block_rejects_invalid_signature() {
        let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
        let height = 1;
        let request = attested_request(&ledger, height);
        let proposer = seeded_keypair(44);
        let mut block = build_identity_block(request, height, &proposer);
        block.signature = "00".repeat(64);
        let err = block
            .verify_without_stark(None, &proposer.public)
            .expect_err("invalid signature must be rejected");
        match err {
            ChainError::Crypto(message) => {
                assert!(message.contains("signature"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn dummy_proof(kind: ProofKind) -> StarkProof {
        let payload = match kind {
            ProofKind::State => ProofPayload::State(StateWitness {
                prev_state_root: "11".repeat(32),
                new_state_root: "22".repeat(32),
                identities: Vec::new(),
                transactions: Vec::new(),
                accounts_before: Vec::new(),
                accounts_after: Vec::new(),
                required_tier: Tier::Tl0,
                reputation_weights: ReputationWeights::default(),
            }),
            ProofKind::Pruning => ProofPayload::Pruning(PruningWitness {
                previous_tx_root: "33".repeat(32),
                pruned_tx_root: "44".repeat(32),
                original_transactions: vec!["55".repeat(32)],
                removed_transactions: vec!["55".repeat(32)],
            }),
            ProofKind::Recursive => ProofPayload::Recursive(RecursiveWitness {
                previous_commitment: Some(RecursiveProof::anchor()),
                aggregated_commitment: "77".repeat(32),
                identity_commitments: vec!["88".repeat(32)],
                tx_commitments: vec!["99".repeat(32)],
                uptime_commitments: vec!["aa".repeat(32)],
                consensus_commitments: vec!["bb".repeat(32)],
                state_commitment: "aa".repeat(32),
                global_state_root: "cc".repeat(32),
                utxo_root: "dd".repeat(32),
                reputation_root: "ee".repeat(32),
                timetoke_root: "ff".repeat(32),
                zsi_root: "11".repeat(32),
                proof_root: "22".repeat(32),
                pruning_commitment: "bb".repeat(32),
                block_height: 0,
            }),
            ProofKind::Uptime => ProofPayload::Uptime(UptimeWitness {
                wallet_address: "alice".into(),
                node_clock: 42,
                epoch: 1,
                head_hash: "cc".repeat(32),
                window_start: 0,
                window_end: 3_600,
                commitment: "dd".repeat(32),
            }),
            ProofKind::Consensus => ProofPayload::Consensus(CircuitConsensusWitness {
                block_hash: "ee".repeat(32),
                round: 0,
                leader_proposal: "ee".repeat(32),
                quorum_threshold: 1,
                pre_votes: vec![VotePower {
                    voter: "alice".into(),
                    weight: 1,
                }],
                pre_commits: vec![VotePower {
                    voter: "alice".into(),
                    weight: 1,
                }],
                commit_votes: vec![VotePower {
                    voter: "alice".into(),
                    weight: 1,
                }],
            }),
            ProofKind::Transaction | ProofKind::Identity => {
                // These variants are not used in the conversion tests.
                ProofPayload::Pruning(PruningWitness {
                    previous_tx_root: "cc".repeat(32),
                    pruned_tx_root: "dd".repeat(32),
                    original_transactions: Vec::new(),
                    removed_transactions: Vec::new(),
                })
            }
        };
        StarkProof {
            kind,
            commitment: "ee".repeat(32),
            public_inputs: Vec::new(),
            payload,
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: CommitmentSchemeProofData::default(),
            fri_proof: FriProof::default(),
        }
    }

    fn consensus_block_fixture() -> (Block, Block, Address) {
        let mut rng = OsRng;
        let keypair = Keypair::generate(&mut rng);
        let address = address_from_public_key(&keypair.public);
        let vrf_keypair = generate_vrf_keypair().expect("generate vrf keypair");

        let state_root = "aa".repeat(32);
        let genesis_seed = [0u8; 32];
        let genesis_vrf = evaluate_vrf(&genesis_seed, 0, &address, 0, Some(&vrf_keypair.secret))
            .expect("evaluate vrf");
        let prev_header = BlockHeader::new(
            0,
            hex::encode([0u8; 32]),
            "bb".repeat(32),
            state_root.clone(),
            "cc".repeat(32),
            "dd".repeat(32),
            "ee".repeat(32),
            "ff".repeat(32),
            "11".repeat(32),
            "0".to_string(),
            genesis_vrf.randomness.to_string(),
            vrf_public_key_to_hex(&vrf_keypair.public),
            genesis_vrf.preoutput.clone(),
            genesis_vrf.proof.clone(),
            "13".repeat(32),
            Tier::Tl5.to_string(),
            0,
        );
        let prev_pruning = pruning_from_previous(None, &prev_header);
        let prev_recursive_chain = dummy_recursive_chain_proof(&prev_header, &prev_pruning, None);
        let prev_recursive =
            RecursiveProof::genesis(&prev_header, &prev_pruning, &prev_recursive_chain)
                .expect("recursive genesis");
        let prev_stark = BlockProofBundle::new(
            Vec::new(),
            ChainProof::Stwo(dummy_proof(ProofKind::State)),
            ChainProof::Stwo(dummy_proof(ProofKind::Pruning)),
            prev_recursive_chain.clone(),
        );
        let prev_block = Block::new(
            prev_header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ModuleWitnessBundle::default(),
            Vec::new(),
            prev_pruning,
            prev_recursive,
            prev_stark,
            Signature::from_bytes(&[0u8; 64]).expect("signature"),
            ConsensusCertificate::genesis(),
            None,
        );

        let vrf = evaluate_vrf(
            &prev_block.block_hash(),
            1,
            &address,
            0,
            Some(&vrf_keypair.secret),
        )
        .expect("evaluate vrf");
        let header = BlockHeader::new(
            1,
            prev_block.hash.clone(),
            "21".repeat(32),
            state_root,
            "22".repeat(32),
            "23".repeat(32),
            "24".repeat(32),
            "25".repeat(32),
            "26".repeat(32),
            "1000".to_string(),
            vrf.randomness.to_string(),
            vrf_public_key_to_hex(&vrf_keypair.public),
            vrf.preoutput.clone(),
            vrf.proof.clone(),
            address.clone(),
            Tier::Tl3.to_string(),
            0,
        );
        let block_hash_hex = hex::encode(header.hash());
        let prevote = BftVote {
            round: 1,
            height: 1,
            block_hash: block_hash_hex.clone(),
            voter: address.clone(),
            kind: BftVoteKind::PreVote,
        };
        let prevote_sig = keypair.sign(&prevote.message_bytes());
        let signed_prevote = SignedBftVote {
            vote: prevote.clone(),
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(prevote_sig.to_bytes()),
        };
        let precommit_vote = BftVote {
            kind: BftVoteKind::PreCommit,
            ..prevote
        };
        let precommit_sig = keypair.sign(&precommit_vote.message_bytes());
        let signed_precommit = SignedBftVote {
            vote: precommit_vote,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(precommit_sig.to_bytes()),
        };
        let certificate = ConsensusCertificate {
            round: 1,
            total_power: "1000".to_string(),
            quorum_threshold: "1000".to_string(),
            pre_vote_power: "1000".to_string(),
            pre_commit_power: "1000".to_string(),
            commit_power: "1000".to_string(),
            observers: 0,
            pre_votes: vec![VoteRecord {
                vote: signed_prevote,
                weight: "1000".to_string(),
            }],
            pre_commits: vec![VoteRecord {
                vote: signed_precommit,
                weight: "1000".to_string(),
            }],
        };

        let pruning_proof = pruning_from_previous(Some(&prev_block), &header);
        let recursive_chain = dummy_recursive_chain_proof(
            &header,
            &pruning_proof,
            Some(prev_block.recursive_proof.commitment.clone()),
        );
        let recursive_proof = RecursiveProof::extend(
            &prev_block.recursive_proof,
            &header,
            &pruning_proof,
            &recursive_chain,
        )
        .expect("recursive extend");
        let stark_bundle = BlockProofBundle::new(
            Vec::new(),
            ChainProof::Stwo(dummy_proof(ProofKind::State)),
            ChainProof::Stwo(dummy_proof(ProofKind::Pruning)),
            recursive_chain,
        );
        let mut witnesses = ModuleWitnessBundle::default();
        witnesses.record_consensus(ConsensusWitness::new(1, 1, vec![address.clone()]));
        let block = Block::new(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            witnesses,
            Vec::new(),
            pruning_proof,
            recursive_proof,
            stark_bundle,
            Signature::from_bytes(&[0u8; 64]).expect("signature"),
            certificate,
            None,
        );

        (prev_block, block, address)
    }

    #[test]
    fn consensus_witness_must_reflect_commit_participants() {
        let (prev_block, block, _address) = consensus_block_fixture();
        let registry = ProofVerifierRegistry::default();
        block
            .verify_consensus(Some(&prev_block), &registry)
            .unwrap();

        let mut missing_witness_block = block.clone();
        missing_witness_block.module_witnesses = ModuleWitnessBundle::default();
        assert!(missing_witness_block
            .verify_consensus(Some(&prev_block), &registry)
            .is_err());

        let mut mismatched_witness_block = block.clone();
        let mut mismatched_bundle = ModuleWitnessBundle::default();
        mismatched_bundle.record_consensus(ConsensusWitness::new(1, 1, vec!["cafebabe".repeat(4)]));
        mismatched_witness_block.module_witnesses = mismatched_bundle;
        assert!(mismatched_witness_block
            .verify_consensus(Some(&prev_block), &registry)
            .is_err());
    }

    #[test]
    fn light_consensus_verification_rejects_invalid_certificates() {
        let (_prev_block, block, _address) = consensus_block_fixture();
        block.verify_consensus_light().unwrap();

        let mut invalid_vrf_block = block.clone();
        invalid_vrf_block.header.vrf_proof = "00".to_string();
        assert!(invalid_vrf_block.verify_consensus_light().is_err());

        let mut duplicate_prevote_block = block.clone();
        duplicate_prevote_block
            .consensus
            .pre_votes
            .push(duplicate_prevote_block.consensus.pre_votes[0].clone());
        assert!(duplicate_prevote_block.verify_consensus_light().is_err());

        let mut insufficient_quorum_block = block.clone();
        insufficient_quorum_block.consensus.pre_commits[0].weight = "1".to_string();
        insufficient_quorum_block.consensus.pre_commit_power = "1".to_string();
        insufficient_quorum_block.consensus.commit_power = "1".to_string();
        assert!(insufficient_quorum_block.verify_consensus_light().is_err());

        let mut missing_witness_block = block.clone();
        missing_witness_block.module_witnesses = ModuleWitnessBundle::default();
        assert!(missing_witness_block.verify_consensus_light().is_err());

        let mut mismatched_witness_block = block.clone();
        let mut mismatched_bundle = ModuleWitnessBundle::default();
        mismatched_bundle.record_consensus(ConsensusWitness::new(
            block.header.height,
            block.consensus.round,
            vec!["cafebabe".repeat(4)],
        ));
        mismatched_witness_block.module_witnesses = mismatched_bundle;
        assert!(mismatched_witness_block.verify_consensus_light().is_err());
    }

    #[test]
    fn stored_block_roundtrip_preserves_pruning_state() {
        let state_root = "11".repeat(32);
        let proposer = "99".repeat(32);
        let vrf_keypair = generate_vrf_keypair().expect("generate vrf keypair");
        let genesis_seed = [0u8; 32];
        let vrf = evaluate_vrf(&genesis_seed, 0, &proposer, 0, Some(&vrf_keypair.secret))
            .expect("evaluate vrf");
        let header = BlockHeader::new(
            0,
            hex::encode([0u8; 32]),
            "22".repeat(32),
            state_root.clone(),
            "33".repeat(32),
            "44".repeat(32),
            "55".repeat(32),
            "66".repeat(32),
            "77".repeat(32),
            "0".to_string(),
            vrf.randomness.to_string(),
            vrf_public_key_to_hex(&vrf_keypair.public),
            vrf.preoutput.clone(),
            vrf.proof.clone(),
            proposer.clone(),
            Tier::Tl5.to_string(),
            0,
        );
        let pruning_proof = pruning_from_previous(None, &header);
        let recursive_chain = dummy_recursive_chain_proof(&header, &pruning_proof, None);
        let recursive_proof = RecursiveProof::genesis(&header, &pruning_proof, &recursive_chain)
            .expect("recursive genesis");
        let stark_bundle = BlockProofBundle::new(
            Vec::new(),
            ChainProof::Stwo(dummy_proof(ProofKind::State)),
            ChainProof::Stwo(dummy_proof(ProofKind::Pruning)),
            recursive_chain.clone(),
        );
        let signature = Signature::from_bytes(&[0u8; 64]).expect("signature bytes");
        let consensus = ConsensusCertificate::genesis();

        let block = Block::new(
            header,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            ModuleWitnessBundle::default(),
            Vec::new(),
            pruning_proof,
            recursive_proof,
            stark_bundle,
            signature,
            consensus,
            None,
        );

        let stored = StoredBlock::from_block(&block);
        let hydrated = stored.clone().into_block();
        assert!(!hydrated.pruned);
        assert_eq!(hydrated.header.height, block.header.height);
        assert_eq!(hydrated.hash, block.hash);

        let mut pruned = stored;
        pruned.prune_payload();
        let pruned_block = pruned.into_block();
        assert!(pruned_block.pruned);
        assert!(pruned_block.transactions.is_empty());
        assert_eq!(
            pruned_block.module_witnesses.transactions.len(),
            block.module_witnesses.transactions.len()
        );
    }
}

fn parse_natural(value: &str) -> ChainResult<Natural> {
    Natural::from_str(value).map_err(|_| ChainError::Crypto("invalid natural encoding".into()))
}

fn ensure_digest(label: &str, value: &str) -> ChainResult<()> {
    let bytes = hex::decode(value)
        .map_err(|err| ChainError::Crypto(format!("{label} is not valid hex encoding: {err}")))?;
    if bytes.len() != 32 {
        return Err(ChainError::Crypto(format!(
            "{label} must encode exactly 32 bytes"
        )));
    }
    Ok(())
}

fn recursive_anchor_default() -> String {
    RecursiveProof::anchor()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(from = "BlockMetadataSerde", into = "BlockMetadataSerde")]
pub struct BlockMetadata {
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
    pub previous_state_root: String,
    pub new_state_root: String,
    #[serde(default)]
    pub proof_hash: String,
    #[serde(default)]
    pub pruning: Option<PruningEnvelopeMetadata>,
    pub recursive_commitment: String,
    #[serde(default)]
    pub recursive_previous_commitment: Option<String>,
    pub recursive_system: ProofSystem,
    #[serde(default = "recursive_anchor_default")]
    pub recursive_anchor: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BlockMetadataSerde {
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
    pub previous_state_root: String,
    pub new_state_root: String,
    #[serde(default)]
    pub proof_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruning: Option<PruningEnvelopeMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruning_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruning_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruning_aggregate_commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruning_schema_version: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pruning_parameter_version: Option<u16>,
    pub recursive_commitment: String,
    #[serde(default)]
    pub recursive_previous_commitment: Option<String>,
    pub recursive_system: ProofSystem,
    #[serde(default = "recursive_anchor_default")]
    pub recursive_anchor: String,
}

impl From<BlockMetadataSerde> for BlockMetadata {
    fn from(value: BlockMetadataSerde) -> Self {
        let BlockMetadataSerde {
            height,
            hash,
            timestamp,
            previous_state_root,
            new_state_root,
            proof_hash,
            pruning,
            pruning_root,
            pruning_commitment,
            pruning_aggregate_commitment,
            pruning_schema_version,
            pruning_parameter_version,
            recursive_commitment,
            recursive_previous_commitment,
            recursive_system,
            recursive_anchor,
        } = value;

        let pruning = pruning.or_else(|| {
            legacy_pruning_envelope(
                height,
                &previous_state_root,
                pruning_root,
                pruning_commitment,
                pruning_aggregate_commitment,
                pruning_schema_version,
                pruning_parameter_version,
            )
        });

        Self {
            height,
            hash,
            timestamp,
            previous_state_root,
            new_state_root,
            proof_hash,
            pruning,
            recursive_commitment,
            recursive_previous_commitment,
            recursive_system,
            recursive_anchor,
        }
    }
}

impl From<BlockMetadata> for BlockMetadataSerde {
    fn from(value: BlockMetadata) -> Self {
        let BlockMetadata {
            height,
            hash,
            timestamp,
            previous_state_root,
            new_state_root,
            proof_hash,
            pruning,
            recursive_commitment,
            recursive_previous_commitment,
            recursive_system,
            recursive_anchor,
        } = value;

        let (
            pruning_root,
            pruning_commitment,
            pruning_aggregate_commitment,
            pruning_schema_version,
            pruning_parameter_version,
        ) = pruning
            .as_ref()
            .map(|metadata| {
                let pruning_root = metadata
                    .segments
                    .get(0)
                    .map(|segment| segment.segment_commitment.as_str().to_owned());
                let pruning_commitment = Some(metadata.binding_digest.as_str().to_owned());
                let pruning_aggregate_commitment = Some(
                    metadata
                        .commitment
                        .aggregate_commitment
                        .as_str()
                        .to_owned(),
                );
                let pruning_schema_version = Some(metadata.schema_version);
                let pruning_parameter_version = Some(metadata.parameter_version);
                (
                    pruning_root,
                    pruning_commitment,
                    pruning_aggregate_commitment,
                    pruning_schema_version,
                    pruning_parameter_version,
                )
            })
            .unwrap_or((None, None, None, None, None));

        Self {
            height,
            hash,
            timestamp,
            previous_state_root,
            new_state_root,
            proof_hash,
            pruning,
            pruning_root,
            pruning_commitment,
            pruning_aggregate_commitment,
            pruning_schema_version,
            pruning_parameter_version,
            recursive_commitment,
            recursive_previous_commitment,
            recursive_system,
            recursive_anchor,
        }
    }
}

fn legacy_pruning_envelope(
    height: u64,
    previous_state_root: &str,
    pruning_root: Option<String>,
    pruning_commitment: Option<String>,
    pruning_aggregate_commitment: Option<String>,
    pruning_schema_version: Option<u16>,
    pruning_parameter_version: Option<u16>,
) -> Option<PruningEnvelopeMetadata> {
    let binding_digest = pruning_commitment.and_then(non_empty_string)?;
    let aggregate_commitment = pruning_aggregate_commitment.and_then(non_empty_string)?;
    let schema_version = pruning_schema_version?;
    let parameter_version = pruning_parameter_version?;
    if schema_version == 0 || parameter_version == 0 {
        return None;
    }
    if previous_state_root.is_empty() {
        return None;
    }

    let snapshot_height = height.saturating_sub(1);
    let snapshot = PruningSnapshotMetadata {
        schema_version,
        parameter_version,
        block_height: snapshot_height,
        state_commitment: TaggedDigestHex(previous_state_root.to_owned()),
    };

    let mut segments = Vec::new();
    if let Some(segment_commitment) = pruning_root.and_then(non_empty_string) {
        segments.push(PruningSegmentMetadata {
            schema_version,
            parameter_version,
            segment_index: 0,
            start_height: snapshot_height,
            end_height: snapshot_height,
            segment_commitment: TaggedDigestHex(segment_commitment),
        });
    }

    let commitment = PruningCommitmentMetadata {
        schema_version,
        parameter_version,
        aggregate_commitment: TaggedDigestHex(aggregate_commitment),
    };

    Some(PruningEnvelopeMetadata {
        schema_version,
        parameter_version,
        snapshot,
        segments,
        commitment,
        binding_digest: TaggedDigestHex(binding_digest),
    })
}

fn non_empty_string(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

impl BlockMetadata {
    pub fn from_block(block: &Block) -> Self {
        let pruning = block.pruning_proof.envelope_metadata();
        let previous_state_root = pruning
            .snapshot
            .state_commitment
            .as_str()
            .to_owned();

        Self {
            height: block.header.height,
            hash: block.hash.clone(),
            timestamp: block.header.timestamp,
            previous_state_root,
            new_state_root: block.header.state_root.clone(),
            proof_hash: block.header.proof_root.clone(),
            pruning: Some(pruning),
            recursive_commitment: block.recursive_proof.commitment.clone(),
            recursive_previous_commitment: block.recursive_proof.previous_commitment.clone(),
            recursive_system: block.recursive_proof.system.clone(),
            recursive_anchor: RecursiveProof::anchor(),
        }
    }

    pub fn pruning_metadata(&self) -> Option<&PruningEnvelopeMetadata> {
        self.pruning.as_ref()
    }

    pub fn pruning_binding_digest_hex(&self) -> Option<&str> {
        self.pruning_metadata()
            .map(|pruning| pruning.binding_digest.as_str())
    }

    pub fn pruning_aggregate_commitment_hex(&self) -> Option<&str> {
        self.pruning_metadata()
            .map(|pruning| pruning.commitment.aggregate_commitment.as_str())
    }

    pub fn pruning_segment_commitment_hex(&self) -> Option<&str> {
        self.pruning_metadata()
            .and_then(|pruning| pruning.segments.get(0))
            .map(|segment| segment.segment_commitment.as_str())
    }

    pub fn pruning_schema_version(&self) -> Option<u16> {
        self.pruning_metadata().map(|pruning| pruning.schema_version)
    }

    pub fn pruning_parameter_version(&self) -> Option<u16> {
        self.pruning_metadata()
            .map(|pruning| pruning.parameter_version)
    }
}

impl From<&Block> for BlockMetadata {
    fn from(block: &Block) -> Self {
        BlockMetadata::from_block(block)
    }
}

#[cfg(test)]
mod tests_prop;
