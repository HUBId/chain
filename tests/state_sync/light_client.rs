use std::collections::HashMap;

use base64::Engine as _;
use blake3::Hasher as Blake3Hasher;
use ed25519_dalek::Signature;
use rpp_chain::consensus::ConsensusCertificate;
use rpp_chain::node::{
    LightClientVerificationEvent, LightClientVerifier, StateSyncVerificationReport,
    VerificationErrorKind, DEFAULT_STATE_SYNC_CHUNK,
};
use rpp_chain::runtime::sync::ReconstructionEngine;
use rpp_chain::runtime::types::{
    pruning_from_previous, AttestedIdentityRequest, Block, BlockHeader, BlockProofBundle,
    ChainProof, ModuleWitnessBundle, ProofArtifact, ProofSystem, PruningProofExt,
    RecursiveProof, ReputationUpdate, SignedBftVote, SignedTransaction, TimetokeUpdate, UptimeProof,
};
use rpp_chain::state::merkle::compute_merkle_root;
use rpp_chain::storage::Storage;
use rpp_pruning::{COMMITMENT_TAG, DIGEST_LENGTH, DOMAIN_TAG_LENGTH};
use serde_json::{from_str, Value};
use storage::snapshots::{known_snapshot_sets, SnapshotEntry, SnapshotSet};
use storage_firewood::pruning::PersistedPrunerState;
use tempfile::TempDir;

#[path = "../support/mod.rs"]
mod support;

use support::{
    collect_state_sync_artifacts, dummy_pruning_proof, dummy_recursive_proof, dummy_state_proof,
    install_pruned_chain,
};

const PRUNER_STATE_KEY: &[u8] = b"pruner_state";

fn load_recorded_pruner_state() -> PersistedPrunerState {
    let raw = include_str!("fixtures/pruning_receipts.json");
    from_str(raw).expect("decode pruning receipts fixture")
}

fn load_corrupted_pruner_state() -> PersistedPrunerState {
    let raw = include_str!("fixtures/pruning_receipts.json");
    let mut value: Value = serde_json::from_str(raw).expect("decode pruning receipts json");
    if let Some(first) = value
        .get_mut("snapshots")
        .and_then(Value::as_array_mut)
        .and_then(|snapshots| snapshots.first_mut())
    {
        if let Some(commitment) = first.get_mut("state_commitment") {
            if let Some(bytes) = commitment.as_array_mut() {
                if let Some(byte) = bytes.first_mut().and_then(Value::as_u64) {
                    let flipped = byte ^ 0x01;
                    *bytes.first_mut().expect("commitment entry") = Value::from(flipped);
                }
            }
        }
    }
    serde_json::from_value(value).expect("decode corrupted pruning receipts")
}

fn dataset_for(state: &PersistedPrunerState) -> &'static SnapshotSet {
    known_snapshot_sets()
        .iter()
        .find(|set| set.schema_digest == state.schema_digest && set.parameter_digest == state.parameter_digest)
        .expect("persisted receipts must match known dataset")
}

fn make_block(
    height: u64,
    previous: Option<&Block>,
    state_root_override: Option<&str>,
) -> Block {
    let previous_hash = previous
        .map(|block| block.hash.clone())
        .unwrap_or_else(|| hex::encode([0u8; 32]));
    let mut tx_leaves: Vec<[u8; 32]> = Vec::new();
    let tx_root = hex::encode(compute_merkle_root(&mut tx_leaves));
    let state_root = state_root_override
        .map(str::to_owned)
        .unwrap_or_else(|| hex::encode([height as u8 + 2; 32]));
    let utxo_root = hex::encode([height as u8 + 3; 32]);
    let reputation_root = hex::encode([height as u8 + 4; 32]);
    let timetoke_root = hex::encode([height as u8 + 5; 32]);
    let zsi_root = hex::encode([height as u8 + 6; 32]);
    let proof_root = hex::encode([height as u8 + 7; 32]);
    let header = BlockHeader::new(
        height,
        previous_hash,
        tx_root,
        state_root.clone(),
        utxo_root.clone(),
        reputation_root.clone(),
        timetoke_root.clone(),
        zsi_root.clone(),
        proof_root.clone(),
        "0".to_string(),
        height.to_string(),
        vec![height as u8; 32],
        hex::encode([height as u8 + 8; 32]),
        hex::encode([height as u8 + 9; 32]),
        hex::encode([height as u8 + 10; 32]),
        hex::encode([height as u8 + 11; 32]),
        hex::encode([height as u8 + 12; 32]),
        hex::encode([height as u8 + 13; 32]),
    );
    build_block_from_header(header, previous)
}

fn build_block_from_header(header: BlockHeader, previous: Option<&Block>) -> Block {
    let pruning_proof = pruning_from_previous(previous, &header);
    let pruning_binding_digest = pruning_proof.binding_digest().prefixed_bytes();
    let pruning_segment_commitments = pruning_proof
        .segments()
        .iter()
        .map(|segment| segment.segment_commitment().prefixed_bytes())
        .collect::<Vec<_>>();

    let recursive_proof = RecursiveProof::from_parts(
        ProofSystem::Stwo,
        "99".repeat(32),
        None,
        pruning_binding_digest.clone(),
        pruning_segment_commitments.clone(),
        ChainProof::Stwo(dummy_recursive_proof(
            None,
            "99".repeat(32),
            &header,
            &pruning_proof,
        )),
    )
    .expect("construct recursive proof");

    let state_stark = dummy_state_proof();
    let pruning_stark = dummy_pruning_proof();
    let recursive_chain = ChainProof::Stwo(dummy_recursive_proof(
        recursive_proof.previous_commitment.clone(),
        recursive_proof.commitment.clone(),
        &header,
        &pruning_proof,
    ));

    let module_witnesses = ModuleWitnessBundle::default();
    let proof_artifacts = Vec::<ProofArtifact>::new();
    let stark_bundle = BlockProofBundle::new(
        Vec::new(),
        ChainProof::Stwo(state_stark),
        ChainProof::Stwo(pruning_stark),
        recursive_chain,
    );
    let signature = Signature::from_bytes(&[0u8; 64]).expect("signature bytes");
    let mut consensus = ConsensusCertificate::genesis();
    consensus.round = header.height;

    Block::new(
        header,
        Vec::<AttestedIdentityRequest>::new(),
        Vec::<SignedTransaction>::new(),
        Vec::<UptimeProof>::new(),
        Vec::<TimetokeUpdate>::new(),
        Vec::<ReputationUpdate>::new(),
        Vec::<SignedBftVote>::new(),
        module_witnesses,
        proof_artifacts,
        pruning_proof,
        recursive_proof,
        stark_bundle,
        signature,
        consensus,
        None,
    )
}

fn build_dataset_chain(dataset: &SnapshotSet) -> Vec<Block> {
    let max_height = dataset
        .snapshots
        .iter()
        .map(|entry| entry.block_height)
        .max()
        .unwrap_or(0);
    let mut blocks = Vec::with_capacity((max_height + 1) as usize);
    let mut previous: Option<Block> = None;
    let overrides: HashMap<u64, &str> = dataset
        .snapshots
        .iter()
        .map(|entry| (entry.block_height, entry.state_root))
        .collect();
    for height in 0..=max_height {
        let override_root = overrides.get(&height).copied();
        let block = make_block(height, previous.as_ref(), override_root);
        previous = Some(block.clone());
        blocks.push(block);
    }
    blocks
}

fn persist_pruner_state(storage: &Storage, state: &PersistedPrunerState) {
    let encoded = bincode::serialize(state).expect("encode pruner state");
    storage
        .write_metadata_blob(PRUNER_STATE_KEY, encoded)
        .expect("persist pruner state");
}

fn decode_commitment_base64(value: &str) -> [u8; DIGEST_LENGTH] {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .expect("base64 pruning commitment");
    assert_eq!(
        bytes.len(),
        DOMAIN_TAG_LENGTH + DIGEST_LENGTH,
        "unexpected pruning commitment length"
    );
    assert_eq!(
        &bytes[..DOMAIN_TAG_LENGTH],
        COMMITMENT_TAG.as_bytes(),
        "unexpected pruning commitment tag"
    );
    let mut digest = [0u8; DIGEST_LENGTH];
    digest.copy_from_slice(&bytes[DOMAIN_TAG_LENGTH..]);
    digest
}

fn chunk_merkle_root(chunks: &[rpp_p2p::NetworkStateSyncChunk]) -> [u8; DIGEST_LENGTH] {
    let mut chunk_roots = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let mut leaves = Vec::with_capacity(chunk.proofs.len());
        for proof in &chunk.proofs {
            leaves.push(decode_commitment_base64(proof));
        }
        chunk_roots.push(compute_merkle_root(&mut leaves));
    }
    compute_merkle_root(&mut chunk_roots)
}

fn compute_state_commitment(
    dataset: &SnapshotSet,
    entry: &SnapshotEntry,
) -> String {
    let mut hasher = Blake3Hasher::new();
    hasher.update(b"fw-pruning-snapshot");
    hasher.update(&dataset.schema_digest);
    hasher.update(&dataset.parameter_digest);
    hasher.update(&entry.block_height.to_be_bytes());
    hasher.update(&decode_hex_digest(entry.state_root));
    hex::encode(hasher.finalize().as_bytes())
}

fn decode_hex_digest(value: &str) -> [u8; DIGEST_LENGTH] {
    let bytes = hex::decode(value).expect("hex digest");
    assert_eq!(bytes.len(), DIGEST_LENGTH, "digest must encode 32 bytes");
    let mut digest = [0u8; DIGEST_LENGTH];
    digest.copy_from_slice(&bytes);
    digest
}

struct PreparedContext {
    _tempdir: TempDir,
    storage: Storage,
    artifacts: support::StateSyncArtifacts,
    dataset: &'static SnapshotSet,
}

fn prepare_context(state: PersistedPrunerState) -> PreparedContext {
    let dataset = dataset_for(&state);
    let tempdir = TempDir::new().expect("temp dir");
    let storage = Storage::open(tempdir.path()).expect("open storage");
    let blocks = build_dataset_chain(dataset);
    install_pruned_chain(&storage, &blocks).expect("install pruned chain");
    persist_pruner_state(&storage, &state);

    let engine = ReconstructionEngine::new(storage.clone());
    let artifacts = collect_state_sync_artifacts(&engine, DEFAULT_STATE_SYNC_CHUNK)
        .expect("collect state sync artifacts");

    PreparedContext {
        _tempdir: tempdir,
        storage,
        artifacts,
        dataset,
    }
}

fn expect_success_report(context: &PreparedContext) -> StateSyncVerificationReport {
    let verifier = LightClientVerifier::new(context.storage.clone());
    verifier
        .run(DEFAULT_STATE_SYNC_CHUNK)
        .expect("verification succeeds")
}

#[test]
fn light_client_verifier_reports_complete_success() {
    let state = load_recorded_pruner_state();
    let context = prepare_context(state);
    let report = expect_success_report(&context);
    let plan = &context.artifacts.plan;
    let chunk_count = plan.chunks.len();
    let update_count = context.artifacts.updates.len();
    let dataset_entry = context
        .dataset
        .snapshots
        .iter()
        .find(|entry| entry.block_height == plan.snapshot.height)
        .expect("dataset snapshot present");
    let expected_commitment = compute_state_commitment(context.dataset, dataset_entry);
    let expected_snapshot_root = chunk_merkle_root(&context.artifacts.chunk_messages);
    let expected_events = {
        let mut events = Vec::new();
        events.push(LightClientVerificationEvent::PlanLoaded {
            snapshot_height: plan.snapshot.height,
            chunk_count,
            update_count,
        });
        events.push(LightClientVerificationEvent::PlanIngested {
            chunk_count,
            update_count,
        });
        events.push(LightClientVerificationEvent::SnapshotMetadataValidated {
            dataset_label: context.dataset.label.to_string(),
            state_root: dataset_entry.state_root.to_string(),
            state_commitment: expected_commitment.clone(),
        });
        events.push(LightClientVerificationEvent::ReceiptsMatched {
            dataset_label: context.dataset.label.to_string(),
            snapshot_count: context.dataset.snapshots.len(),
        });
        for chunk in &context.artifacts.chunk_messages {
            events.push(LightClientVerificationEvent::MerkleRootConfirmed {
                start_height: chunk.start_height,
                end_height: chunk.end_height,
            });
        }
        for update in &context.artifacts.updates {
            events.push(LightClientVerificationEvent::RecursiveProofVerified {
                height: update.height,
            });
        }
        events.push(LightClientVerificationEvent::VerificationCompleted {
            snapshot_root: hex::encode(expected_snapshot_root),
        });
        events
    };
    assert_eq!(report.events, expected_events, "event sequence must match");
    assert_eq!(
        report.summary.snapshot_height,
        Some(plan.snapshot.height),
        "snapshot height reported",
    );
    assert_eq!(
        report.summary.snapshot_root.as_deref(),
        Some(dataset_entry.state_root),
        "snapshot root must match dataset",
    );
    assert_eq!(
        report.summary.failure,
        None,
        "summary must report success",
    );
}

#[test]
fn light_client_verifier_flags_metadata_mismatch() {
    let corrupted = load_corrupted_pruner_state();
    let context = prepare_context(corrupted);
    let verifier = LightClientVerifier::new(context.storage.clone());
    let error = verifier
        .run(DEFAULT_STATE_SYNC_CHUNK)
        .expect_err("metadata mismatch must fail");
    assert!(
        matches!(error.kind(), VerificationErrorKind::Metadata(_)),
        "verification error must report metadata mismatch"
    );
    let report = error.report().clone();
    assert_eq!(
        report.summary.failure.as_deref(),
        Some("state commitment mismatch for block 4096"),
        "failure summary must highlight mismatched height",
    );
}
