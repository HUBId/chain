mod support;

use std::fs;
use std::path::Path;

use rpp_chain::config::{NodeConfig, DEFAULT_PRUNING_RETENTION_DEPTH};
use rpp_chain::errors::ChainError;
use rpp_chain::node::Node;
use rpp_chain::runtime::sync::{
    CheckpointSignatureConfig, PruningCheckpoint, ReconstructionEngine,
};
use rpp_chain::runtime::types::Block;
use rpp_chain::runtime::RuntimeMetrics;
use tempfile::TempDir;

use support::{install_pruned_chain, make_dummy_block, seeded_rng};

fn prepare_config() -> (NodeConfig, TempDir) {
    let temp = TempDir::new().expect("temp dir");
    let mut config = NodeConfig::default();
    let data_dir = temp.path().join("data");
    let keys_dir = temp.path().join("keys");
    fs::create_dir_all(&data_dir).expect("data dir");
    fs::create_dir_all(&keys_dir).expect("keys dir");
    config.data_dir = data_dir.clone();
    config.snapshot_dir = data_dir.join("snapshots");
    config.proof_cache_dir = data_dir.join("proofs");
    config.network.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
    config.network.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
    config.key_path = keys_dir.join("node.toml");
    config.p2p_key_path = keys_dir.join("p2p.toml");
    config.vrf_key_path = keys_dir.join("vrf.toml");
    config.rollout.feature_gates.pruning = true;
    config.rollout.feature_gates.reconstruction = true;
    config.rollout.feature_gates.recursive_proofs = false;
    config.rollout.feature_gates.consensus_enforcement = false;
    config.network.rpc.listen = "127.0.0.1:0".parse().expect("rpc listen");
    (config, temp)
}

fn checkpoint_signing_config(config: &NodeConfig) -> CheckpointSignatureConfig {
    let signing_key = config
        .pruning
        .checkpoint_signatures
        .load_signing_key()
        .expect("load pruning checkpoint signing key");
    let verifying_key = config
        .pruning
        .checkpoint_signatures
        .verifying_key()
        .expect("decode pruning checkpoint verifying key")
        .or_else(|| {
            signing_key
                .as_ref()
                .map(|key| key.signing_key.verifying_key())
        });

    CheckpointSignatureConfig {
        signing_key,
        verifying_key,
        expected_version: config.pruning.checkpoint_signatures.signature_version,
        require_signatures: config.pruning.checkpoint_signatures.require_signatures,
    }
}

fn build_chain(handle: &rpp_chain::node::NodeHandle, length: u64) -> Vec<Block> {
    let genesis = handle
        .latest_block()
        .expect("latest block")
        .expect("genesis block");
    let mut blocks = Vec::new();
    blocks.push(genesis.clone());
    let mut previous = Some(genesis);
    for height in 1..=length {
        let block = make_dummy_block(height, previous.as_ref());
        previous = Some(block.clone());
        blocks.push(block);
    }
    blocks
}

#[test]
fn pruning_recovery_is_atomic_across_restart() {
    let mut _rng = seeded_rng("pruning_recovery_is_atomic_across_restart");

    let (config, temp) = prepare_config();
    let restart_config = config.clone();
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let blocks = build_chain(&handle, 4);
    install_pruned_chain(&storage, &blocks).expect("install pruned chain");

    let summary = handle
        .run_pruning_cycle(2, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("pruning cycle");
    let status = summary.status.expect("pruning status");
    assert!(!summary.cancelled, "unexpected cancellation");
    assert!(
        !status.stored_proofs.is_empty(),
        "pruning cycle should persist pruning proofs"
    );

    drop(handle);
    drop(node);

    let node = Node::new(restart_config, RuntimeMetrics::noop()).expect("restart node");
    let handle = node.handle();
    let storage = handle.storage();

    let mut pruned = 0usize;
    let mut hydrated = 0usize;
    for block in &blocks {
        let stored = storage
            .read_block(block.header.height)
            .expect("read block")
            .expect("block present");
        if stored.pruned {
            pruned += 1;
        } else {
            hydrated += 1;
        }
    }

    assert!(
        pruned == 0 || hydrated == 0,
        "storage should not mix pruned ({pruned}) and hydrated ({hydrated}) payloads after restart",
    );

    let engine = ReconstructionEngine::new(storage.clone());
    let plan = engine.full_plan().expect("reload reconstruction plan");
    if pruned == 0 {
        assert!(
            plan.requests.is_empty(),
            "no reconstruction needed when payloads remain hydrated",
        );
    } else {
        assert_eq!(
            plan.requests.len(),
            pruned,
            "plan should request payload for every pruned block",
        );
    }

    drop(engine);
    drop(storage);
    drop(handle);
    drop(node);
    drop(temp);
}

#[test]
fn pruning_rolls_back_after_snapshot_persist_failure() {
    let mut _rng = seeded_rng("pruning_rolls_back_after_snapshot_persist_failure");

    let (mut config, temp) = prepare_config();
    let snapshot_file = temp.path().join("snapshots");
    fs::write(&snapshot_file, "locked").expect("create blocking snapshot path");
    config.snapshot_dir = snapshot_file.clone();

    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();

    let attempt = handle.run_pruning_cycle(2, DEFAULT_PRUNING_RETENTION_DEPTH);
    assert!(
        matches!(attempt, Err(ChainError::Io(_))),
        "pruning cycle should surface storage IO errors"
    );
    assert!(
        handle.pruning_job_status().is_none(),
        "failed cycles should not cache pruning status"
    );

    fs::remove_file(&snapshot_file).expect("clear blocking snapshot path");
    fs::create_dir_all(&snapshot_file).expect("create snapshot directory");

    let retry = handle
        .run_pruning_cycle(2, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("retry pruning cycle");
    let retry = retry.status.expect("pruning status after retry");

    assert!(retry.persisted_path.is_some(), "retry should persist plan");
    assert!(
        retry.missing_heights.is_empty(),
        "retry should succeed after IO recovery"
    );

    drop(handle);
    drop(node);
    drop(temp);
}

#[test]
fn pruning_checkpoint_recovery_rejects_partial_files() {
    let (config, temp) = prepare_config();
    let snapshot_dir = config.snapshot_dir.clone();
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let blocks = build_chain(&handle, 3);
    install_pruned_chain(&storage, &blocks).expect("install pruned chain");

    let status = handle
        .run_pruning_cycle(2, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("pruning cycle");
    let status = status.status.expect("pruning status");
    let checkpoint_path = Path::new(
        status
            .persisted_path
            .as_ref()
            .expect("checkpoint path should be recorded"),
    )
    .to_path_buf();

    let checkpoint_bytes = fs::read(&checkpoint_path).expect("read pruning checkpoint");
    let checkpoint: PruningCheckpoint =
        serde_json::from_slice(&checkpoint_bytes).expect("decode pruning checkpoint");
    assert_eq!(
        checkpoint.metadata.height, checkpoint.plan.snapshot.height,
        "metadata should track snapshot height",
    );
    assert!(
        !checkpoint.metadata.backend.is_empty(),
        "backend recorded in metadata"
    );
    assert!(
        checkpoint.metadata.timestamp > 0,
        "checkpoint timestamp populated"
    );

    // Simulate a crash mid-write by writing a truncated payload to a different checkpoint path.
    let partial_path = checkpoint_path
        .parent()
        .expect("checkpoint parent")
        .join("snapshot-999999.json");
    let partial_bytes = &checkpoint_bytes[..checkpoint_bytes.len() / 2];
    fs::write(&partial_path, partial_bytes).expect("write partial checkpoint");

    let engine = ReconstructionEngine::with_snapshot_dir(storage, snapshot_dir);
    let recovered = engine
        .recover_checkpoint()
        .expect("recover pruning checkpoint")
        .expect("checkpoint should be recovered");
    assert_eq!(
        recovered.metadata.height, checkpoint.metadata.height,
        "recovery should ignore corrupted checkpoints",
    );
    assert_eq!(
        recovered.metadata.backend, checkpoint.metadata.backend,
        "backend metadata should survive recovery",
    );

    drop(handle);
    drop(node);
    drop(temp);
}

#[test]
fn pruning_checkpoint_signature_rejects_tampered_payload() {
    let (mut config, temp) = prepare_config();
    let snapshot_dir = config.snapshot_dir.clone();
    let keys_dir = temp.path().join("keys");
    config.pruning.checkpoint_signatures.signing_key_path =
        Some(keys_dir.join("pruning-checkpoint-signing.toml"));
    config.pruning.checkpoint_signatures.require_signatures = true;
    let restart_config = config.clone();

    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let blocks = build_chain(&handle, 3);
    install_pruned_chain(&storage, &blocks).expect("install pruned chain");

    let status = handle
        .run_pruning_cycle(2, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("pruning cycle")
        .status
        .expect("pruning status");
    let checkpoint_path = Path::new(
        status
            .persisted_path
            .as_ref()
            .expect("checkpoint path should be recorded"),
    )
    .to_path_buf();

    let mut checkpoint_bytes = fs::read(&checkpoint_path).expect("read pruning checkpoint");
    checkpoint_bytes[0] = checkpoint_bytes[0].wrapping_add(1);
    fs::write(&checkpoint_path, &checkpoint_bytes).expect("tamper pruning checkpoint");

    let signing = checkpoint_signing_config(&restart_config);
    let engine = ReconstructionEngine::with_snapshot_dir(storage, snapshot_dir)
        .with_checkpoint_signatures(signing);

    let err = engine
        .recover_checkpoint()
        .expect_err("tampered checkpoint should be rejected");
    assert!(matches!(err, ChainError::Config(msg) if msg.contains("signature")));

    drop(handle);
    drop(node);
    drop(temp);
}

#[test]
fn pruning_checkpoint_signature_rejects_tampered_signature() {
    let (mut config, temp) = prepare_config();
    let snapshot_dir = config.snapshot_dir.clone();
    let keys_dir = temp.path().join("keys");
    config.pruning.checkpoint_signatures.signing_key_path =
        Some(keys_dir.join("pruning-checkpoint-signing.toml"));
    config.pruning.checkpoint_signatures.require_signatures = true;
    let restart_config = config.clone();

    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let blocks = build_chain(&handle, 3);
    install_pruned_chain(&storage, &blocks).expect("install pruned chain");

    let status = handle
        .run_pruning_cycle(2, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("pruning cycle")
        .status
        .expect("pruning status");
    let checkpoint_path = Path::new(
        status
            .persisted_path
            .as_ref()
            .expect("checkpoint path should be recorded"),
    )
    .to_path_buf();

    let mut signature_path = checkpoint_path.clone();
    let mut sig_name = signature_path
        .file_name()
        .expect("checkpoint filename")
        .to_os_string();
    sig_name.push(".sig");
    signature_path.set_file_name(sig_name);
    fs::write(&signature_path, "invalid:signature").expect("tamper pruning signature");

    let signing = checkpoint_signing_config(&restart_config);
    let engine = ReconstructionEngine::with_snapshot_dir(storage, snapshot_dir)
        .with_checkpoint_signatures(signing);

    let err = engine
        .recover_checkpoint()
        .expect_err("tampered signature should be rejected");
    assert!(matches!(err, ChainError::Config(msg) if msg.contains("signature")));

    drop(handle);
    drop(node);
    drop(temp);
}
