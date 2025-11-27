mod support;

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use rpp_chain::config::{NodeConfig, DEFAULT_PRUNING_RETENTION_DEPTH};
use rpp_chain::node::Node;
use rpp_chain::runtime::sync::ReconstructionEngine;
use rpp_chain::runtime::types::{Block, BlockMetadata, PruningProofExt};
use rpp_chain::runtime::RuntimeMetrics;
use tempfile::TempDir;

use support::{
    collect_state_sync_artifacts, install_pruned_chain, make_dummy_block, seeded_rng,
    InMemoryPayloadProvider,
};

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
fn rpp_pruning_roundtrip_preserves_commitments() {
    let mut _rng = seeded_rng("rpp_pruning_roundtrip_preserves_commitments");

    let (config, temp) = prepare_config();
    let snapshot_dir = config.snapshot_dir.clone();
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let blocks = build_chain(&handle, 6);
    let payloads = install_pruned_chain(&storage, &blocks).expect("install pruned chain");

    for block in &blocks {
        let stored = storage
            .read_block(block.header.height)
            .expect("read stored block")
            .expect("block persisted");
        assert!(
            stored.pruned,
            "block {} should be pruned",
            block.header.height
        );
    }

    let summary = handle
        .run_pruning_cycle(2, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("pruning cycle");
    let status = summary.status.expect("pruning status");
    assert!(!summary.cancelled, "unexpected cancellation");
    let persisted_path = status
        .persisted_path
        .as_deref()
        .expect("snapshot plan persisted");
    assert!(
        Path::new(persisted_path).exists(),
        "persisted pruning plan should exist on disk"
    );

    let engine = ReconstructionEngine::with_snapshot_dir(storage.clone(), snapshot_dir.clone());
    let artifacts = collect_state_sync_artifacts(&engine, 2).expect("collect state sync artifacts");

    let mut advertised_heights: Vec<u64> =
        artifacts.requests().map(|request| request.height).collect();
    advertised_heights.sort_unstable();
    let mut expected_heights: Vec<u64> = blocks.iter().map(|block| block.header.height).collect();
    expected_heights.sort_unstable();
    assert_eq!(
        advertised_heights, expected_heights,
        "reconstruction plan should enumerate every stored height",
    );

    assert_eq!(
        artifacts.plan.snapshot.height, status.plan.snapshot.height,
        "snapshot height should match pruning status",
    );
    assert_eq!(
        artifacts.plan.tip.height, status.plan.tip.height,
        "tip height should match pruning status",
    );

    for request in artifacts.requests() {
        let original = blocks
            .iter()
            .find(|block| block.header.height == request.height)
            .expect("plan references stored block");
        assert_eq!(
            request.block_hash, original.hash,
            "plan preserves block hash at height {}",
            request.height
        );
        assert_eq!(
            request.pruning.commitment.aggregate_commitment.as_str(),
            original.pruning_proof.aggregate_commitment_hex(),
            "plan preserves aggregate pruning commitment at height {}",
            request.height
        );
        assert_eq!(
            request.pruning.binding_digest.as_str(),
            original.pruning_proof.binding_digest_hex(),
            "plan preserves pruning binding digest at height {}",
            request.height
        );
    }

    let provider = InMemoryPayloadProvider::new(payloads);
    let plan = engine.full_plan().expect("reconstruction plan");
    let reconstructed = engine
        .execute_plan(&plan, &provider)
        .expect("execute reconstruction plan");

    let rebuilt_by_height: HashMap<u64, Block> = reconstructed
        .into_iter()
        .map(|block| (block.header.height, block))
        .collect();

    for original in &blocks {
        let rebuilt = rebuilt_by_height
            .get(&original.header.height)
            .expect("reconstructed block present");
        assert_eq!(
            rebuilt.hash, original.hash,
            "rehydrated block hash matches at height {}",
            original.header.height
        );
        assert!(
            !rebuilt.pruned,
            "rehydrated block {} should contain payload",
            rebuilt.header.height
        );
        assert_eq!(
            rebuilt.pruning_proof.aggregate_commitment_hex(),
            original.pruning_proof.aggregate_commitment_hex(),
            "rehydrated pruning commitment matches at height {}",
            original.header.height
        );
        assert_eq!(
            rebuilt.pruning_proof.binding_digest_hex(),
            original.pruning_proof.binding_digest_hex(),
            "rehydrated binding digest matches at height {}",
            original.header.height
        );
    }

    for block in rebuilt_by_height.values() {
        let metadata = BlockMetadata::from(block);
        storage
            .store_block(block, &metadata)
            .expect("persist hydrated block");
    }

    let refreshed = ReconstructionEngine::new(storage.clone());
    let refreshed_plan = refreshed.full_plan().expect("refreshed plan");
    assert!(
        refreshed_plan.requests.is_empty(),
        "reconstruction plan should be empty after replay",
    );

    drop(engine);
    drop(storage);
    drop(handle);
    drop(node);
    drop(snapshot_dir);
    drop(temp);
}
