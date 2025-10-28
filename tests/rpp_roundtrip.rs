mod support;

use std::collections::HashMap;
use std::fs;

use rpp_chain::config::NodeConfig;
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
    config.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
    config.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
    config.key_path = keys_dir.join("node.toml");
    config.p2p_key_path = keys_dir.join("p2p.toml");
    config.vrf_key_path = keys_dir.join("vrf.toml");
    config.rollout.feature_gates.pruning = true;
    config.rollout.feature_gates.reconstruction = true;
    config.rollout.feature_gates.recursive_proofs = false;
    config.rollout.feature_gates.consensus_enforcement = false;
    config.rpc_listen = "127.0.0.1:0".parse().expect("rpc listen");
    (config, temp)
}

#[test]
fn rpp_pruning_roundtrip() {
    let mut _rng = seeded_rng("rpp_pruning_roundtrip");

    let (config, temp) = prepare_config();
    let runtime_metrics = RuntimeMetrics::noop();
    let node = Node::new(config, runtime_metrics).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let genesis = handle
        .latest_block()
        .expect("latest block")
        .expect("genesis block");

    let mut blocks: Vec<Block> = Vec::new();
    blocks.push(genesis.clone());
    let mut previous = Some(genesis.clone());
    for height in 1..=4u64 {
        let block = make_dummy_block(height, previous.as_ref());
        previous = Some(block.clone());
        blocks.push(block);
    }

    let payloads = install_pruned_chain(&storage, &blocks).expect("install pruned chain");

    for block in &blocks {
        let stored = storage
            .read_block(block.header.height)
            .expect("read stored block")
            .expect("block persisted");
        assert!(stored.pruned, "block {} should be pruned", block.header.height);
    }

    let engine = ReconstructionEngine::new(storage.clone());
    let artifacts = collect_state_sync_artifacts(&engine, 2).expect("state sync artifacts");

    let blocks_by_height: HashMap<u64, &Block> =
        blocks.iter().map(|block| (block.header.height, block)).collect();

    let mut advertised_heights: Vec<u64> = artifacts.requests().map(|request| request.height).collect();
    advertised_heights.sort_unstable();
    let mut expected_heights: Vec<u64> = blocks_by_height.keys().copied().collect();
    expected_heights.sort_unstable();
    assert_eq!(
        advertised_heights,
        expected_heights,
        "reconstruction plan should enumerate every stored height",
    );

    for request in artifacts.requests() {
        let original = blocks_by_height
            .get(&request.height)
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
    let start_height = blocks.first().expect("blocks available").header.height;
    let end_height = blocks.last().expect("blocks available").header.height;
    let reconstructed = engine
        .reconstruct_range(start_height, end_height, &provider)
        .expect("reconstruct pruned range");

    let rebuilt_by_height: HashMap<u64, Block> =
        reconstructed.into_iter().map(|block| (block.header.height, block)).collect();

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
    assert!(refreshed_plan.is_fully_hydrated());

    drop(engine);
    drop(storage);
    drop(handle);
    drop(node);
    drop(temp);
}
