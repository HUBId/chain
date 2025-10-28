mod support;

use std::collections::HashMap;
use std::fs;

use bincode;
use rpp_chain::config::NodeConfig;
use rpp_chain::errors::ChainError;
use rpp_chain::node::Node;
use rpp_chain::runtime::sync::ReconstructionEngine;
use rpp_chain::runtime::types::{Block, BlockMetadata, PruningProofExt};
use rpp_chain::runtime::RuntimeMetrics;
use tempfile::TempDir;

use support::{
    install_pruned_chain, make_dummy_block, mutate_hex, seeded_rng, InMemoryPayloadProvider,
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
fn pruning_recovery_cycle_restores_commitments() {
    let mut _rng = seeded_rng("pruning_recovery_cycle_restores_commitments");

    let (config, temp) = prepare_config();
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let blocks = build_chain(&handle, 4);
    let payloads = install_pruned_chain(&storage, &blocks).expect("install chain");

    let engine = ReconstructionEngine::new(storage.clone());
    engine.verify_proof_chain().expect("proof chain valid");

    let provider = InMemoryPayloadProvider::new(payloads);
    let start = blocks.first().expect("blocks available").header.height;
    let end = blocks.last().expect("blocks available").header.height;
    let rebuilt = engine
        .reconstruct_range(start, end, &provider)
        .expect("reconstruct range");

    let rebuilt_map: HashMap<u64, Block> =
        rebuilt.into_iter().map(|block| (block.header.height, block)).collect();

    for original in &blocks {
        let rebuilt = rebuilt_map
            .get(&original.header.height)
            .expect("rehydrated block");
        assert_eq!(
            rebuilt.hash, original.hash,
            "rehydrated block hash matches at height {}",
            original.header.height
        );
        assert_eq!(
            rebuilt.pruning_proof.aggregate_commitment_hex(),
            original.pruning_proof.aggregate_commitment_hex(),
            "rehydrated pruning commitment matches at height {}",
            original.header.height
        );
    }

    drop(engine);
    drop(storage);
    drop(handle);
    drop(node);
    drop(temp);
}

#[test]
fn pruning_recovery_detects_invalid_proof() {
    let mut _rng = seeded_rng("pruning_recovery_detects_invalid_proof");
    let (config, temp) = prepare_config();
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let blocks = build_chain(&handle, 3);
    install_pruned_chain(&storage, &blocks).expect("install chain");

    let target_height = 3;
    let mut corrupted = storage
        .read_block(target_height)
        .expect("read block")
        .expect("block present");
    corrupted.recursive_proof.commitment = mutate_hex(&corrupted.recursive_proof.commitment);
    let metadata = BlockMetadata::from(&corrupted);
    storage
        .store_block(&corrupted, &metadata)
        .expect("store corrupted block");
    let _ = storage
        .prune_block_payload(target_height)
        .expect("re-prune corrupted block");

    let engine = ReconstructionEngine::new(storage.clone());
    let err = engine
        .verify_proof_chain()
        .expect_err("invalid proof should be detected");
    match err {
        ChainError::InvalidProof(message) => {
            assert!(message.contains(&target_height.to_string()));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    drop(engine);
    drop(storage);
    drop(handle);
    drop(node);
    drop(temp);
}

#[test]
fn pruning_recovery_detects_commitment_mismatch() {
    let mut _rng = seeded_rng("pruning_recovery_detects_commitment_mismatch");
    let (config, temp) = prepare_config();
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let blocks = build_chain(&handle, 2);
    install_pruned_chain(&storage, &blocks).expect("install chain");

    let target_height = 2;
    let mut metadata = storage
        .read_block_metadata(target_height)
        .expect("read metadata")
        .expect("metadata present");
    metadata.recursive_commitment = mutate_hex(&metadata.recursive_commitment);
    let mut suffix = Vec::from(b"block_metadata/".as_slice());
    suffix.extend_from_slice(&target_height.to_be_bytes());
    let encoded = bincode::serialize(&metadata).expect("encode metadata");
    storage
        .write_metadata_blob(&suffix, encoded)
        .expect("write corrupted metadata");

    let engine = ReconstructionEngine::new(storage.clone());
    let err = engine
        .verify_proof_chain()
        .expect_err("commitment mismatch should be detected");
    match err {
        ChainError::CommitmentMismatch(message) => {
            assert!(message.contains(&target_height.to_string()));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    drop(engine);
    drop(storage);
    drop(handle);
    drop(node);
    drop(temp);
}
