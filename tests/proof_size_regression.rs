mod support;

use std::collections::BTreeSet;
use std::fs;

use rpp_chain::config::NodeConfig;
use rpp_chain::node::Node;
use rpp_chain::runtime::types::Block;
use rpp_chain::runtime::RuntimeMetrics;
use rpp_pruning::canonical_bincode_options;
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
fn pruning_proof_size_regression_guard() {
    let mut _rng = seeded_rng("pruning_proof_size_regression_guard");

    let (config, temp) = prepare_config();
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let blocks = build_chain(&handle, 5);
    install_pruned_chain(&storage, &blocks).expect("install pruned chain");

    let mut previous_total: Option<usize> = None;
    for cycle in 0..3 {
        let status = handle
            .run_pruning_cycle(2)
            .expect("pruning cycle")
            .expect("pruning status");
        assert!(
            !status.missing_heights.is_empty(),
            "cycle {cycle} should report pruned heights",
        );

        let heights: BTreeSet<u64> = status.missing_heights.iter().copied().collect();
        let mut total_size = 0usize;
        for height in heights {
            let proof = storage
                .load_pruning_proof(height)
                .expect("load pruning proof")
                .expect("pruning proof persisted");
            let bytes = canonical_bincode_options()
                .serialize(proof.as_ref())
                .expect("encode pruning proof");
            total_size += bytes.len();
        }

        if let Some(previous) = previous_total {
            let allowed = (previous as f64 * 1.05).ceil() as usize;
            assert!(
                total_size <= allowed,
                "pruning proof payload grew from {previous} bytes to {total_size} bytes on cycle {cycle}",
            );
        } else {
            assert!(
                total_size > 0,
                "initial pruning cycle should persist non-empty proofs",
            );
        }
        previous_total = Some(total_size);
    }

    drop(storage);
    drop(handle);
    drop(node);
    drop(temp);
}
