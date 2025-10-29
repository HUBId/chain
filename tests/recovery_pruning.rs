mod support;

use std::fs;

use rpp_chain::config::NodeConfig;
use rpp_chain::node::Node;
use rpp_chain::runtime::sync::ReconstructionEngine;
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

    let status = handle
        .run_pruning_cycle(2)
        .expect("pruning cycle")
        .expect("pruning status");
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
