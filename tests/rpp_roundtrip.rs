mod support;

use std::fs;

use rpp_chain::config::NodeConfig;
use rpp_chain::node::Node;
use rpp_chain::runtime::sync::{PayloadProvider, ReconstructionEngine, ReconstructionRequest};
use rpp_chain::runtime::types::{BlockMetadata, BlockPayload};
use rpp_chain::runtime::RuntimeMetrics;
use storage_firewood::pruning::FirewoodPruner;
use storage_firewood::state::FirewoodState;
use tempfile::TempDir;

use support::seeded_rng;

struct SinglePayload {
    height: u64,
    payload: BlockPayload,
}

impl PayloadProvider for SinglePayload {
    fn fetch_payload(&self, request: &ReconstructionRequest) -> rpp_chain::errors::ChainResult<BlockPayload> {
        if request.height == self.height {
            Ok(self.payload.clone())
        } else {
            Err(rpp_chain::errors::ChainError::Config(format!(
                "unexpected payload request for height {}",
                request.height
            )))
        }
    }
}

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

    let firewood_temp = TempDir::new().expect("firewood temp dir");
    let firewood_dir = firewood_temp.path().join("firewood");
    let firewood_path = firewood_dir.to_string_lossy().to_string();
    let state = FirewoodState::open(&firewood_path).expect("open firewood state");

    let mut proofs = Vec::new();
    for block_id in 1..=5u64 {
        for entry in 0..3u8 {
            let key = format!("block-{block_id}-key-{entry}").into_bytes();
            let value = format!("value-{block_id}-{entry}").into_bytes();
            state.put(key, value);
        }
        let (state_root, proof) = state.commit_block(block_id).expect("commit block");
        assert!(
            FirewoodPruner::verify_pruned_state(state_root, &proof),
            "proof validates the committed state root"
        );
        proofs.push((state_root, proof));
    }

    drop(state);

    for (root, proof) in &proofs {
        assert!(
            FirewoodPruner::verify_pruned_state(*root, proof),
            "pruning proof should validate against the recorded state root"
        );
    }

    let (config, temp) = prepare_config();
    let runtime_metrics = RuntimeMetrics::noop();
    let node = Node::new(config, runtime_metrics).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let genesis = handle
        .latest_block()
        .expect("latest block")
        .expect("genesis block");
    let metadata = BlockMetadata::from(&genesis);
    storage
        .store_block(&genesis, &metadata)
        .expect("persist genesis block");
    let payload = BlockPayload::from_block(&genesis);

    storage
        .prune_block_payload(genesis.header.height)
        .expect("prune payload");

    let provider = SinglePayload {
        height: genesis.header.height,
        payload,
    };
    let engine = ReconstructionEngine::new(storage.clone());
    let rebuilt = engine
        .reconstruct_block(genesis.header.height, &provider)
        .expect("reconstruct pruned block");

    assert_eq!(rebuilt.hash, genesis.hash, "reconstructed block hash matches");
    assert!(!rebuilt.pruned, "reconstructed block should restore payload");

    drop(rebuilt);
    drop(engine);
    drop(storage);
    drop(handle);
    drop(node);
    drop(temp);
    drop(firewood_temp);
}
