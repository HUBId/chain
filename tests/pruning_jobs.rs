use std::fs;
use std::time::Duration;

use rpp_chain::config::NodeConfig;
use rpp_chain::errors::{ChainError, ChainResult};
use rpp_chain::node::{Node, PruningJobStatus};
use rpp_chain::runtime::sync::{PayloadProvider, ReconstructionEngine, ReconstructionRequest};
use rpp_chain::runtime::types::BlockPayload;
use rpp_p2p::GossipTopic;
use tempfile::TempDir;
use tokio::time::timeout;

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
fn pruning_plan_without_pending_blocks() {
    let (config, _temp) = prepare_config();
    let node = Node::new(config).expect("node");
    let handle = node.handle();

    let status = handle.run_pruning_cycle(4).expect("cycle").expect("status");

    assert!(
        status.missing_heights.is_empty(),
        "expected no missing heights"
    );
    assert!(status.plan.chunks.is_empty(), "expected no chunks in plan");
    assert!(status.stored_proofs.is_empty(), "expected no stored proofs");
    assert!(
        handle.pruning_job_status().is_some(),
        "status cached on node"
    );
}

struct SinglePayload {
    height: u64,
    payload: BlockPayload,
}

impl PayloadProvider for SinglePayload {
    fn fetch_payload(&self, request: &ReconstructionRequest) -> ChainResult<BlockPayload> {
        if request.height == self.height {
            Ok(self.payload.clone())
        } else {
            Err(ChainError::Config(format!(
                "unexpected payload request for height {}",
                request.height
            )))
        }
    }
}

#[test]
fn rebuild_succeeds_after_prune() {
    let (config, _temp) = prepare_config();
    let node = Node::new(config).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let genesis = handle
        .latest_block()
        .expect("latest block")
        .expect("genesis block");
    let payload = BlockPayload::from_block(&genesis);

    storage
        .prune_block_payload(genesis.header.height)
        .expect("prune payload");

    let status = handle.run_pruning_cycle(4).expect("cycle").expect("status");
    assert!(status.missing_heights.contains(&genesis.header.height));
    let persisted = storage
        .load_pruning_proof(genesis.header.height)
        .expect("load pruning proof");
    assert!(persisted.is_some(), "pruning proof persisted");

    let provider = SinglePayload {
        height: genesis.header.height,
        payload,
    };
    let engine = ReconstructionEngine::new(storage);
    let rebuilt = engine
        .reconstruct_block(genesis.header.height, &provider)
        .expect("reconstruct block");
    assert_eq!(rebuilt.hash, genesis.hash);
    assert!(!rebuilt.pruned);
}

#[tokio::test]
async fn gossip_emits_pruning_status() {
    let (config, _temp) = prepare_config();
    let node = Node::new(config).expect("node");
    let handle = node.handle();
    let mut receiver = node.subscribe_witness_gossip(GossipTopic::Snapshots);

    handle.run_pruning_cycle(4).expect("cycle").expect("status");

    let bytes = timeout(Duration::from_secs(1), receiver.recv())
        .await
        .expect("gossip wait")
        .expect("gossip payload");
    let status: PruningJobStatus = serde_json::from_slice(&bytes).expect("decode status");
    assert!(status.plan.tip.height >= status.plan.snapshot.height);
    assert!(status.last_updated > 0);
}
