use std::fs;
use std::time::Duration;

use rpp_chain::config::{NodeConfig, DEFAULT_PRUNING_RETENTION_DEPTH};
use rpp_chain::errors::{ChainError, ChainResult};
use rpp_chain::node::{Node, PruningJobStatus};
use rpp_chain::runtime::sync::{PayloadProvider, ReconstructionEngine, ReconstructionRequest};
use rpp_chain::runtime::types::BlockPayload;
use rpp_chain::runtime::RuntimeMetrics;
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

#[test]
fn pruning_plan_without_pending_blocks() {
    let (config, _temp) = prepare_config();
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();

    let summary = handle
        .run_pruning_cycle(4, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("cycle");
    let status = summary.status.expect("status");
    assert!(!summary.cancelled, "unexpected cancellation");

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
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
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

    let summary = handle
        .run_pruning_cycle(4, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("cycle");
    let status = summary.status.expect("status");
    assert!(!summary.cancelled, "unexpected cancellation");
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
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let mut receiver = node.subscribe_witness_gossip(GossipTopic::Snapshots);

    let summary = handle
        .run_pruning_cycle(4, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("cycle");
    assert!(!summary.cancelled, "unexpected cancellation");

    let bytes = timeout(Duration::from_secs(1), receiver.recv())
        .await
        .expect("gossip wait")
        .expect("gossip payload");
    let status: PruningJobStatus = serde_json::from_slice(&bytes).expect("decode status");
    assert!(status.plan.tip.height >= status.plan.snapshot.height);
    assert!(status.last_updated > 0);
}

#[test]
fn pruning_cancellation_preserves_progress() {
    let (config, _temp) = prepare_config();
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let handle = node.handle();
    let storage = handle.storage();

    let chain = build_chain(&handle, 3);
    install_pruned_chain(&storage, &chain).expect("install pruned chain");

    handle.request_pruning_cancellation();
    let cancelled = handle
        .run_pruning_cycle(4, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("cancelled cycle");
    assert!(cancelled.cancelled, "cycle should report cancellation");
    let cancelled_status = cancelled.status.expect("cancelled status");
    assert!(
        cancelled_status.persisted_path.is_some(),
        "cancelled cycle should still persist a plan",
    );

    let resumed = handle
        .run_pruning_cycle(4, DEFAULT_PRUNING_RETENTION_DEPTH)
        .expect("resumed cycle");
    let resumed_status = resumed.status.expect("resumed status");
    assert!(!resumed.cancelled, "second cycle should complete");
    assert!(
        resumed_status.stored_proofs.len() >= cancelled_status.stored_proofs.len(),
        "resumed cycle should not regress stored proofs",
    );
}
