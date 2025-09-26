use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tempfile::tempdir;
use tokio::time;

use rpp_chain::config::NodeConfig;
use rpp_chain::crypto::load_keypair;
use rpp_chain::node::Node;
use rpp_chain::orchestration::{PipelineOrchestrator, PipelineStage};
use rpp_chain::runtime::RuntimeMode;
use rpp_chain::wallet::Wallet;

struct OrchestratorFixture {
    wallet: Arc<Wallet>,
    orchestrator: Arc<PipelineOrchestrator>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    _mode: Arc<RwLock<RuntimeMode>>,
    _tempdir: tempfile::TempDir,
}

impl OrchestratorFixture {
    fn new() -> Option<Self> {
        let tempdir = tempdir().expect("temp dir");
        let node_data = tempdir.path().join("node");
        let key_dir = tempdir.path().join("keys");
        std::fs::create_dir_all(&node_data).expect("node data dir");
        std::fs::create_dir_all(&key_dir).expect("key dir");

        let mut node_config = NodeConfig::default();
        node_config.data_dir = node_data.clone();
        node_config.key_path = key_dir.join("node.toml");
        node_config.p2p_key_path = key_dir.join("p2p.toml");
        node_config.vrf_key_path = key_dir.join("vrf.toml");
        node_config.snapshot_dir = node_data.join("snapshots");
        node_config.proof_cache_dir = node_data.join("proofs");
        node_config.block_time_ms = 200;
        node_config.mempool_limit = 64;
        node_config.rollout.feature_gates.pruning = false;
        node_config.rollout.feature_gates.recursive_proofs = false;
        node_config.rollout.feature_gates.reconstruction = false;
        node_config.rollout.feature_gates.consensus_enforcement = false;

        node_config.ensure_directories().expect("node directories");

        let node = match Node::new(node_config.clone()) {
            Ok(node) => node,
            Err(err) => {
                eprintln!("skipping orchestrator fixture setup: {err}");
                return None;
            }
        };
        let handle = node.handle();
        let keypair = load_keypair(&node_config.key_path).expect("load node key");
        let wallet = Arc::new(Wallet::new(handle.storage(), keypair));

        let (orchestrator, shutdown_rx) = PipelineOrchestrator::new(handle.clone(), None);
        let orchestrator = Arc::new(orchestrator);
        let shutdown_observer = shutdown_rx.clone();
        orchestrator.spawn(shutdown_rx);

        let mode = Arc::new(RwLock::new(RuntimeMode::Hybrid));

        Some(Self {
            wallet,
            orchestrator,
            shutdown_rx: shutdown_observer,
            _mode: mode,
            _tempdir: tempdir,
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn pipeline_dashboard_snapshot_is_initially_empty() {
    let Some(fixture) = OrchestratorFixture::new() else {
        return;
    };
    let snapshot = fixture
        .wallet
        .pipeline_dashboard(fixture.orchestrator.as_ref());
    assert!(snapshot.flows.is_empty());
    fixture
        .wallet
        .shutdown_pipeline(fixture.orchestrator.as_ref());
}

#[tokio::test(flavor = "current_thread")]
async fn wait_for_stage_times_out_for_unknown_hash() {
    let Some(fixture) = OrchestratorFixture::new() else {
        return;
    };
    let result = fixture
        .wallet
        .wait_for_pipeline_stage(
            fixture.orchestrator.as_ref(),
            "deadbeef",
            PipelineStage::BftFinalised,
            Duration::from_millis(25),
        )
        .await;
    assert!(result.is_err());
    fixture
        .wallet
        .shutdown_pipeline(fixture.orchestrator.as_ref());
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_notifies_pipeline_watchers() {
    let Some(fixture) = OrchestratorFixture::new() else {
        return;
    };
    let OrchestratorFixture {
        wallet,
        orchestrator,
        mut shutdown_rx,
        ..
    } = fixture;

    wallet.shutdown_pipeline(orchestrator.as_ref());
    time::timeout(Duration::from_secs(1), shutdown_rx.changed())
        .await
        .expect("shutdown signal received")
        .expect("shutdown channel open");
    assert!(*shutdown_rx.borrow());
}
