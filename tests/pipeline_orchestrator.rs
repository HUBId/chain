use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tempfile::tempdir;
use tokio::sync::broadcast;
use tokio::task::{self, LocalSet};
use tokio::time;

use rpp_chain::config::NodeConfig;
use rpp_chain::crypto::load_keypair;
use rpp_chain::errors::ChainError;
use rpp_chain::node::Node;
use rpp_chain::orchestration::{PipelineOrchestrator, PipelineStage};
use rpp_chain::runtime::node_runtime::node::NodeRuntimeConfig;
use rpp_chain::runtime::node_runtime::{NodeEvent, NodeInner as P2pNode};
use rpp_chain::runtime::RuntimeMode;
use rpp_chain::wallet::Wallet;
use rpp_chain::wallet::WalletWorkflows;
use rpp_p2p::GossipTopic;
use serde_json;

fn random_listen_addr() -> (String, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind random port");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    (format!("/ip4/127.0.0.1/tcp/{port}"), port)
}

fn sample_node_config(base: &Path) -> NodeConfig {
    let node_data = base.join("node");
    let key_dir = base.join("keys");
    fs::create_dir_all(&node_data).expect("node data dir");
    fs::create_dir_all(&key_dir).expect("key dir");

    let mut node_config = NodeConfig::default();
    node_config.data_dir = node_data.clone();
    node_config.key_path = key_dir.join("node.toml");
    node_config.p2p_key_path = key_dir.join("p2p.toml");
    node_config.vrf_key_path = key_dir.join("vrf.toml");
    node_config.snapshot_dir = node_data.join("snapshots");
    node_config.proof_cache_dir = node_data.join("proofs");
    node_config.p2p.peerstore_path = node_data.join("p2p/peerstore.json");
    node_config.p2p.gossip_path = Some(node_data.join("p2p/gossip.json"));
    node_config.block_time_ms = 200;
    node_config.mempool_limit = 64;
    node_config.rollout.feature_gates.pruning = false;
    node_config.rollout.feature_gates.recursive_proofs = false;
    node_config.rollout.feature_gates.reconstruction = false;
    node_config.rollout.feature_gates.consensus_enforcement = false;
    node_config.ensure_directories().expect("node directories");
    node_config
}

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
        let node_config = sample_node_config(tempdir.path());

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_dashboard_snapshot_is_initially_empty() {
    let Some(fixture) = tokio::task::spawn_blocking(OrchestratorFixture::new)
        .await
        .expect("spawn blocking")
    else {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_for_stage_times_out_for_unknown_hash() {
    let Some(fixture) = tokio::task::spawn_blocking(OrchestratorFixture::new)
        .await
        .expect("spawn blocking")
    else {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_notifies_pipeline_watchers() {
    let Some(fixture) = tokio::task::spawn_blocking(OrchestratorFixture::new)
        .await
        .expect("spawn blocking")
    else {
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

async fn wait_for_peer_connected(events: &mut broadcast::Receiver<NodeEvent>) {
    time::timeout(Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Ok(NodeEvent::PeerConnected { .. }) => break,
                Ok(_) => continue,
                Err(err) => panic!("event channel closed: {err}"),
            }
        }
    })
    .await
    .expect("peer connected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submit_transaction_returns_config_error_when_gossip_publish_fails() {
    let setup = tokio::task::spawn_blocking(|| -> Result<_, String> {
        let base_dir = tempdir().expect("temp dir");
        let node_config = sample_node_config(base_dir.path());
        let node = Node::new(node_config.clone()).map_err(|err| err.to_string())?;
        let handle = node.handle();
        let identity = node
            .network_identity_profile()
            .map_err(|err| err.to_string())?;
        let keypair = load_keypair(&node_config.key_path).expect("load node key");
        let wallet = Arc::new(Wallet::new(handle.storage(), keypair));
        Ok((base_dir, handle, wallet, identity, node_config))
    })
    .await
    .expect("spawn blocking");
    let (_base_dir, handle, wallet, identity, node_config) = match setup {
        Ok(values) => values,
        Err(err) => {
            eprintln!("skipping orchestrator p2p test setup: {err}");
            return;
        }
    };

    let mut runtime_config = NodeRuntimeConfig::from(&node_config);
    runtime_config.identity = Some(identity.into());
    let (listen_addr, _) = random_listen_addr();
    runtime_config.p2p.listen_addr = listen_addr;
    runtime_config.p2p.bootstrap_peers = Vec::new();
    runtime_config.p2p.gossip_enabled = false;

    let handle_clone = handle.clone();
    let wallet_clone = wallet.clone();
    let local = LocalSet::new();
    local
        .run_until(async move {
            let (p2p_runtime, p2p_handle) =
                P2pNode::new(runtime_config).expect("p2p runtime initialised");
            let p2p_task = task::spawn_local(async move {
                p2p_runtime.run().await.expect("run p2p runtime");
            });

            handle_clone.attach_p2p(p2p_handle.clone()).await;

            let (orchestrator, shutdown_rx) =
                PipelineOrchestrator::new(handle_clone.clone(), Some(p2p_handle.clone()));
            let orchestrator = Arc::new(orchestrator);
            orchestrator.spawn(shutdown_rx);

            let workflows = WalletWorkflows::new(&wallet_clone);
            let amount = 1_000u128;
            let fee = 10u64;
            let tx_workflow = workflows
                .transaction_bundle(handle_clone.address().to_string(), amount, fee, None)
                .expect("transaction workflow");
            let hash = tx_workflow.bundle.hash();

            match orchestrator.submit_transaction(tx_workflow.clone()).await {
                Err(ChainError::Config(message)) => {
                    assert!(
                        message.contains(&hash),
                        "config error should include transaction hash"
                    );
                }
                other => panic!("expected config error, got {other:?}"),
            }

            orchestrator.shutdown();
            p2p_handle.shutdown().await.expect("shutdown p2p");
            p2p_task.await.expect("p2p task completed");
        })
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn gossip_loop_records_stage_for_matching_payload() {
    let setup = tokio::task::spawn_blocking(|| -> Result<_, String> {
        let base_dir = tempdir().expect("temp dir");
        let node_config = sample_node_config(base_dir.path());
        let node = Node::new(node_config.clone()).map_err(|err| err.to_string())?;
        let handle = node.handle();
        let identity = node
            .network_identity_profile()
            .map_err(|err| err.to_string())?;
        let keypair = load_keypair(&node_config.key_path).expect("load node key");
        let wallet = Arc::new(Wallet::new(handle.storage(), keypair));
        Ok((base_dir, handle, wallet, identity, node_config))
    })
    .await
    .expect("spawn blocking");
    let (_base_dir, handle, wallet, identity, node_config) = match setup {
        Ok(values) => values,
        Err(err) => {
            eprintln!("skipping orchestrator gossip loop test: {err}");
            return;
        }
    };

    let mut receiver_config = NodeRuntimeConfig::from(&node_config);
    receiver_config.identity = Some(identity.into());
    let (receiver_listen, _) = random_listen_addr();
    receiver_config.p2p.listen_addr = receiver_listen.clone();
    receiver_config.p2p.bootstrap_peers = Vec::new();

    let publisher_dir = tempdir().expect("publisher dir");
    let publisher_node_config = sample_node_config(publisher_dir.path());
    let mut publisher_config = NodeRuntimeConfig::from(&publisher_node_config);
    let (publisher_listen, _) = random_listen_addr();
    publisher_config.p2p.listen_addr = publisher_listen;
    publisher_config.p2p.bootstrap_peers = vec![receiver_listen.clone()];

    let handle_clone = handle.clone();
    let wallet_clone = wallet.clone();
    let local = LocalSet::new();
    local
        .run_until(async move {
            let (receiver_runtime, receiver_handle) =
                P2pNode::new(receiver_config).expect("receiver runtime");
            let (publisher_runtime, publisher_handle) =
                P2pNode::new(publisher_config).expect("publisher runtime");

            let mut receiver_events = receiver_handle.subscribe();
            let receiver_task = task::spawn_local(async move {
                receiver_runtime.run().await.expect("run receiver");
            });
            let publisher_task = task::spawn_local(async move {
                publisher_runtime.run().await.expect("run publisher");
            });

            wait_for_peer_connected(&mut receiver_events).await;

            handle_clone.attach_p2p(receiver_handle.clone()).await;

            let (orchestrator, shutdown_rx) =
                PipelineOrchestrator::new(handle_clone.clone(), Some(receiver_handle.clone()));
            let orchestrator = Arc::new(orchestrator);
            orchestrator.spawn(shutdown_rx);

            let workflows = WalletWorkflows::new(&wallet_clone);
            let amount = 2_000u128;
            let fee = 25u64;
            let tx_workflow = workflows
                .transaction_bundle(handle_clone.address().to_string(), amount, fee, None)
                .expect("transaction workflow");
            let hash = orchestrator
                .submit_transaction(tx_workflow.clone())
                .await
                .expect("submit transaction");

            let payload = serde_json::to_vec(&tx_workflow.bundle).expect("serialize proof bundle");
            publisher_handle
                .publish_gossip(GossipTopic::Proofs, payload)
                .await
                .expect("publish gossip");

            orchestrator
                .wait_for_stage(&hash, PipelineStage::GossipReceived, Duration::from_secs(5))
                .await
                .expect("gossip stage recorded");

            orchestrator.shutdown();
            receiver_handle.shutdown().await.expect("shutdown receiver");
            publisher_handle
                .shutdown()
                .await
                .expect("shutdown publisher");
            receiver_task.await.expect("receiver task completed");
            publisher_task.await.expect("publisher task completed");
        })
        .await;
}
