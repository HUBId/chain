use std::time::Duration;

use rpp_chain::config::NodeConfig;
use rpp_chain::crypto::load_keypair;
use rpp_chain::node::Node;
use rpp_chain::orchestration::{PipelineOrchestrator, PipelineStage};
use rpp_chain::sync::ReconstructionEngine;
use rpp_chain::wallet::{Wallet, WalletWorkflows};

/// Full integration test for the orchestrated pipeline. The current blueprint
/// stack still requires additional genesis plumbing, so the test is marked as
/// ignored and can be exercised manually once the network stack is completed.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orchestrated_pipeline_finalises_transaction() {
    let _ = tracing_subscriber::fmt::try_init();
    let temp = tempfile::tempdir().expect("temp dir");
    let node_data = temp.path().join("node");
    let key_dir = temp.path().join("keys");
    std::fs::create_dir_all(&node_data).expect("node dir");
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

    let node = Node::new(node_config.clone()).expect("node");
    let handle = node.handle();
    let node_keypair = load_keypair(&node_config.key_path).expect("load node key");

    let (orchestrator, shutdown_rx) = PipelineOrchestrator::new(handle.clone(), None);
    orchestrator.spawn(shutdown_rx);
    let node_task = tokio::spawn(async move {
        let _ = node.start().await;
    });

    let wallet = Wallet::new(handle.storage(), node_keypair);
    let workflows = WalletWorkflows::new(&wallet);
    let amount = 5_000u128;
    let fee = 100u64;
    let tx_workflow = workflows
        .transaction_bundle(handle.address().to_string(), amount, fee, None)
        .expect("transaction workflow");

    let hash = orchestrator
        .submit_transaction(tx_workflow.clone())
        .await
        .expect("submit pipeline");

    orchestrator
        .wait_for_stage(
            &hash,
            PipelineStage::RewardsDistributed,
            Duration::from_secs(10),
        )
        .await
        .expect("pipeline completed");

    let account = handle
        .get_account(wallet.address())
        .expect("fetch account")
        .expect("account exists");
    assert_eq!(account.nonce, tx_workflow.nonce);

    let dashboard = orchestrator.subscribe_dashboard();
    let snapshot = dashboard.borrow().clone();
    assert!(snapshot.is_stage_complete(&hash, PipelineStage::BftFinalised));

    let engine = ReconstructionEngine::new(handle.storage());
    let sync_plan = engine.state_sync_plan(1).expect("state sync plan");
    assert!(!sync_plan.light_client_updates.is_empty());

    orchestrator.shutdown();
    node_task.abort();
    let _ = node_task.await;
}
