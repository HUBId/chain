use std::time::Duration;

use rpp_chain::orchestration::PipelineStage;
use rpp_chain::wallet::WalletWorkflows;

mod support;

use support::cluster::TestCluster;

const STAGE_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn orchestrated_pipeline_finalises_transaction() {
    let _ = tracing_subscriber::fmt::try_init();

    let cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping orchestrated pipeline test: {err:?}");
            return;
        }
    };
    cluster
        .wait_for_full_mesh(STAGE_TIMEOUT)
        .await
        .expect("cluster mesh");

    let consensus_baseline = cluster
        .consensus_snapshots()
        .expect("capture consensus baseline");

    let (primary_handle, orchestrator, wallet, recipient) = {
        let nodes = cluster.nodes();
        let primary = &nodes[0];
        let recipient = nodes[1].wallet.address().to_string();
        (
            primary.node_handle.clone(),
            primary.orchestrator.clone(),
            primary.wallet.clone(),
            recipient,
        )
    };

    let workflows = WalletWorkflows::new(wallet.as_ref());
    let amount = 5_000u128;
    let fee = 100u64;
    let tx_workflow = workflows
        .transaction_bundle(recipient, amount, fee, None)
        .expect("transaction workflow");

    let hash = orchestrator
        .submit_transaction(tx_workflow.clone())
        .await
        .expect("submit pipeline");

    for stage in [
        PipelineStage::GossipReceived,
        PipelineStage::MempoolAccepted,
        PipelineStage::LeaderElected,
        PipelineStage::BftFinalised,
        PipelineStage::RewardsDistributed,
    ] {
        orchestrator
            .wait_for_stage(&hash, stage, STAGE_TIMEOUT)
            .await
            .unwrap_or_else(|err| panic!("stage {stage:?} not reached: {err}"));
    }

    cluster
        .wait_for_quorum_progress(&consensus_baseline, STAGE_TIMEOUT)
        .await
        .expect("quorum progress");

    let account = primary_handle
        .get_account(wallet.address())
        .expect("fetch account")
        .expect("account exists");
    assert_eq!(account.nonce, tx_workflow.nonce);

    let dashboard = orchestrator.subscribe_dashboard();
    let snapshot = dashboard.borrow().clone();
    for stage in [
        PipelineStage::GossipReceived,
        PipelineStage::MempoolAccepted,
        PipelineStage::LeaderElected,
        PipelineStage::BftFinalised,
        PipelineStage::RewardsDistributed,
    ] {
        assert!(
            snapshot.is_stage_complete(&hash, stage),
            "dashboard missing stage {stage:?}"
        );
    }

    orchestrator.shutdown();
    cluster.shutdown().await.expect("shutdown cluster");
}
