use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::time::sleep;

use rpp_chain::orchestration::PipelineStage;
use rpp_chain::wallet::WalletWorkflows;

mod support;

use support::cluster::TestCluster;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
const STAGE_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MAX_STATUS_ATTEMPTS: usize = 120;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pipeline_recovers_after_validator_restart() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping restart recovery test: {err:?}");
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let stage_sequence = [
            PipelineStage::GossipReceived,
            PipelineStage::MempoolAccepted,
            PipelineStage::LeaderElected,
            PipelineStage::BftFinalised,
            PipelineStage::FirewoodCommitted,
            PipelineStage::RewardsDistributed,
        ];

        let initial_status = {
            let primary = &cluster.nodes()[0];
            let recipient = cluster.nodes()[1].wallet.address().to_string();
            let workflows = WalletWorkflows::new(primary.wallet.as_ref());
            let workflow = workflows
                .transaction_bundle(recipient, 3_000u128, 90u64, None)
                .context("build initial transaction")?;
            let tx_hash = workflow.tx_hash.clone();
            primary
                .orchestrator
                .submit_transaction(workflow)
                .await
                .context("submit initial transaction")?;
            for stage in stage_sequence {
                primary
                    .orchestrator
                    .wait_for_stage(&tx_hash, stage, STAGE_TIMEOUT)
                    .await
                    .with_context(|| format!("initial wait for stage {stage:?}"))?;
            }
            wait_for_consensus_progress(primary, None)
                .await
                .context("initial consensus status")?
        };

        {
            let nodes = cluster.nodes_mut();
            nodes[0]
                .restart()
                .await
                .context("restart primary validator")?;
        }

        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("remesh after restart")?;

        let primary = &cluster.nodes()[0];
        let recipient = cluster.nodes()[2].wallet.address().to_string();
        let workflows = WalletWorkflows::new(primary.wallet.as_ref());
        let workflow = workflows
            .transaction_bundle(recipient, 4_500u128, 110u64, None)
            .context("build recovery transaction")?;
        let tx_hash = workflow.tx_hash.clone();
        primary
            .orchestrator
            .submit_transaction(workflow)
            .await
            .context("submit recovery transaction")?;

        for stage in stage_sequence {
            primary
                .orchestrator
                .wait_for_stage(&tx_hash, stage, STAGE_TIMEOUT)
                .await
                .with_context(|| format!("recovery wait for stage {stage:?}"))?;
        }

        let recovered = wait_for_consensus_progress(primary, Some(initial_status.height))
            .await
            .context("consensus status after restart")?;
        anyhow::ensure!(
            recovered.height >= initial_status.height,
            "validator height regressed after restart"
        );
        anyhow::ensure!(
            recovered.round >= initial_status.round,
            "consensus round regressed after restart"
        );
        anyhow::ensure!(
            recovered.leader_changes >= initial_status.leader_changes,
            "leader change counter decreased after restart"
        );
        anyhow::ensure!(
            recovered.quorum_reached,
            "restarted validator failed to regain quorum"
        );

        Ok(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}

#[derive(Clone)]
struct ConsensusSnapshot {
    height: u64,
    round: u64,
    quorum_reached: bool,
    leader_changes: u64,
}

async fn wait_for_consensus_progress(
    node: &support::cluster::TestClusterNode,
    minimum_height: Option<u64>,
) -> Result<ConsensusSnapshot> {
    let mut attempts = 0usize;
    loop {
        let status = node
            .node_handle
            .consensus_status()
            .context("poll consensus status")?;
        if status.quorum_reached
            && status.block_hash.is_some()
            && status.quorum_latency_ms.is_some()
            && minimum_height.map(|min| status.height >= min).unwrap_or(true)
        {
            return Ok(ConsensusSnapshot {
                height: status.height,
                round: status.round,
                quorum_reached: status.quorum_reached,
                leader_changes: status.leader_changes,
            });
        }
        if attempts >= MAX_STATUS_ATTEMPTS {
            return Err(anyhow!("timed out waiting for consensus status update"));
        }
        attempts += 1;
        sleep(POLL_INTERVAL).await;
    }
}
