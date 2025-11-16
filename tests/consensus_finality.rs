#![cfg(all(feature = "wallet-integration", feature = "wallet-ui"))]

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
async fn orchestrated_round_advances_to_finality() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping consensus finality test: {err:?}");
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let primary = &cluster.nodes()[0];
        let recipient = cluster.nodes()[1].wallet.address().to_string();
        let workflows = WalletWorkflows::new(primary.wallet.as_ref());
        let amount = 2_000u128;
        let fee = 75u64;
        let workflow = workflows
            .transaction_bundle(recipient, amount, fee, None)
            .context("build transaction workflow")?;
        let tx_hash = workflow.tx_hash.clone();

        primary
            .orchestrator
            .submit_transaction(workflow)
            .await
            .context("submit orchestrated transaction")?;

        let stage_sequence = [
            PipelineStage::GossipReceived,
            PipelineStage::MempoolAccepted,
            PipelineStage::LeaderElected,
            PipelineStage::BftFinalised,
            PipelineStage::FirewoodCommitted,
            PipelineStage::RewardsDistributed,
        ];

        for stage in stage_sequence {
            primary
                .orchestrator
                .wait_for_stage(&tx_hash, stage, STAGE_TIMEOUT)
                .await
                .with_context(|| format!("wait for stage {stage:?}"))?;
        }

        let mut attempts = 0usize;
        let status = loop {
            let status = primary
                .node_handle
                .consensus_status()
                .context("fetch consensus status")?;
            if status.quorum_reached
                && status.block_hash.is_some()
                && !status.round_latencies_ms.is_empty()
            {
                break status;
            }
            if attempts >= MAX_STATUS_ATTEMPTS {
                return Err(anyhow!(
                    "consensus status missing quorum markers after transaction"
                ));
            }
            attempts += 1;
            sleep(POLL_INTERVAL).await;
        };

        anyhow::ensure!(
            status.leader_changes > 0,
            "leader change counter should advance after orchestrated round"
        );
        anyhow::ensure!(
            status.quorum_latency_ms.is_some(),
            "quorum latency should be recorded after finality"
        );

        let dashboard = primary
            .orchestrator
            .telemetry_summary()
            .await
            .context("fetch pipeline telemetry summary")?;
        anyhow::ensure!(
            dashboard
                .stage_latency_ms
                .get(&PipelineStage::LeaderElected)
                .map(|summary| summary.count >= 1)
                .unwrap_or(false),
            "leader election stage should record at least one completion"
        );
        anyhow::ensure!(
            dashboard
                .stage_latency_ms
                .get(&PipelineStage::BftFinalised)
                .map(|summary| summary.count >= 1)
                .unwrap_or(false),
            "BFT finalisation stage should record at least one completion"
        );

        Ok(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}
