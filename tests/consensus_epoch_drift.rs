#![cfg(all(feature = "wallet-integration", feature = "wallet-ui"))]

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::time::{sleep, Instant};

use rpp_chain::orchestration::PipelineStage;
use rpp_chain::wallet::WalletWorkflows;

mod support;

use support::cluster::TestCluster;

const EPOCH_LENGTH: u64 = 6;
const QUIESCENT_TIMEOUT: Duration = Duration::from_secs(60);
const MESH_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(200);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn epoch_transitions_tolerate_clock_and_peer_drift() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start_with(4, |config, index| {
        config.epoch_length = EPOCH_LENGTH;
        config.block_time_ms = 150 + (index as u64 * 35);
        config.malachite.validator.round_timeout_ms = 1_800 + (index as u64 * 250);
        config.malachite.validator.max_round_extensions = 2;
        config.network.p2p.gossip_rate_limit_per_sec = if index == 0 { 48 } else { 96 };
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping epoch drift test: {err:?}");
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(MESH_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let baseline = cluster.consensus_snapshots()?;

        let primary = &cluster.nodes()[0];
        let recipient = cluster.nodes()[1].wallet.address().to_string();
        let workflows = WalletWorkflows::new(primary.wallet.as_ref());
        let mut latest_tx = None;
        for i in 0..3u128 {
            let workflow = workflows
                .transaction_bundle(recipient.clone(), 1_000 + i * 17, 50, None)
                .context("build transaction workflow")?;
            latest_tx = Some(workflow.tx_hash.clone());
            primary
                .orchestrator
                .submit_transaction(workflow)
                .await
                .context("submit orchestrated transaction")?;
        }

        let mut statuses = Vec::new();
        let mut stage_asserted = false;
        let deadline = Instant::now() + QUIESCENT_TIMEOUT;
        loop {
            statuses.clear();
            for node in cluster.nodes() {
                statuses.push(
                    node
                        .node_handle
                        .consensus_status()
                        .with_context(|| format!("poll consensus status for node {}", node.index))?,
                );
            }

            let min_epoch = statuses.iter().map(|status| status.epoch).min().unwrap_or(0);
            let min_height = statuses.iter().map(|status| status.height).min().unwrap_or(0);
            let all_quorum = statuses.iter().all(|status| status.quorum_reached);

            if all_quorum && min_epoch >= 2 && min_height >= EPOCH_LENGTH * 2 {
                if !stage_asserted {
                    // Ensure the pipeline completed the critical leader/finality path at least once.
                    let tx_hash = latest_tx.as_ref().expect("latest tx hash captured");
                    primary
                        .orchestrator
                        .wait_for_stage(
                            tx_hash,
                            PipelineStage::LeaderElected,
                            Duration::from_secs(30),
                        )
                        .await
                        .context("leader election stage latency")?;
                    primary
                        .orchestrator
                        .wait_for_stage(
                            tx_hash,
                            PipelineStage::BftFinalised,
                            Duration::from_secs(30),
                        )
                        .await
                        .context("BFT finality stage latency")?;
                    stage_asserted = true;
                }
                break;
            }

            if Instant::now() >= deadline {
                return Err(anyhow!(
                    "cluster failed to reach quorum across epochs; min_epoch={min_epoch} min_height={min_height}"
                ));
            }
            sleep(POLL_INTERVAL).await;
        }

        // Verify fork-choice convergence and leader selection stability under skewed timing.
        let heights: Vec<u64> = statuses.iter().map(|status| status.height).collect();
        let hashes: HashSet<_> = statuses
            .iter()
            .filter_map(|status| status.block_hash.clone())
            .collect();
        let proposers: HashSet<_> = statuses
            .iter()
            .filter_map(|status| status.proposer.clone())
            .collect();

        let max_height = *heights.iter().max().unwrap_or(&0);
        let min_height = *heights.iter().min().unwrap_or(&0);
        anyhow::ensure!(
            max_height.saturating_sub(min_height) <= 1,
            "height drift exceeded tolerance: max={max_height} min={min_height}"
        );
        anyhow::ensure!(
            hashes.len() <= 1,
            "fork-choice divergence detected across nodes: {:?}",
            hashes
        );
        anyhow::ensure!(
            proposers.len() <= 1,
            "leader selection diverged across nodes: {:?}",
            proposers
        );

        let mut latencies: Vec<u64> = statuses
            .iter()
            .flat_map(|status| status.round_latencies_ms.iter().copied())
            .collect();
        latencies.sort_unstable();
        let drift_budget = latencies
            .last()
            .copied()
            .unwrap_or_default()
            .saturating_sub(latencies.first().copied().unwrap_or_default());
        anyhow::ensure!(
            drift_budget <= 1_200,
            "round latency spread {drift_budget}ms exceeded drift budget"
        );

        anyhow::ensure!(
            statuses.iter().any(|status| status.leader_changes > 0),
            "leader change counter should advance under epoch churn"
        );

        let new_snapshots = cluster.consensus_snapshots()?;
        cluster
            .wait_for_quorum_progress(&baseline, Duration::from_secs(10))
            .await
            .context("quorum progress")?;
        anyhow::ensure!(
            new_snapshots
                .iter()
                .zip(baseline.iter())
                .all(|(after, before)| after.height >= before.height),
            "consensus heights regressed after drift exercise"
        );

        Ok(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}
