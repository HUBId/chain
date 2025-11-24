#![cfg(all(feature = "wallet-integration", feature = "wallet-ui"))]

use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use tokio::time::sleep;

use rpp_chain::orchestration::PipelineStage;
use rpp_chain::wallet::WalletWorkflows;

#[path = "../support/mod.rs"]
mod support;

use support::cluster::TestCluster;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
const STAGE_TIMEOUT: Duration = Duration::from_secs(60);
const QUIET_PERIOD: Duration = Duration::from_millis(200);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn graceful_restart_retains_epoch_and_timetoke_state() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping uptime HA test: {err:?}");
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

        let primary = &cluster.nodes()[0];
        let baseline_status = primary
            .node_handle
            .consensus_status()
            .context("fetch baseline consensus status")?;
        let baseline_account = primary
            .node_handle
            .get_account(primary.node_handle.address())
            .context("fetch baseline account")?
            .ok_or_else(|| anyhow!("missing baseline account"))?;
        let baseline_timetoke = baseline_account.reputation.timetokes.hours_online;
        let baseline_nonce = baseline_account.nonce;
        let recipient = cluster.nodes()[1].wallet.address().to_string();
        let workflows = WalletWorkflows::new(primary.wallet.as_ref());
        let workflow = workflows
            .transaction_bundle(recipient, 3_000u128, 90u64, None)
            .context("build uptime HA transaction")?;
        let tx_hash = workflow.tx_hash.clone();
        primary
            .orchestrator
            .submit_transaction(workflow)
            .await
            .context("submit uptime HA transaction")?;

        for stage in stage_sequence {
            primary
                .orchestrator
                .wait_for_stage(&tx_hash, stage, STAGE_TIMEOUT)
                .await
                .with_context(|| format!("wait for stage {stage:?}"))?;
        }

        let progressed_status = primary
            .node_handle
            .consensus_status()
            .context("consensus status after transaction")?;
        ensure!(
            progressed_status.height >= baseline_status.height,
            "height regressed after transaction"
        );

        let settled_balance = primary
            .wallet
            .balance()
            .context("fetch settled balance")?
            .total();

        {
            let nodes = cluster.nodes_mut();
            nodes[0]
                .restart()
                .await
                .context("restart validator after transaction")?;
        }

        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("remesh after restart")?;

        let restarted = &cluster.nodes()[0];
        let restarted_status = restarted
            .node_handle
            .consensus_status()
            .context("consensus status after restart")?;
        ensure!(
            restarted_status.epoch >= progressed_status.epoch,
            "epoch regressed across restart"
        );
        ensure!(
            restarted_status.height >= progressed_status.height,
            "height regressed across restart"
        );

        let restarted_account = restarted
            .node_handle
            .get_account(restarted.node_handle.address())
            .context("fetch account after restart")?
            .ok_or_else(|| anyhow!("missing account after restart"))?;
        ensure!(
            restarted_account.reputation.timetokes.hours_online >= baseline_timetoke,
            "timetoke hours decreased after restart"
        );
        ensure!(
            restarted_account.nonce >= baseline_nonce,
            "account nonce decreased after restart"
        );

        let restarted_balance = restarted
            .wallet
            .balance()
            .context("fetch balance after restart")?
            .total();
        ensure!(
            restarted_balance == settled_balance,
            "wallet balance diverged after restart (expected {settled_balance}, found {restarted_balance})"
        );

        Ok(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crash_restart_recovers_mempool_and_switches_backends() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start_with(3, |config, _| {
        config.rollout.feature_gates.recursive_proofs = false;
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping uptime HA crash test: {err:?}");
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

        let primary = &cluster.nodes()[0];
        let recipient = cluster.nodes()[2].wallet.address().to_string();
        let workflows = WalletWorkflows::new(primary.wallet.as_ref());
        let first = workflows
            .transaction_bundle(recipient.clone(), 2_000u128, 75u64, None)
            .context("build first crash transaction")?;
        let second = workflows
            .transaction_bundle(recipient, 2_500u128, 80u64, None)
            .context("build second crash transaction")?;
        let pending_hashes = vec![first.tx_hash.clone(), second.tx_hash.clone()];

        primary
            .orchestrator
            .submit_transaction(first)
            .await
            .context("submit first crash transaction")?;
        primary
            .orchestrator
            .submit_transaction(second)
            .await
            .context("submit second crash transaction")?;

        // Give the pipeline a moment to queue submissions before crashing the process.
        sleep(QUIET_PERIOD).await;

        let baseline_status = primary
            .node_handle
            .node_status()
            .context("fetch baseline node status")?;
        ensure!(
            baseline_status.pending_transactions >= 2,
            "expected pending transactions before crash"
        );

        {
            let nodes = cluster.nodes_mut();
            nodes[0].config.rollout.feature_gates.recursive_proofs = true;
            nodes[0]
                .crash_and_restart()
                .await
                .context("crash-restart validator")?;
        }

        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("remesh after crash restart")?;

        let restarted = &cluster.nodes()[0];
        let restarted_status = restarted
            .node_handle
            .node_status()
            .context("node status after crash restart")?;
        ensure!(
            !restarted_status.backend_health.is_empty(),
            "backend health should report at least one active prover"
        );

        for hash in pending_hashes.iter() {
            for stage in stage_sequence {
                restarted
                    .orchestrator
                    .wait_for_stage(hash, stage, STAGE_TIMEOUT)
                    .await
                    .with_context(|| format!("wait for {hash} stage {stage:?}"))?;
            }
        }

        let settled_account = restarted
            .node_handle
            .get_account(restarted.node_handle.address())
            .context("fetch account after crash restart")?
            .ok_or_else(|| anyhow!("missing account after crash restart"))?;
        ensure!(
            settled_account.nonce >= 2,
            "account nonce did not advance after crash recovery"
        );

        let final_status = restarted
            .node_handle
            .node_status()
            .context("final node status after crash restart")?;
        ensure!(
            final_status.pending_transactions == 0,
            "mempool did not drain after crash recovery"
        );

        Ok(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}
