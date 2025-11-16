#![cfg(all(feature = "wallet-integration", feature = "wallet-ui"))]

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use tokio::time::sleep;

use rpp_chain::orchestration::PipelineStage;
use rpp_chain::wallet::WalletWorkflows;
use rpp_chain::storage::ConsensusRecoveryState;

mod support;

use support::cluster::TestCluster;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
const STAGE_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MAX_STATUS_ATTEMPTS: usize = 120;
const LOCK_TIMEOUT: Duration = Duration::from_secs(30);

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consensus_lock_survives_crash() -> Result<()> {
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

        let (locked_hash, target_height, peer_before_failed, peer_before_slash) = {
            let primary = &cluster.nodes()[0];
            let secondary = &cluster.nodes()[1];
            let initial_tip = primary
                .node_handle
                .storage()
                .tip()
                .context("initial tip metadata")?
                .context("missing initial tip metadata")?;
            let target_height = initial_tip.height.saturating_add(1);

            let recipient = cluster.nodes()[2].wallet.address().to_string();
            let workflows = WalletWorkflows::new(primary.wallet.as_ref());
            let workflow = workflows
                .transaction_bundle(recipient, 2_500u128, 75u64, None)
                .context("build crash test transaction")?;
            let tx_hash = workflow.tx_hash.clone();
            primary
                .orchestrator
                .submit_transaction(workflow)
                .await
                .context("submit crash test transaction")?;
            primary
                .orchestrator
                .wait_for_stage(&tx_hash, PipelineStage::LeaderElected, STAGE_TIMEOUT)
                .await
                .context("wait for leader election")?;

            let lock_state = wait_for_locked_proposal(primary, LOCK_TIMEOUT)
                .await
                .context("wait for consensus lock")?;
            let locked_hash = lock_state
                .locked_proposal
                .clone()
                .context("expected locked proposal hash")?;
            let peer_status = secondary
                .node_handle
                .consensus_status()
                .context("peer consensus status before crash")?;
            (locked_hash, target_height, peer_status.failed_votes, peer_status.slashing_events)
        };

        {
            let nodes = cluster.nodes_mut();
            nodes[0]
                .crash_and_restart()
                .await
                .context("crash and restart primary validator")?;
        }

        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("remesh after crash")?;

        {
            let primary = &cluster.nodes()[0];
            let restored_state = primary
                .node_handle
                .storage()
                .read_consensus_state()
                .context("read restored consensus state")?
                .unwrap_or_default();
            if let Some(restored) = restored_state.locked_proposal.as_ref() {
                anyhow::ensure!(
                    restored == &locked_hash,
                    "restored lock {restored} did not match expected {locked_hash}"
                );
            } else if let Some(certificate) = restored_state.last_certificate.as_ref() {
                anyhow::ensure!(
                    certificate.block_hash.0 == locked_hash,
                    "restarted node committed different proposal {}",
                    certificate.block_hash.0
                );
            } else {
                anyhow::bail!("restarted node lost consensus recovery state");
            }
        }

        let primary = &cluster.nodes()[0];
        wait_for_tip_height(primary, target_height, STAGE_TIMEOUT)
            .await
            .context("wait for target height")?;

        let committed = primary
            .node_handle
            .storage()
            .read_block(target_height)
            .context("load committed block")?
            .context("committed block missing")?;
        anyhow::ensure!(
            committed.hash == locked_hash,
            "committed block hash {} did not match locked proposal {}",
            committed.hash,
            locked_hash
        );

        let final_state = primary
            .node_handle
            .storage()
            .read_consensus_state()
            .context("read final consensus state")?
            .unwrap_or_default();
        anyhow::ensure!(
            final_state.locked_proposal.is_none(),
            "consensus lock should be cleared after commit"
        );
        let certificate = final_state
            .last_certificate
            .as_ref()
            .context("missing last certificate after commit")?;
        anyhow::ensure!(
            certificate.height == target_height,
            "last certificate height {} did not match target {target_height}",
            certificate.height
        );
        anyhow::ensure!(
            certificate.block_hash.0 == locked_hash,
            "last certificate hash {} did not match locked proposal {}",
            certificate.block_hash.0,
            locked_hash
        );

        let peer_after = cluster.nodes()[1]
            .node_handle
            .consensus_status()
            .context("peer consensus status after crash")?;
        anyhow::ensure!(
            peer_after.failed_votes == peer_before_failed,
            "peer observed failed votes after crash"
        );
        anyhow::ensure!(
            peer_after.slashing_events == peer_before_slash,
            "peer observed slashing events after crash"
        );

        Ok(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
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

async fn wait_for_locked_proposal(
    node: &support::cluster::TestClusterNode,
    timeout: Duration,
) -> Result<ConsensusRecoveryState> {
    let deadline = Instant::now() + timeout;
    loop {
        let state = node
            .node_handle
            .storage()
            .read_consensus_state()
            .context("read consensus recovery state")?
            .unwrap_or_default();
        if state.locked_proposal.is_some() {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            return Err(anyhow!("timed out waiting for locked proposal"));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_tip_height(
    node: &support::cluster::TestClusterNode,
    target_height: u64,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(metadata) = node
            .node_handle
            .storage()
            .tip()
            .context("read tip metadata")?
        {
            if metadata.height >= target_height {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "timed out waiting for tip height {}",
                target_height
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}
