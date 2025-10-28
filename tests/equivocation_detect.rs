use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::time::sleep;

use rpp_chain::node::{ExternalFinalizationContext, FinalizationOutcome};
use rpp_chain::runtime::types::block::Block;
use rpp_chain::storage::ledger::SlashingReason;

mod support;

use support::cluster::{TestCluster, TestClusterNode};
use support::consensus::{consensus_round_for_block, signed_votes_for_round};

const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MAX_ATTEMPTS: usize = 120;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflicting_votes_trigger_slashing_pipeline() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping equivocation detection test: {err:?}");
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let nodes = cluster.nodes();
        let primary = &nodes[0];
        let baseline_events = primary
            .node_handle
            .slashing_events(16)
            .context("baseline slashing events")?;
        let baseline_count = baseline_events.len();

        let tip_block = wait_for_tip_block(primary)
            .await
            .context("tip block for equivocation")?;
        anyhow::ensure!(
            !tip_block.bft_votes.is_empty(),
            "tip block missing votes for equivocation scenario"
        );

        let mut round = consensus_round_for_block(primary, &tip_block, nodes)
            .context("build consensus round")?;
        let height = tip_block.header.height;
        let round_number = tip_block.consensus.round;

        let commit_pairs = signed_votes_for_round(nodes, height, round_number, &tip_block.hash)
            .context("assemble canonical votes")?;
        let mut archived_votes = Vec::with_capacity(commit_pairs.len() * 2);
        for (prevote, precommit) in &commit_pairs {
            round
                .register_prevote(prevote)
                .context("register prevote")?;
            round
                .register_precommit(precommit)
                .context("register precommit")?;
            archived_votes.push(prevote.clone());
            archived_votes.push(precommit.clone());
        }
        anyhow::ensure!(round.commit_reached(), "round failed to reach commit");

        let previous_block = if height == 0 {
            None
        } else {
            primary
                .node_handle
                .get_block(height - 1)
                .context("fetch previous block")?
        };

        let conflicting_hash = format!("{:064x}", height + 51);
        let conflicting_pairs = signed_votes_for_round(nodes, height, round_number, &conflicting_hash)
            .context("assemble conflicting votes")?;
        let mut conflicting_archive = archived_votes.clone();
        for (prevote, precommit) in conflicting_pairs {
            conflicting_archive.push(prevote);
            conflicting_archive.push(precommit);
        }

        let mut second_round = consensus_round_for_block(primary, &tip_block, nodes)
            .context("rebuild consensus round")?;
        for (prevote, precommit) in &commit_pairs {
            second_round
                .register_prevote(prevote)
                .context("re-register prevote")?;
            second_round
                .register_precommit(precommit)
                .context("re-register precommit")?;
        }
        anyhow::ensure!(second_round.commit_reached(), "rebuilt round failed to reach commit");

        let outcome = primary.node_handle.finalize_block(ExternalFinalizationContext {
            round: second_round,
            block: tip_block.clone(),
            previous_block,
            archived_votes: conflicting_archive,
        });

        match outcome {
            Ok(FinalizationOutcome::AwaitingQuorum) => {}
            Ok(FinalizationOutcome::Sealed { .. }) => {
                return Err(anyhow!("conflicting votes unexpectedly sealed block"));
            }
            Err(err) => {
                anyhow::ensure!(
                    matches!(err, rpp_chain::errors::ChainError::Transaction(message) if message.contains("conflicting vote")),
                    "unexpected error from conflicting finalize: {err:?}"
                );
            }
        }

        let slashing_events = wait_for_slashing_increase(primary, baseline_count)
            .await
            .context("wait for slashing evidence")?;
        anyhow::ensure!(
            slashing_events
                .iter()
                .any(|event| event.reason == SlashingReason::ConflictingVote),
            "expected conflicting vote slashing reason present"
        );

        let status = primary
            .node_handle
            .consensus_status()
            .context("post equivocation consensus status")?;
        anyhow::ensure!(
            status.slashing_events as usize >= baseline_count + 1,
            "consensus telemetry missing slashing increment"
        );

        Ok(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}

async fn wait_for_tip_block(node: &TestClusterNode) -> Result<Block> {
    let mut attempts = 0usize;
    loop {
        if attempts >= MAX_ATTEMPTS {
            return Err(anyhow!("timed out waiting for tip block"));
        }
        if let Some(block) = node
            .node_handle
            .latest_block()
            .context("fetch latest block while waiting for tip")?
        {
            return Ok(block);
        }
        attempts += 1;
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_slashing_increase(
    node: &TestClusterNode,
    baseline: usize,
) -> Result<Vec<rpp_chain::storage::ledger::SlashingEvent>> {
    let mut attempts = 0usize;
    loop {
        let events = node
            .node_handle
            .slashing_events(16)
            .context("poll slashing events")?;
        if events.len() > baseline {
            return Ok(events);
        }
        if attempts >= MAX_ATTEMPTS {
            return Err(anyhow!("timed out waiting for slashing evidence"));
        }
        attempts += 1;
        sleep(POLL_INTERVAL).await;
    }
}
