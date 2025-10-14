use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use tokio::time::sleep;

use rpp_chain::consensus::BftVoteKind;
use rpp_chain::errors::ChainError;
use rpp_chain::storage::ledger::SlashingReason;
use rpp_chain::types::block::Block;

mod support;

use support::cluster::TestCluster;
use support::consensus::signed_votes_for_round;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MAX_ATTEMPTS: usize = 50;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn evidence_pool_rejects_conflicting_votes_without_reorg() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start_with(4, |config, _| {
        config.rollout.feature_gates.consensus_enforcement = true;
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping reorg regression test: {err:?}");
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

        let tip_block = wait_for_tip_block(primary).await.context("tip block")?;
        let baseline_height = tip_block.header.height;
        let baseline_hash = tip_block.hash.clone();

        let baseline_slashes = primary
            .node_handle
            .slashing_events(32)
            .context("baseline slashing events")?;

        let next_height = baseline_height + 1;
        let round_number = tip_block.consensus.round.saturating_add(1);
        let canonical_hash = format!("{:064x}", next_height + 41);
        let fork_hash = format!("{:064x}", next_height + 42);

        let canonical_votes =
            signed_votes_for_round(&nodes, next_height, round_number, &canonical_hash)
                .context("canonical votes")?;
        let fork_votes = signed_votes_for_round(&nodes, next_height, round_number, &fork_hash)
            .context("fork votes")?;

        ensure_enough_validators(&canonical_votes)?;

        let prevote_index = 0usize;
        let precommit_index = 1usize;

        let prevote_voter = canonical_votes[prevote_index].0.vote.voter.clone();
        let precommit_voter = canonical_votes[precommit_index].1.vote.voter.clone();

        primary
            .node_handle
            .submit_vote(canonical_votes[prevote_index].0.clone())
            .context("canonical prevote submission")?;
        primary
            .node_handle
            .submit_vote(canonical_votes[precommit_index].1.clone())
            .context("canonical precommit submission")?;

        let conflicting_prevote = fork_votes[prevote_index].0.clone();
        assert_eq!(
            conflicting_prevote.vote.kind,
            BftVoteKind::PreVote,
            "unexpected vote kind for prevote test"
        );
        match primary.node_handle.submit_vote(conflicting_prevote) {
            Ok(hash) => {
                return Err(anyhow!(
                    "conflicting prevote unexpectedly accepted with hash {hash}"
                ));
            }
            Err(err) => match &err {
                ChainError::Transaction(message) => {
                    ensure!(
                        message.contains("conflicting vote detected for validator"),
                        "unexpected prevote rejection message: {message}",
                    );
                }
                other => return Err(anyhow!("unexpected prevote error: {other:?}")),
            },
        }

        let conflicting_precommit = fork_votes[precommit_index].1.clone();
        assert_eq!(
            conflicting_precommit.vote.kind,
            BftVoteKind::PreCommit,
            "unexpected vote kind for precommit test"
        );
        match primary.node_handle.submit_vote(conflicting_precommit) {
            Ok(hash) => {
                return Err(anyhow!(
                    "conflicting precommit unexpectedly accepted with hash {hash}"
                ));
            }
            Err(err) => match &err {
                ChainError::Transaction(message) => {
                    ensure!(
                        message.contains("conflicting vote detected for validator"),
                        "unexpected precommit rejection message: {message}",
                    );
                }
                other => return Err(anyhow!("unexpected precommit error: {other:?}")),
            },
        }

        let latest_block = primary
            .node_handle
            .latest_block()
            .context("latest block after conflicting votes")?
            .context("missing tip after conflicting votes")?;
        ensure!(latest_block.header.height == baseline_height);
        ensure!(latest_block.hash == baseline_hash);

        let updated_slashes = primary
            .node_handle
            .slashing_events(32)
            .context("slashing events after conflicts")?;
        ensure!(
            updated_slashes
                .iter()
                .any(|event| event.address == prevote_voter
                    && event.reason == SlashingReason::ConsensusFault),
            "missing slashing event for conflicting prevote"
        );
        ensure!(
            updated_slashes
                .iter()
                .any(|event| event.address == precommit_voter
                    && event.reason == SlashingReason::ConsensusFault),
            "missing slashing event for conflicting precommit"
        );
        ensure!(updated_slashes.len() >= baseline_slashes.len() + 2);

        Ok(())
    }
    .await;

    if let Err(err) = cluster.shutdown().await {
        eprintln!("cluster shutdown failed: {err:?}");
    }

    result
}

async fn wait_for_tip_block(node: &support::cluster::TestClusterNode) -> Result<Block> {
    let mut attempts = 0;
    loop {
        if attempts >= MAX_ATTEMPTS {
            return Err(anyhow!("timed out waiting for node to produce a tip block"));
        }
        if let Some(block) = node
            .node_handle
            .latest_block()
            .context("fetch latest block while waiting for tip")?
        {
            return Ok(block);
        }
        sleep(POLL_INTERVAL).await;
        attempts += 1;
    }
}

fn ensure_enough_validators<T>(votes: &[T]) -> Result<()> {
    if votes.len() < 2 {
        return Err(anyhow!(
            "test cluster returned {} validators, need at least two for fork test",
            votes.len()
        ));
    }
    Ok(())
}
