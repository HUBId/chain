use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::time::sleep;

use rpp_chain::errors::ChainError;
use rpp_chain::node::{ExternalFinalizationContext, FinalizationOutcome};

mod support;

use support::cluster::TestCluster;
use support::consensus::{consensus_round_for_block, signed_votes_for_round};

const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MAX_ATTEMPTS: usize = 50;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consensus_conflicting_votes_emit_evidence() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping consensus evidence test: {err:?}");
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
        let node_handle = primary.node_handle.clone();

        let mut attempts = 0;
        let tip_block = loop {
            if attempts >= MAX_ATTEMPTS {
                return Err(anyhow!("timed out waiting for node to produce tip block"));
            }
            match node_handle.latest_block().context("fetch latest block")? {
                Some(block) => break block,
                None => {
                    sleep(POLL_INTERVAL).await;
                    attempts += 1;
                }
            }
        };

        let status = node_handle
            .consensus_status()
            .context("query consensus status")?;
        assert_eq!(status.height, tip_block.header.height);
        assert_eq!(status.block_hash.as_deref(), Some(tip_block.hash.as_str()));

        let previous_block = if tip_block.header.height == 0 {
            None
        } else {
            node_handle
                .get_block(tip_block.header.height - 1)
                .context("fetch previous block")?
        };

        let mut round = consensus_round_for_block(primary, &tip_block, nodes)
            .context("build consensus round")?;
        let height = tip_block.header.height;
        let round_number = tip_block.consensus.round;

        let commit_pairs = signed_votes_for_round(nodes, height, round_number, &tip_block.hash)
            .context("assemble commit votes")?;

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
        assert!(round.commit_reached());

        let outcome = node_handle
            .finalize_block(ExternalFinalizationContext {
                round,
                block: tip_block.clone(),
                previous_block: previous_block.clone(),
                archived_votes: archived_votes.clone(),
            })
            .context("finalize block")?;

        let sealed_block = match outcome {
            FinalizationOutcome::Sealed { block, .. } => block,
            FinalizationOutcome::AwaitingQuorum => {
                return Err(anyhow!("expected block to seal"));
            }
        };
        assert_eq!(sealed_block.hash, tip_block.hash);
        let sealed_height = sealed_block.header.height;

        let conflicting_hash = format!("{:064x}", sealed_height + 42);
        let conflicting_pairs =
            signed_votes_for_round(nodes, height, round_number, &conflicting_hash)
                .context("assemble conflicting votes")?;

        let mut conflicting_archived = archived_votes.clone();
        for (prevote, precommit) in conflicting_pairs {
            conflicting_archived.push(prevote);
            conflicting_archived.push(precommit);
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
        assert!(second_round.commit_reached());

        let second_result = node_handle.finalize_block(ExternalFinalizationContext {
            round: second_round,
            block: tip_block.clone(),
            previous_block,
            archived_votes: conflicting_archived,
        });

        match second_result {
            Ok(outcome) => match outcome {
                FinalizationOutcome::AwaitingQuorum => {}
                FinalizationOutcome::Sealed { .. } => {
                    return Err(anyhow!("conflicting votes unexpectedly sealed block"));
                }
            },
            Err(err) => match &err {
                ChainError::Transaction(message) => {
                    assert!(
                        message.contains("conflicting vote"),
                        "unexpected transaction error: {message}"
                    );
                }
                _ => return Err(err.into()),
            },
        }

        let slashing_events = node_handle
            .slashing_events(16)
            .context("fetch slashing events")?;
        assert!(
            !slashing_events.is_empty(),
            "expected conflicting votes to produce slashing evidence"
        );

        let latest = node_handle
            .latest_block()
            .context("fetch latest block after evidence")?
            .expect("sealed block should remain tip");
        assert_eq!(latest.header.height, sealed_height);
        assert_eq!(latest.hash, sealed_block.hash);

        Ok(())
    }
    .await;

    if let Err(err) = cluster.shutdown().await {
        eprintln!("cluster shutdown failed: {err:?}");
    }

    result
}
