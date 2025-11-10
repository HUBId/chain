#![cfg(feature = "backend-rpp-stark")]

use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use tokio::time::sleep;

use rpp_chain::consensus::BftVoteKind;
use rpp_chain::errors::ChainError;
use rpp_chain::orchestration::PipelineStage;
use rpp_chain::proof_system::ProofVerifierRegistry;
use rpp_chain::storage::ledger::SlashingReason;
use rpp_chain::types::block::Block;
use rpp_chain::types::ChainProof;
use rpp_chain::wallet::WalletWorkflows;

mod support;

use support::cluster::TestCluster;
use support::consensus::signed_votes_for_round;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MAX_STATUS_ATTEMPTS: usize = 120;
const MAX_BLOCK_ATTEMPTS: usize = 60;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn conflicting_blocks_require_stark_verification() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start_with(4, |config, _| {
        config.rollout.feature_gates.consensus_enforcement = true;
        config.rollout.feature_gates.recursive_proofs = true;
        config.rollout.feature_gates.reconstruction = true;
        config.rollout.feature_gates.pruning = true;
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping reorg stark test: {err:?}");
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
        let recipient = nodes[1].wallet.address().to_string();

        // Submit a transaction to drive the pipeline to finality.
        let workflows = WalletWorkflows::new(primary.wallet.as_ref());
        let workflow = workflows
            .transaction_bundle(recipient, 1_000, 40, None)
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
                .wait_for_stage(&tx_hash, stage, NETWORK_TIMEOUT)
                .await
                .with_context(|| format!("wait for stage {stage:?}"))?;
        }

        let consensus_status = wait_for_consensus_status(primary).await?;
        ensure!(
            consensus_status.quorum_reached && consensus_status.block_hash.is_some(),
            "expected quorum markers after orchestrated transaction"
        );

        let telemetry = primary
            .orchestrator
            .telemetry_summary()
            .await
            .context("fetch pipeline telemetry")?;
        ensure!(
            telemetry
                .stage_latency_ms
                .get(&PipelineStage::BftFinalised)
                .map(|summary| summary.count >= 1)
                .unwrap_or(false),
            "BFT finalisation stage should record at least one completion"
        );

        // Capture the latest committed block as our baseline before injecting conflicts.
        let tip_block = wait_for_tip_block(primary).await.context("tip block")?;
        let baseline_height = tip_block.header.height;
        let baseline_hash = tip_block.hash.clone();
        let baseline_slashes = primary
            .node_handle
            .slashing_events(64)
            .context("baseline slashing events")?;

        // Assemble canonical and conflicting votes for the next height.
        let next_height = baseline_height + 1;
        let round_number = tip_block.consensus.round.saturating_add(1);
        let canonical_hash = format!("{:064x}", next_height + 131);
        let fork_hash = format!("{:064x}", next_height + 132);

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

        // Submit conflicting votes and ensure the evidence pool rejects them.
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
            .context("latest block after conflicts")?
            .context("missing tip after conflicts")?;
        ensure!(latest_block.header.height == baseline_height);
        ensure!(latest_block.hash == baseline_hash);

        let updated_slashes = primary
            .node_handle
            .slashing_events(64)
            .context("slashing events after conflicts")?;
        ensure!(
            updated_slashes
                .iter()
                .any(|event| event.address == prevote_voter
                    && event.reason == SlashingReason::ConsensusFault),
            "missing slashing event for conflicting prevote",
        );
        ensure!(
            updated_slashes
                .iter()
                .any(|event| event.address == precommit_voter
                    && event.reason == SlashingReason::ConsensusFault),
            "missing slashing event for conflicting precommit",
        );
        ensure!(updated_slashes.len() >= baseline_slashes.len() + 2);

        // Fetch the proof bundle for the latest block and verify it with the RPP-STARK backend.
        let proof_bundle = primary
            .node_handle
            .block_proofs(baseline_height)
            .context("fetch block proofs")?
            .context("missing proof bundle for tip")?;

        ensure!(
            matches!(proof_bundle.stark.state_proof, ChainProof::RppStark(_)),
            "state proof should use RPP-STARK backend",
        );
        ensure!(
            matches!(proof_bundle.stark.pruning_proof, ChainProof::RppStark(_)),
            "pruning proof should use RPP-STARK backend",
        );
        ensure!(
            matches!(proof_bundle.stark.recursive_proof, ChainProof::RppStark(_)),
            "recursive proof should use RPP-STARK backend",
        );
        let consensus_proof = proof_bundle
            .consensus_proof
            .as_ref()
            .context("consensus proof missing from bundle")?;
        ensure!(
            matches!(consensus_proof, ChainProof::RppStark(_)),
            "consensus proof should use RPP-STARK backend",
        );

        let verifier =
            ProofVerifierRegistry::with_max_proof_size_bytes(primary.config.max_proof_size_bytes)
                .context("initialise proof verifier registry")?;
        verifier
            .verify_rpp_stark_block_bundle(&proof_bundle.stark)
            .context("verify block bundle with RPP-STARK verifier")?;
        let snapshot = verifier.metrics_snapshot();
        let stark_metrics = snapshot
            .per_backend
            .get("rpp-stark")
            .context("registry metrics missing rpp-stark entry")?;
        ensure!(
            stark_metrics.accepted > 0,
            "expected verifier to record accepted proofs"
        );

        let validator_metrics = primary
            .node_handle
            .validator_telemetry()
            .context("validator telemetry snapshot")?
            .verifier_metrics;
        let runtime_stark = validator_metrics
            .per_backend
            .get("rpp-stark")
            .context("runtime metrics missing rpp-stark entry")?;
        ensure!(
            runtime_stark.accepted > 0,
            "node runtime should report accepted RPP-STARK verifications",
        );

        Ok(())
    }
    .await;

    if let Err(err) = cluster.shutdown().await {
        eprintln!("cluster shutdown failed: {err:?}");
    }

    result
}

async fn wait_for_tip_block(node: &support::cluster::TestClusterNode) -> Result<Block> {
    let mut attempts = 0usize;
    loop {
        if attempts >= MAX_BLOCK_ATTEMPTS {
            return Err(anyhow!("timed out waiting for node to produce a tip block"));
        }
        if let Some(block) = node
            .node_handle
            .latest_block()
            .context("fetch latest block while waiting for tip")?
        {
            if block.header.height > 0 {
                return Ok(block);
            }
        }
        sleep(POLL_INTERVAL).await;
        attempts += 1;
    }
}

async fn wait_for_consensus_status(
    node: &support::cluster::TestClusterNode,
) -> Result<rpp_chain::node::ConsensusStatus> {
    let mut attempts = 0usize;
    loop {
        let status = node
            .node_handle
            .consensus_status()
            .context("fetch consensus status")?;
        if status.quorum_reached
            && status.block_hash.is_some()
            && !status.round_latencies_ms.is_empty()
        {
            return Ok(status);
        }
        if attempts >= MAX_STATUS_ATTEMPTS {
            return Err(anyhow!(
                "consensus status missing quorum markers after orchestrated round"
            ));
        }
        attempts += 1;
        sleep(POLL_INTERVAL).await;
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
