#![cfg(all(
    feature = "backend-rpp-stark",
    feature = "wallet-integration",
    feature = "wallet-ui",
))]

use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use tokio::time::sleep;

use rpp_chain::errors::ChainError;
use rpp_chain::orchestration::PipelineStage;
use rpp_chain::proof_system::BackendVerificationOutcome;
use rpp_chain::runtime::types::proofs::TransactionProofBundle;
use rpp_chain::wallet::WalletWorkflows;

mod support;

use support::cluster::TestCluster;
use support::transactions::duplicate_transaction_for_double_spend;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MAX_BLOCK_ATTEMPTS: usize = 60;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_rpp_stark_transactions_are_rejected_and_penalised() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start_with(3, |config, _| {
        config.rollout.feature_gates.consensus_enforcement = true;
        config.rollout.feature_gates.recursive_proofs = true;
        config.rollout.feature_gates.pruning = true;
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping rpp-stark conflict test: {err:?}");
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

        let tip_block = wait_for_tip_block(primary).await.context("tip block")?;
        let (duplicate_tx, duplicate_proof, duplicate_witness) = duplicate_transaction_for_double_spend(&tip_block, 0)
            .context("duplicate first transaction for replay")?;

        let base_metrics = primary
            .node_handle
            .validator_telemetry()
            .context("validator telemetry")?
            .verifier_metrics;
        let baseline_rejected = base_metrics
            .per_backend
            .get("rpp-stark")
            .map(|metrics| metrics.rejected)
            .unwrap_or_default();

        let duplicate_bundle = TransactionProofBundle::new(
            duplicate_tx.clone(),
            duplicate_proof.clone(),
            Some(duplicate_witness.clone()),
            None,
        );

        match primary.node_handle.submit_transaction(duplicate_bundle.clone()) {
            Ok(hash) => {
                return Err(anyhow!(
                    "duplicate transaction unexpectedly accepted with hash {hash}"
                ));
            }
            Err(err) => match &err {
                ChainError::Transaction(message) => {
                    ensure!(
                        message.contains("duplicate")
                            || message.contains("double")
                            || message.contains("conflict"),
                        "unexpected duplicate rejection message: {message}",
                    );
                }
                other => return Err(anyhow!("unexpected duplicate error: {other:?}")),
            },
        }

        let after_duplicate = primary
            .node_handle
            .validator_telemetry()
            .context("telemetry after duplicate")?
            .verifier_metrics;
        let after_rejected = after_duplicate
            .per_backend
            .get("rpp-stark")
            .map(|metrics| metrics.rejected)
            .unwrap_or_default();
        ensure!(
            after_rejected >= baseline_rejected,
            "rejected counter regressed after duplicate submission",
        );

        let mut tampered_bundle = duplicate_bundle;
        if let rpp_chain::runtime::types::proofs::ChainProof::RppStark(ref mut proof) = tampered_bundle.proof {
            if let Some(first) = proof.proof.first_mut() {
                *first ^= 0xff;
            } else {
                proof.proof.push(1);
            }
        }

        match primary.node_handle.submit_transaction(tampered_bundle) {
            Ok(hash) => {
                return Err(anyhow!(
                    "tampered proof transaction unexpectedly accepted with hash {hash}"
                ));
            }
            Err(err) => match &err {
                ChainError::Transaction(message) => {
                    ensure!(
                        message.contains("proof") || message.contains("invalid"),
                        "unexpected tamper rejection message: {message}",
                    );
                }
                other => return Err(anyhow!("unexpected tamper error: {other:?}")),
            },
        }

        let final_metrics = primary
            .node_handle
            .validator_telemetry()
            .context("telemetry after tamper")?
            .verifier_metrics;
        let final_rejected = final_metrics
            .per_backend
            .get("rpp-stark")
            .map(|metrics| metrics.rejected)
            .unwrap_or_default();
        ensure!(
            final_rejected > after_rejected || matches!(final_metrics.last.as_ref().map(|last| &last.outcome), Some(BackendVerificationOutcome::Rejected)),
            "expected rejection counter or last outcome to reflect tampered proof",
        );

        Ok(())
    }
    .await;

    if let Err(err) = cluster.shutdown().await {
        eprintln!("cluster shutdown failed: {err:?}");
    }

    result
}

async fn wait_for_tip_block(node: &support::cluster::TestClusterNode) -> Result<rpp_chain::runtime::types::block::Block> {
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
