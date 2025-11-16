#![cfg(all(feature = "wallet-integration", feature = "wallet-ui"))]

use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use tokio::time::sleep;

use rpp_chain::crypto::{load_keypair, sign_message, signature_to_hex};
use rpp_chain::errors::ChainError;
use rpp_chain::node::{ExternalFinalizationContext, FinalizationOutcome};
use rpp_chain::proof_backend::Blake2sHasher;
use rpp_chain::runtime::types::block::Block;
use rpp_chain::runtime::types::proofs::ProofArtifact;
use rpp_chain::storage::ledger::SlashingReason;
use rpp_chain::wallet::WalletWorkflows;

mod support;

use support::cluster::TestCluster;
use support::consensus::{consensus_round_for_block, signed_votes_for_round};
use support::transactions::duplicate_transaction_for_double_spend;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn double_spend() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    run_double_spend_case(false).await?;
    run_double_spend_case(true).await?
}

async fn run_double_spend_case(enforce_consensus: bool) -> Result<()> {
    let mut cluster = match TestCluster::start_with(3, |config, _| {
        config.rollout.feature_gates.consensus_enforcement = enforce_consensus;
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!(
                "skipping double spend consensus test (enforcement={enforce_consensus}): {err:?}"
            );
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
        let amount = 5_000u128;
        let fee = 100u64;
        let tx_workflow = workflows
            .transaction_bundle(recipient, amount, fee, None)
            .context("build transaction bundle")?;
        let target_tx_id = tx_workflow.bundle.transaction.id;

        primary
            .node_handle
            .submit_transaction(tx_workflow.bundle.clone())
            .context("enqueue transaction bundle")?;

        let sealed_block = wait_for_transaction_block(primary, target_tx_id)
            .await
            .context("wait block")?;
        ensure!(
            !sealed_block.transactions.is_empty(),
            "expected sealed block to contain at least one transaction"
        );
        let tx_index = sealed_block
            .transactions
            .iter()
            .position(|tx| tx.id == target_tx_id)
            .context("locate transaction in block")?;
        let previous_block = if sealed_block.header.height == 0 {
            None
        } else {
            primary
                .node_handle
                .get_block(sealed_block.header.height - 1)
                .context("fetch previous block")?
        };

        let (round, double_spend_block) =
            prepare_double_spend_block(primary, nodes, &sealed_block, tx_index)
                .context("prepare double spend block")?;

        let baseline_events = primary
            .node_handle
            .slashing_events(16)
            .context("fetch baseline slashing events")?;
        let baseline_count = baseline_events.len();
        let expected_tip_height = sealed_block.header.height;
        let expected_tip_hash = sealed_block.hash.clone();

        let outcome = primary
            .node_handle
            .finalize_block(ExternalFinalizationContext {
                round,
                block: double_spend_block.clone(),
                previous_block,
                archived_votes: Vec::new(),
            });

        match outcome {
            Ok(result) => match result {
                FinalizationOutcome::Sealed { .. } => {
                    return Err(anyhow!("double spend block unexpectedly sealed"));
                }
                FinalizationOutcome::AwaitingQuorum => {
                    return Err(anyhow!("double spend block should not await quorum"));
                }
            },
            Err(err) => match &err {
                ChainError::Transaction(message) => {
                    ensure!(
                        message.contains("transaction input already spent"),
                        "unexpected transaction error: {message}"
                    );
                }
                _ => return Err(err.into()),
            },
        }

        let slashing_events = primary
            .node_handle
            .slashing_events(16)
            .context("fetch slashing events after double spend")?;

        if enforce_consensus {
            ensure!(
                slashing_events.len() == baseline_count + 1,
                "expected consensus enforcement to record slashing event"
            );
            let latest = slashing_events
                .last()
                .context("slashing events missing new record")?;
            ensure!(
                latest.reason == SlashingReason::ConsensusFault,
                "unexpected slashing reason: {:?}",
                latest.reason
            );
            ensure!(
                latest.address == double_spend_block.header.proposer,
                "slashing event references unexpected address"
            );
        } else {
            ensure!(
                slashing_events.len() == baseline_count,
                "consensus enforcement disabled should not add slashing event"
            );
        }

        let tip = primary
            .node_handle
            .latest_block()
            .context("fetch latest block after double spend")?
            .context("tip missing after double spend attempt")?;
        ensure!(tip.header.height == expected_tip_height);
        ensure!(tip.hash == expected_tip_hash);

        Ok(())
    }
    .await;

    if let Err(err) = cluster.shutdown().await {
        eprintln!("cluster shutdown failed: {err:?}");
    }

    result
}

async fn wait_for_transaction_block(
    node: &support::cluster::TestClusterNode,
    tx_id: uuid::Uuid,
) -> Result<Block> {
    let mut attempts = 0;
    loop {
        if attempts >= MAX_ATTEMPTS {
            return Err(anyhow!(
                "timed out waiting for block containing transaction"
            ));
        }
        if let Some(latest) = node
            .node_handle
            .latest_block()
            .context("fetch latest block while waiting for transaction")?
        {
            let start_height = latest.header.height.saturating_sub(4);
            for height in start_height..=latest.header.height {
                if let Some(candidate) = node
                    .node_handle
                    .get_block(height)
                    .context("fetch candidate block")?
                {
                    if candidate.transactions.iter().any(|tx| tx.id == tx_id) {
                        return Ok(candidate);
                    }
                }
            }
        }
        sleep(POLL_INTERVAL).await;
        attempts += 1;
    }
}

fn prepare_double_spend_block(
    primary: &support::cluster::TestClusterNode,
    nodes: &[support::cluster::TestClusterNode],
    base_block: &Block,
    duplicate_index: usize,
) -> Result<(rpp_chain::consensus::ConsensusRound, Block)> {
    use rpp_chain::state::merkle::compute_merkle_root;

    let (duplicate_tx, duplicate_proof, duplicate_witness) =
        duplicate_transaction_for_double_spend(base_block, duplicate_index)
            .context("duplicate original transaction")?;

    let mut block = base_block.clone();
    let insert_at = duplicate_index + 1;
    block.transactions.insert(insert_at, duplicate_tx);
    block
        .stark
        .transaction_proofs
        .insert(insert_at, duplicate_proof);
    block
        .module_witnesses
        .transactions
        .insert(insert_at, duplicate_witness);

    let mut verification_keys = block
        .proof_artifacts
        .iter()
        .map(|artifact| (artifact.module, artifact.verification_key.clone()))
        .collect::<std::collections::HashMap<_, _>>();
    block.proof_artifacts = block
        .module_witnesses
        .expected_artifacts()
        .context("recompute module witness artifacts")?
        .into_iter()
        .map(|(module, commitment, proof)| ProofArtifact {
            module,
            commitment,
            proof,
            verification_key: verification_keys.remove(&module).unwrap_or_default(),
        })
        .collect();

    let mut operation_hashes = Vec::new();
    for request in &block.identities {
        operation_hashes.push(request.declaration.hash()?);
    }
    for tx in &block.transactions {
        operation_hashes.push(tx.hash());
    }
    for proof in &block.uptime_proofs {
        let encoded = serde_json::to_vec(proof).context("encode uptime proof for hash")?;
        operation_hashes.push(Blake2sHasher::hash(&encoded).into());
    }
    for update in &block.timetoke_updates {
        let encoded = serde_json::to_vec(update).context("encode timetoke update for hash")?;
        operation_hashes.push(Blake2sHasher::hash(&encoded).into());
    }
    for update in &block.reputation_updates {
        let encoded = serde_json::to_vec(update).context("encode reputation update for hash")?;
        operation_hashes.push(Blake2sHasher::hash(&encoded).into());
    }
    let tx_root = compute_merkle_root(&mut operation_hashes);
    block.header.tx_root = hex::encode(tx_root);

    let proposer = nodes
        .iter()
        .find(|node| node.node_handle.address() == block.header.proposer)
        .context("locate proposer for signature")?;
    let proposer_keys = load_keypair(&proposer.config.key_path)
        .context("load proposer key material for signature")?;
    let signature = sign_message(&proposer_keys, &block.header.canonical_bytes());
    block.signature = signature_to_hex(&signature);

    let block_hash_bytes = block.header.hash();
    block.hash = hex::encode(block_hash_bytes);

    let mut round = consensus_round_for_block(primary, &block, nodes)
        .context("reconstruct consensus round for mutated block")?;
    round.set_block_hash(block.hash.clone());
    let height = block.header.height;
    let round_number = base_block.consensus.round;
    let commit_pairs = signed_votes_for_round(nodes, height, round_number, &block.hash)
        .context("sign consensus votes for mutated block")?;

    let mut aggregated_votes: Vec<rpp_chain::consensus::SignedBftVote> = Vec::new();
    for (prevote, precommit) in &commit_pairs {
        round
            .register_prevote(prevote)
            .context("register prevote for mutated block")?;
        round
            .register_precommit(precommit)
            .context("register precommit for mutated block")?;
        aggregated_votes.push(prevote.clone());
        aggregated_votes.push(precommit.clone());
    }
    ensure!(
        round.commit_reached(),
        "expected consensus round to reach commit"
    );

    block.bft_votes = aggregated_votes;
    block.consensus = round.certificate();

    Ok((round, block))
}
