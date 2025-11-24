#![cfg(all(feature = "prover-stwo", feature = "backend-rpp-stark"))]

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use futures::future::try_join_all;
use rand::{rngs::StdRng, SeedableRng};
use rpp_chain::zk::rpp_verifier::{
    RppStarkVerifier, RppStarkVerifierError, RppStarkVerifyFailure,
};
use rpp_stark::backend::params_limit_to_node_bytes;
use rpp_stark::params::deserialize_params;
use tokio::sync::Semaphore;

#[path = "rpp_vectors.rs"]
mod rpp_vectors;

use rpp_vectors::{load_bytes, log_vector_checksums};

use prover_stwo_backend::official::params::StarkParameters;
use prover_stwo_backend::official::prover::WalletProver as StwoWalletProver;
use prover_stwo_backend::official::verifier::NodeVerifier;
use prover_stwo_backend::types::{
    Account, ChainProof, SignedTransaction, Stake, Transaction, TransactionWitness, UptimeProof,
    UptimeWitness,
};
use prover_stwo_backend::{reputation::Tier, ReputationWeights};

const STWO_CONCURRENCY: usize = 2;
const RPP_CONCURRENCY: usize = 3;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn zk_backends_handle_parallel_batches_and_size_limits() -> Result<()> {
    log_vector_checksums()?;

    let stwo_metrics = run_stwo_batch().await.context("stwo batch generation")?;
    assert!(
        stwo_metrics.throughput_per_second > 0.1,
        "stwo throughput should stay above minimal floor"
    );

    let rpp_metrics = run_rpp_batch().await.context("rpp-stark verifier batch")?;
    assert!(rpp_metrics.oversize_failure_recorded, "oversized proofs must fail");

    Ok(())
}

struct BatchMetrics {
    latencies: Vec<Duration>,
    throughput_per_second: f64,
    oversize_failure_recorded: bool,
}

async fn run_stwo_batch() -> Result<BatchMetrics> {
    let parameters = StarkParameters::blueprint_default();
    let prover = Arc::new(StwoWalletProver::new(parameters.clone()));
    let verifier = Arc::new(NodeVerifier::with_parameters(parameters));
    let semaphore = Arc::new(Semaphore::new(STWO_CONCURRENCY));

    let start = Instant::now();
    let mut jobs = Vec::new();
    for job in 0..6u64 {
        let permit = semaphore.clone().acquire_owned().await?;
        let prover = prover.clone();
        let verifier = verifier.clone();
        jobs.push(tokio::spawn(async move {
            let latency = if job % 2 == 0 {
                let witness = build_transaction_witness(job)?;
                measure_latency(|| prove_and_verify_transaction(&prover, &verifier, witness))?
            } else {
                let witness = build_uptime_witness(job);
                measure_latency(|| prove_and_verify_uptime(&prover, &verifier, witness))?
            };
            drop(permit);
            Ok::<Duration, anyhow::Error>(latency)
        }));
    }

    let latencies: Vec<Duration> = try_join_all(jobs).await?.into_iter().collect::<Result<_, _>>()?;
    let elapsed = start.elapsed().max(Duration::from_millis(1));
    let throughput_per_second = latencies.len() as f64 / elapsed.as_secs_f64();

    Ok(BatchMetrics {
        latencies,
        throughput_per_second,
        oversize_failure_recorded: false,
    })
}

fn measure_latency<F>(mut f: F) -> Result<Duration>
where
    F: FnMut() -> Result<()>,
{
    let started = Instant::now();
    f()?;
    Ok(started.elapsed())
}

fn build_transaction_witness(job: u64) -> Result<TransactionWitness> {
    let mut rng = StdRng::seed_from_u64(job + 42);
    let signing: SigningKey = SigningKey::generate(&mut rng);
    let verifying: VerifyingKey = signing.verifying_key();
    let from = format!("{:064x}", job + 1);
    let to = format!("{:064x}", job + 2);
    let payload = Transaction {
        from: from.clone(),
        to,
        amount: 100 + job as u128,
        fee: 1,
        nonce: job + 1,
        memo: None,
        timestamp: 1,
    };
    let signature: Signature = signing.sign(&payload.canonical_bytes());
    let signed_tx = SignedTransaction::new(payload, signature, &verifying);

    let mut sender = Account::new(from, 10_000, Stake::default());
    sender.nonce = job;
    let receiver = Account::new(format!("{:064x}", job + 3), 0, Stake::default());

    Ok(TransactionWitness {
        signed_tx,
        sender_account: sender,
        receiver_account: Some(receiver),
        required_tier: Tier::Tl0,
        reputation_weights: ReputationWeights::default(),
    })
}

fn prove_and_verify_transaction(
    prover: &StwoWalletProver,
    verifier: &NodeVerifier,
    witness: TransactionWitness,
) -> Result<()> {
    let proof = prover
        .prove_transaction_witness(witness.clone())
        .context("generate transaction proof")?;
    verifier
        .verify_transaction(&ChainProof::Stwo(proof))
        .context("verify transaction proof")
}

fn build_uptime_witness(job: u64) -> UptimeWitness {
    let wallet_address = format!("{:064x}", job + 9);
    let window_start = job * 10;
    let window_end = window_start + 5;
    let commitment = hex::encode(UptimeProof::commitment_bytes(&wallet_address, window_start, window_end));

    UptimeWitness {
        wallet_address,
        node_clock: job,
        epoch: 1,
        head_hash: format!("{:064x}", job + 20),
        window_start,
        window_end,
        commitment,
    }
}

fn prove_and_verify_uptime(
    prover: &StwoWalletProver,
    verifier: &NodeVerifier,
    witness: UptimeWitness,
) -> Result<()> {
    let proof = prover
        .prove_uptime_witness(witness.clone())
        .context("generate uptime proof")?;
    verifier
        .verify_uptime(&ChainProof::Stwo(proof))
        .context("verify uptime proof")
}

async fn run_rpp_batch() -> Result<BatchMetrics> {
    let params = load_bytes("params.bin")?;
    let public_inputs = load_bytes("public_inputs.bin")?;
    let proof = load_bytes("proof.bin")?;
    let verifier = Arc::new(RppStarkVerifier::new());

    let stark_params = deserialize_params(&params).context("decode stark params")?;
    let node_limit = params_limit_to_node_bytes(&stark_params)
        .context("map node size limit")?;

    let semaphore = Arc::new(Semaphore::new(RPP_CONCURRENCY));
    let start = Instant::now();
    let mut jobs = Vec::new();
    for _ in 0..9 {
        let permit = semaphore.clone().acquire_owned().await?;
        let verifier = verifier.clone();
        let params = params.clone();
        let public_inputs = public_inputs.clone();
        let proof = proof.clone();
        jobs.push(tokio::spawn(async move {
            let latency = measure_latency(|| {
                verifier.verify(&params, &public_inputs, &proof, node_limit)?;
                Ok(())
            })?;
            drop(permit);
            Ok::<Duration, anyhow::Error>(latency)
        }));
    }

    let latencies: Vec<Duration> = try_join_all(jobs).await?.into_iter().collect::<Result<_, _>>()?;
    let elapsed = start.elapsed().max(Duration::from_millis(1));
    let throughput_per_second = latencies.len() as f64 / elapsed.as_secs_f64();

    let oversize_failure_recorded = matches!(
        verifier
            .verify(&params, &public_inputs, &[proof.clone(), vec![0u8; 2048]].concat(), node_limit)
            .expect_err("oversized proof should fail"),
        RppStarkVerifierError::VerificationFailed {
            failure: RppStarkVerifyFailure::ProofTooLarge { .. },
            ..
        }
    );

    Ok(BatchMetrics {
        latencies,
        throughput_per_second,
        oversize_failure_recorded,
    })
}

