use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tempfile::tempdir;

use rpp_chain::proof_system::ProofVerifierRegistry;
use rpp_chain::runtime::types::uptime::UptimeClaim;
use rpp_chain::runtime::types::proofs::ChainProof;
use rpp_chain::runtime::types::proofs::ProofPayload;

#[cfg(feature = "prover-stwo")]
use rpp_chain::storage::Storage;
#[cfg(feature = "prover-stwo")]
use rpp_chain::stwo::prover::WalletProver as StwoWalletProver;

#[cfg(feature = "backend-plonky3")]
use rpp_chain::plonky3::prover::Plonky3Prover;

#[cfg(feature = "prover-stwo")]
fn sample_claim(node_clock: u64, window_span: Duration) -> UptimeClaim {
    let window_end = 4_200u64;
    let window_start = window_end.saturating_sub(window_span.as_secs());
    UptimeClaim {
        wallet_address: "aa".repeat(32),
        node_clock,
        epoch: 1,
        head_hash: "11".repeat(32),
        window_start,
        window_end,
    }
}

#[cfg(feature = "prover-stwo")]
#[test]
fn stwo_uptime_proof_flags_backward_clock_skew() -> Result<()> {
    let temp_dir = tempdir().context("clock skew tempdir")?;
    let storage = Storage::open(temp_dir.path()).context("open storage")?;
    let prover = StwoWalletProver::new(&storage);

    let claim = sample_claim(3_900, Duration::from_secs(600));
    let witness = prover
        .derive_uptime_witness(&claim)
        .context("derive uptime witness")?;
    let err = prover
        .prove_uptime_witness(witness)
        .expect_err("backwards clock skew should fail proving");

    let message = format!("{err:#}");
    assert!(
        message.contains("node clock precedes observation window"),
        "error message should flag the skew: {message}"
    );

    Ok(())
}

#[cfg(feature = "backend-plonky3")]
#[test]
fn plonky3_uptime_proof_flags_backward_clock_skew() -> Result<()> {
    let prover = Plonky3Prover::new();
    let window_end = 5_000u64;
    let claim = UptimeClaim {
        wallet_address: "bb".repeat(32),
        node_clock: window_end.saturating_sub(120),
        epoch: 2,
        head_hash: "22".repeat(32),
        window_start: window_end.saturating_sub(600),
        window_end,
    };

    let witness = prover
        .build_uptime_witness(&claim)
        .context("build plonky3 uptime witness")?;
    let err = prover
        .prove_uptime(witness)
        .expect_err("plonky3 should reject backwards clock skew");

    let message = format!("{err:#}");
    assert!(
        message.to_lowercase().contains("clock"),
        "skew error should mention the clock: {message}"
    );

    Ok(())
}

#[cfg(feature = "prover-stwo")]
#[test]
fn verifier_metrics_alert_on_skewed_payload() -> Result<()> {
    let temp_dir = tempdir().context("metrics tempdir")?;
    let storage = Storage::open(temp_dir.path()).context("open storage")?;
    let prover = StwoWalletProver::new(&storage);

    let claim = sample_claim(4_260, Duration::from_secs(900));
    let witness = prover
        .derive_uptime_witness(&claim)
        .context("derive healthy witness")?;
    let mut proof = prover
        .prove_uptime_witness(witness)
        .context("prove uptime")?;

    if let ProofPayload::Uptime(ref mut uptime) = proof.payload {
        uptime.node_clock = uptime.window_end.saturating_sub(1);
    } else {
        return Err(anyhow!("unexpected proof payload for uptime"));
    }

    let registry = ProofVerifierRegistry::default();
    let result = registry.verify_uptime(&ChainProof::Stwo(proof.clone()));
    assert!(result.is_err(), "skewed payload should be rejected");

    let snapshot = registry.metrics_snapshot();
    let stwo_metrics = snapshot
        .per_backend
        .get("stwo")
        .ok_or_else(|| anyhow!("missing stwo metrics"))?;
    assert_eq!(stwo_metrics.rejected, 1, "rejections should be counted");
    assert_eq!(stwo_metrics.accepted, 0, "no proofs should be accepted");

    Ok(())
}
