#![cfg(feature = "backend-rpp-stark")]

use rpp_chain::zk::rpp_verifier::{RppStarkVerifier, RppStarkVerifierError, RppStarkVerifyFailure};
use rpp_stark::backend::params_limit_to_node_bytes;
use rpp_stark::params::deserialize_params;

#[path = "rpp_vectors.rs"]
mod rpp_vectors;
use rpp_vectors::{load_bytes, log_vector_checksums};

#[test]
fn verify_smoke_ok_with_golden_vector() -> anyhow::Result<()> {
    log_vector_checksums()?;

    let params = load_bytes("params.bin")?;
    let public_inputs = load_bytes("public_inputs.bin")?;
    let proof = load_bytes("proof.bin")?;

    let stark_params = deserialize_params(&params)?;
    let node_limit = params_limit_to_node_bytes(&stark_params)?;

    let verifier = RppStarkVerifier::new();
    let report = verifier.verify(&params, &public_inputs, &proof, node_limit)?;

    assert!(report.is_verified());
    assert!(report.params_ok());
    assert!(report.public_ok());
    assert!(report.merkle_ok());
    assert!(report.fri_ok());
    assert!(report.composition_ok());
    assert_eq!(report.total_bytes() as usize, proof.len());
    assert_eq!(report.notes(), None);

    Ok(())
}

#[test]
fn size_gate_mismatch_surfaces_from_library() -> anyhow::Result<()> {
    log_vector_checksums()?;

    let params = load_bytes("params.bin")?;
    let public_inputs = load_bytes("public_inputs.bin")?;
    let proof = load_bytes("proof.bin")?;

    let stark_params = deserialize_params(&params)?;
    let node_limit = params_limit_to_node_bytes(&stark_params)?;
    let tightened_limit = node_limit.saturating_sub(1024);

    let verifier = RppStarkVerifier::new();
    let error = verifier
        .verify(&params, &public_inputs, &proof, tightened_limit)
        .expect_err("mismatched size gate should yield an error");

    match error {
        RppStarkVerifierError::ProofSizeLimitMismatch {
            params_kib,
            expected_kib,
        } => {
            assert_eq!(params_kib, node_limit.div_ceil(1024));
            assert_eq!(expected_kib, tightened_limit.div_ceil(1024));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    Ok(())
}

#[test]
fn error_mapping_is_stable_display() -> anyhow::Result<()> {
    log_vector_checksums()?;

    let params = load_bytes("params.bin")?;
    let public_inputs = load_bytes("public_inputs.bin")?;
    let mut proof = load_bytes("proof.bin")?;

    let stark_params = deserialize_params(&params)?;
    let node_limit = params_limit_to_node_bytes(&stark_params)?;

    // Flip the first byte of the parameter hash in the proof header.
    if proof.len() > 2 {
        proof[2] ^= 0x01;
    }

    let verifier = RppStarkVerifier::new();
    let error = verifier
        .verify(&params, &public_inputs, &proof, node_limit)
        .expect_err("mutated proof should fail verification");

    let (failure, report) = match error {
        RppStarkVerifierError::VerificationFailed { failure, report } => (failure, report),
        other => panic!("unexpected error variant: {other:?}"),
    };

    assert!(matches!(failure, RppStarkVerifyFailure::ParamsHashMismatch));
    assert!(!report.is_verified());
    assert!(!report.params_ok());
    assert_eq!(
        format!("{error}"),
        "verification failed: parameter hash mismatch"
    );

    Ok(())
}
