#![cfg(feature = "backend-rpp-stark")]

use rpp_chain::zk::rpp_verifier::{RppStarkVerifier, RppStarkVerifierError, RppStarkVerifyFailure};
use rpp_stark::backend::{
    ensure_proof_size_consistency, params_limit_to_node_bytes, ProofSizeMappingError,
};
use rpp_stark::params::{deserialize_params, StarkParamsBuilder};

#[path = "rpp_vectors.rs"]
mod rpp_vectors;
use rpp_vectors::{load_bytes, log_vector_checksums, log_vector_report};

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

    log_vector_report(&report)?;

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
fn size_gate_rounds_node_limit_up_to_next_kib() -> anyhow::Result<()> {
    log_vector_checksums()?;

    let params = load_bytes("params.bin")?;
    let stark_params = deserialize_params(&params)?;
    let node_limit = params_limit_to_node_bytes(&stark_params)?;

    ensure_proof_size_consistency(&stark_params, node_limit.saturating_sub(1))
        .expect("rounding should tolerate sub-kiB deltas");

    let err = ensure_proof_size_consistency(&stark_params, node_limit - 1024)
        .expect_err("dropping a full KiB should shift the expected bucket");
    match err {
        ProofSizeMappingError::Mismatch {
            params_kb,
            expected_kb,
        } => {
            assert_eq!(params_kb, stark_params.proof().max_size_kb);
            assert_eq!(expected_kb + 1, params_kb);
        }
        other => panic!("unexpected mapping error: {other:?}"),
    }

    Ok(())
}

#[test]
fn proof_size_gate_rejects_oversized_payloads() -> anyhow::Result<()> {
    log_vector_checksums()?;

    let params = load_bytes("params.bin")?;
    let public_inputs = load_bytes("public_inputs.bin")?;
    let mut proof = load_bytes("proof.bin")?;

    let stark_params = deserialize_params(&params)?;
    let node_limit = params_limit_to_node_bytes(&stark_params)?;

    proof.extend_from_slice(&vec![0u8; 2 * 1024]);

    let verifier = RppStarkVerifier::new();
    let error = verifier
        .verify(&params, &public_inputs, &proof, node_limit)
        .expect_err("oversized proof should yield a proof-too-large error");

    match error {
        RppStarkVerifierError::VerificationFailed { failure, report } => {
            if let RppStarkVerifyFailure::ProofTooLarge { max_kib, got_kib } = failure {
                assert_eq!(max_kib, node_limit.div_ceil(1024));
                assert_eq!(got_kib, u64::try_from(proof.len()).unwrap().div_ceil(1024));
            } else {
                panic!("unexpected failure variant: {failure:?}");
            }
            assert!(!report.is_verified());
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    Ok(())
}

#[test]
fn size_gate_overflow_maps_to_facade_error() {
    let mut builder = StarkParamsBuilder::default();
    builder.proof.max_size_kb = u32::MAX;
    let params = builder.build().expect("params build succeeds");

    let error = params_limit_to_node_bytes(&params).unwrap_err();
    match error {
        ProofSizeMappingError::Overflow { max_size_kb } => {
            assert_eq!(max_size_kb, u32::MAX);
        }
        other => panic!("unexpected mapping error: {other:?}"),
    }

    let facade_error = RppStarkVerifierError::from_size_mapping_error(error);
    assert!(matches!(
        facade_error,
        RppStarkVerifierError::ProofSizeLimitOverflow { max_kib } if max_kib == u32::MAX
    ));
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
