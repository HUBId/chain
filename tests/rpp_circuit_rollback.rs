#![cfg(feature = "backend-rpp-stark")]

use anyhow::Result;
use rpp_chain::zk::rpp_verifier::{RppStarkVerifier, RppStarkVerifierError, RppStarkVerifyFailure};
use rpp_stark::params::{deserialize_params, params_limit_to_node_bytes};
use rpp_stark::proof::types::{Proof, VerifyError, PROOF_VERSION};

#[path = "rpp_vectors.rs"]
mod rpp_vectors;
use rpp_vectors::{load_bytes, log_vector_checksums};

#[test]
fn future_circuit_proofs_are_rejected_after_rollback() -> Result<()> {
    log_vector_checksums()?;

    let params = load_bytes("params.bin")?;
    let public_inputs = load_bytes("public_inputs.bin")?;
    let proof_bytes = load_bytes("proof.bin")?;

    let stark_params = deserialize_params(&params)?;
    let node_limit = params_limit_to_node_bytes(&stark_params)?;
    let verifier = RppStarkVerifier::new();

    // Sanity: the embedded proof for the current circuit should still verify.
    verifier.verify(&params, &public_inputs, &proof_bytes, node_limit)?;

    // Simulate a proof emitted by a newer circuit version after the node rolled back
    // to the previous circuit.
    let mut future_proof = Proof::from_bytes(&proof_bytes)?;
    *future_proof.version_mut() = PROOF_VERSION + 1;
    let future_bytes = future_proof.to_bytes()?;

    let error = verifier
        .verify(&params, &public_inputs, &future_bytes, node_limit)
        .expect_err("rolled-back verifier should reject future proof versions");

    match error {
        RppStarkVerifierError::VerificationFailed { failure, report } => {
            assert!(matches!(
                failure,
                RppStarkVerifyFailure::VersionMismatch {
                    expected,
                    actual
                } if expected == PROOF_VERSION && actual == PROOF_VERSION + 1
            ));
            assert_eq!(
                report.error,
                Some(VerifyError::VersionMismatch {
                    expected: PROOF_VERSION,
                    actual: PROOF_VERSION + 1,
                })
            );
            assert!(!report.params_ok);
            assert!(!report.public_ok);
        }
        other => panic!("unexpected verifier error: {other:?}"),
    }

    Ok(())
}

#[test]
fn mixed_circuit_versions_reject_incompatible_proofs() -> Result<()> {
    log_vector_checksums()?;

    let params = load_bytes("params.bin")?;
    let public_inputs = load_bytes("public_inputs.bin")?;
    let proof_bytes = load_bytes("proof.bin")?;

    let stark_params = deserialize_params(&params)?;
    let node_limit = params_limit_to_node_bytes(&stark_params)?;
    let verifier = RppStarkVerifier::new();

    // Old node verifying a future proof version.
    let mut future_proof = Proof::from_bytes(&proof_bytes)?;
    *future_proof.version_mut() = PROOF_VERSION + 1;
    let future_bytes = future_proof.to_bytes()?;
    let future_error = verifier
        .verify(&params, &public_inputs, &future_bytes, node_limit)
        .expect_err("rolled-back verifier should reject future proof versions");

    match future_error {
        RppStarkVerifierError::VerificationFailed { failure, report } => {
            assert!(matches!(
                failure,
                RppStarkVerifyFailure::VersionMismatch {
                    expected,
                    actual
                } if expected == PROOF_VERSION && actual == PROOF_VERSION + 1
            ));
            assert_eq!(
                report.error,
                Some(VerifyError::VersionMismatch {
                    expected: PROOF_VERSION,
                    actual: PROOF_VERSION + 1,
                })
            );
            assert!(!report.params_ok);
            assert!(!report.public_ok);
        }
        other => panic!("unexpected verifier error: {other:?}"),
    }

    // Upgraded node rejecting stale proofs that advertise an older PROOF_VERSION.
    let mut stale_proof = Proof::from_bytes(&proof_bytes)?;
    *stale_proof.version_mut() = PROOF_VERSION.saturating_sub(1);
    let stale_bytes = stale_proof.to_bytes()?;
    let stale_error = verifier
        .verify(&params, &public_inputs, &stale_bytes, node_limit)
        .expect_err("upgraded verifier should reject stale proof versions");

    match stale_error {
        RppStarkVerifierError::VerificationFailed { failure, report } => {
            assert!(matches!(
                failure,
                RppStarkVerifyFailure::VersionMismatch {
                    expected,
                    actual
                } if expected == PROOF_VERSION && actual == PROOF_VERSION.saturating_sub(1)
            ));
            assert_eq!(
                report.error,
                Some(VerifyError::VersionMismatch {
                    expected: PROOF_VERSION,
                    actual: PROOF_VERSION.saturating_sub(1),
                })
            );
            assert!(!report.params_ok);
            assert!(!report.public_ok);
        }
        other => panic!("unexpected verifier error: {other:?}"),
    }

    Ok(())
}

#[test]
fn circuit_digest_drift_surfaces_as_rollback_warning() -> Result<()> {
    log_vector_checksums()?;

    let params = load_bytes("params.bin")?;
    let public_inputs = load_bytes("public_inputs.bin")?;
    let proof_bytes = load_bytes("proof.bin")?;

    let stark_params = deserialize_params(&params)?;
    let node_limit = params_limit_to_node_bytes(&stark_params)?;
    let verifier = RppStarkVerifier::new();

    let mut rolled_back_proof = Proof::from_bytes(&proof_bytes)?;
    rolled_back_proof.params_hash_mut().0.bytes[0] ^= 0x7f;
    let drifted_bytes = rolled_back_proof.to_bytes()?;

    let error = verifier
        .verify(&params, &public_inputs, &drifted_bytes, node_limit)
        .expect_err("drifted circuit digest should be rejected after rollback");

    match error {
        RppStarkVerifierError::VerificationFailed { failure, report } => {
            assert!(matches!(failure, RppStarkVerifyFailure::ParamsHashMismatch));
            assert_eq!(report.error, Some(VerifyError::ParamsHashMismatch));
            assert!(!report.params_ok);
        }
        other => panic!("unexpected verifier error: {other:?}"),
    }

    Ok(())
}
