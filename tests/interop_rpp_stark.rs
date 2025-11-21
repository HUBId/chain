#![cfg(feature = "backend-rpp-stark")]

use std::collections::BTreeSet;
use std::convert::TryFrom;
use std::fs;

use rpp_chain::zk::rpp_adapter::{compute_public_digest, Digest32};
use rpp_chain::zk::rpp_verifier::{self, RppStarkVerifier};

#[path = "rpp_vectors.rs"]
mod rpp_vectors;
use rpp_vectors::{load_bytes, load_hex_digest, log_vector_checksums, vector_path};

#[test]
fn interop_verify_golden_vector_ok() -> anyhow::Result<()> {
    log_vector_checksums()?;

    let params = load_bytes("params.bin")?;
    let public_inputs = load_bytes("public_inputs.bin")?;
    let proof = load_bytes("proof.bin")?;
    let expected_digest = load_hex_digest("public_digest.hex")?;

    assert!(!params.is_empty(), "params.bin should not be empty");
    assert!(
        !public_inputs.is_empty(),
        "public_inputs.bin should not be empty"
    );
    assert!(!proof.is_empty(), "proof.bin should not be empty");

    let digest = compute_public_digest(&public_inputs);
    assert_eq!(digest.to_hex(), expected_digest, "public digest mismatch");

    let verifier = RppStarkVerifier::new();
    assert!(verifier.is_ready(), "backend wiring should be complete");

    let report = verifier.verify_golden_vector(&params, &public_inputs, &proof)?;
    assert_eq!(report.backend(), verifier.backend_name());
    assert!(report.is_verified(), "golden proof should verify");
    let flags = report.flags();
    assert!(flags.params(), "params stage should succeed");
    assert!(flags.public(), "public-input stage should succeed");
    assert!(flags.merkle(), "merkle stage should succeed");
    assert!(flags.fri(), "fri stage should succeed");
    assert!(flags.composition(), "composition stage should succeed");
    assert!(
        flags.all_passed(),
        "all stage flags should be set for golden proof"
    );
    assert_eq!(
        report.total_bytes() as usize,
        proof.len(),
        "reported proof length must match provided bytes"
    );

    Ok(())
}

#[test]
fn interop_indices_match_and_are_sorted_unique() -> anyhow::Result<()> {
    log_vector_checksums()?;

    let indices_contents = fs::read_to_string(vector_path("indices.json"))?;
    let indices: Vec<u64> = serde_json::from_str(&indices_contents)?;
    assert!(!indices.is_empty(), "indices.json should contain entries");

    for window in indices.windows(2) {
        let [left, right]: [u64; 2] = [window[0], window[1]];
        assert!(
            left < right,
            "indices must be strictly increasing: {left} !< {right}"
        );
    }

    let unique: BTreeSet<_> = indices.iter().copied().collect();
    assert_eq!(unique.len(), indices.len(), "indices must be unique");

    let params = load_bytes("params.bin")?;
    let public_inputs = load_bytes("public_inputs.bin")?;
    let proof = load_bytes("proof.bin")?;

    let verifier = RppStarkVerifier::new();
    assert!(verifier.is_ready(), "backend wiring should be complete");
    let report = verifier.verify_golden_vector(&params, &public_inputs, &proof)?;

    if let Some(report_indices) = report.trace_query_indices() {
        let expected: Vec<u32> = indices
            .iter()
            .map(|&index| {
                u32::try_from(index)
                    .expect("vector indices must fit into 32 bits for backend comparison")
            })
            .collect();
        assert_eq!(
            report_indices, expected,
            "verifier report indices must match indices.json"
        );
    }

    Ok(())
}

#[test]
fn interop_repeatability_is_deterministic() -> anyhow::Result<()> {
    log_vector_checksums()?;

    let proof_first = load_bytes("proof.bin")?;
    let proof_second = load_bytes("proof.bin")?;
    assert_eq!(
        proof_first, proof_second,
        "proof reads should be deterministic"
    );

    let digest_first: Digest32 = compute_public_digest(&load_bytes("public_inputs.bin")?);
    let digest_second: Digest32 = compute_public_digest(&load_bytes("public_inputs.bin")?);
    assert_eq!(
        digest_first, digest_second,
        "digest computations must be deterministic"
    );

    let params = load_bytes("params.bin")?;
    let public_inputs = load_bytes("public_inputs.bin")?;
    let proof = load_bytes("proof.bin")?;

    let verifier = RppStarkVerifier::new();
    assert!(verifier.is_ready(), "backend wiring should be complete");
    let report_first = verifier.verify_golden_vector(&params, &public_inputs, &proof)?;
    let report_second = verifier.verify_golden_vector(&params, &public_inputs, &proof)?;
    assert_eq!(
        report_first, report_second,
        "verifier reports must be deterministic across runs"
    );

    Ok(())
}
