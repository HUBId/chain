#![cfg(feature = "backend-rpp-stark")]

use hex::FromHex;
use std::fs;
use std::path::{Path, PathBuf};

use rpp_chain::zk::rpp_adapter::{compute_public_digest, Digest32};
use rpp_chain::zk::rpp_verifier::{self, RppStarkVerifier};

const VECTORS_DIR: &str = "vendor/rpp-stark/vectors/stwo/mini";

fn vector_path(name: &str) -> PathBuf {
    Path::new(VECTORS_DIR).join(name)
}

fn load_bytes(name: &str) -> std::io::Result<Vec<u8>> {
    let contents = fs::read_to_string(vector_path(name))?;
    Vec::from_hex(contents.trim())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
}

fn load_hex_digest(name: &str) -> std::io::Result<String> {
    let contents = fs::read_to_string(vector_path(name))?;
    Ok(contents.trim().to_lowercase())
}

#[test]
fn interop_verify_golden_vector_ok() -> anyhow::Result<()> {
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
    if verifier.is_ready() {
        let report = verifier.verify_golden_vector(&params, &public_inputs, &proof)?;
        assert_eq!(report.backend(), verifier.backend_name());
        assert!(report.is_verified(), "golden proof should verify");
    } else {
        let error = verifier
            .verify_golden_vector(&params, &public_inputs, &proof)
            .expect_err("stub verifier should report backend availability");
        assert!(matches!(
            error,
            rpp_verifier::RppStarkVerifierError::BackendUnavailable(_)
        ));
    }

    Ok(())
}

#[test]
fn interop_indices_match_and_are_sorted_unique() -> anyhow::Result<()> {
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

    let unique: std::collections::BTreeSet<_> = indices.iter().copied().collect();
    assert_eq!(unique.len(), indices.len(), "indices must be unique");

    Ok(())
}

#[test]
fn interop_repeatability_is_deterministic() -> anyhow::Result<()> {
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

    Ok(())
}
