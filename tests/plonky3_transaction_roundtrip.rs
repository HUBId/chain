#![cfg(feature = "backend-plonky3")]

//! End-to-end Plonky3 transaction tests that mirror wallet flows.
//!
//! Proofs are generated with deterministic RNG seeds so CI observes the same
//! commitments and proof blobs across runs.

use ed25519_dalek::{Keypair, Signer};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rpp_chain::crypto::address_from_public_key;
use rpp_chain::plonky3::crypto;
use rpp_chain::plonky3::proof::Plonky3Proof;
use rpp_chain::plonky3::prover::Plonky3Prover;
use rpp_chain::plonky3::verifier::Plonky3Verifier;
use rpp_chain::proof_system::{ProofProver, ProofVerifier};
use rpp_chain::types::{ChainProof, SignedTransaction, Transaction};

const TRANSACTION_SEED: [u8; 32] = [23u8; 32];

fn enable_experimental_backend() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| rpp_chain::plonky3::experimental::force_enable_for_tests());
}

fn deterministic_transaction() -> SignedTransaction {
    let mut rng = StdRng::from_seed(TRANSACTION_SEED);
    let keypair = Keypair::generate(&mut rng);
    let sender = address_from_public_key(&keypair.public);
    let tx = Transaction::new(sender.clone(), sender, 17, 5, 0, None);
    let signature = keypair.sign(&tx.canonical_bytes());
    SignedTransaction::new(tx, signature, &keypair.public)
}

#[test]
fn transaction_roundtrip_produces_stable_commitment() {
    enable_experimental_backend();
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = deterministic_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    verifier.verify_transaction(&proof).unwrap();

    let value = match &proof {
        ChainProof::Plonky3(value) => value,
        ChainProof::Stwo(_) => panic!("expected Plonky3 proof"),
    };
    let parsed = Plonky3Proof::from_value(value).unwrap();
    assert_eq!(parsed.circuit, "transaction");
    let verifying_key = crypto::verifying_key("transaction").unwrap();
    let verifying_hash = blake3::hash(&verifying_key);
    assert!(!parsed.payload.proof_blob.is_empty());
    assert_eq!(
        parsed.payload.metadata.verifying_key_hash,
        *verifying_hash.as_bytes()
    );

    let commitment = crypto::compute_commitment(&parsed.public_inputs).unwrap();
    assert_eq!(commitment, parsed.commitment);

    let witness_value = parsed
        .public_inputs
        .get("witness")
        .cloned()
        .expect("witness payload");
    let decoded: rpp_chain::plonky3::circuit::transaction::TransactionWitness =
        serde_json::from_value(witness_value).unwrap();
    assert_eq!(decoded.transaction, tx);

    assert!(matches!(parsed.public_inputs.get("block_height"), None));
    assert!(matches!(parsed.public_inputs.get("commitments"), None));
}

#[test]
fn transaction_roundtrip_rejects_tampered_public_inputs() {
    enable_experimental_backend();
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = deterministic_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut tampered = proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        if let serde_json::Value::Object(ref mut root) = parsed.public_inputs {
            if let Some(serde_json::Value::Object(witness)) = root.get_mut("witness") {
                if let Some(serde_json::Value::Object(tx)) = witness.get_mut("transaction") {
                    if let Some(serde_json::Value::Object(payload)) = tx.get_mut("payload") {
                        payload.insert("amount".to_string(), serde_json::json!(404));
                    }
                }
            }
        }
        *value = parsed.into_value().unwrap();
    }

    assert!(verifier.verify_transaction(&tampered).is_err());
}

#[test]
fn transaction_roundtrip_rejects_truncated_proof() {
    enable_experimental_backend();
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = deterministic_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut tampered = proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed
            .payload
            .proof_blob
            .truncate(parsed.payload.proof_blob.len().saturating_sub(1));
        *value = parsed.into_value().unwrap();
    }

    assert!(verifier.verify_transaction(&tampered).is_err());
}

#[test]
fn transaction_roundtrip_rejects_wrong_verifying_key() {
    enable_experimental_backend();
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = deterministic_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut tampered = proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed.payload.metadata.verifying_key_hash[0] ^= 0x40;
        if let Some(first) = parsed.payload.proof_blob.first_mut() {
            *first ^= 0x02;
        }
        *value = parsed.into_value().unwrap();
    }

    let err = verifier.verify_transaction(&tampered).unwrap_err();
    assert!(
        err.to_string().contains("verifying key mismatch"),
        "unexpected verifier error: {err:?}"
    );
}

#[test]
fn transaction_roundtrip_rejects_mismatched_commitment() {
    enable_experimental_backend();
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = deterministic_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut tampered = proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        if let Some(object) = value.as_object_mut() {
            object.insert("commitment".into(), serde_json::json!("deadbeef"));
        }
    }

    let err = verifier.verify_transaction(&tampered).unwrap_err();
    assert!(
        err.to_string().contains("commitment mismatch"),
        "unexpected verifier error: {err:?}"
    );
}

#[test]
fn transaction_roundtrip_rejects_oversized_proof() {
    enable_experimental_backend();
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = deterministic_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut tampered = proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed.payload.proof_blob.push(0);
        *value = parsed.into_value().unwrap();
    }

    let err = verifier.verify_transaction(&tampered).unwrap_err();
    assert!(
        err.to_string().contains("proof blob must be"),
        "unexpected verifier error: {err:?}"
    );
}
