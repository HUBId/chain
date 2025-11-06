#![cfg(feature = "backend-plonky3")]

//! End-to-end Plonky3 transaction tests that mirror wallet flows.
//!
//! Proofs are generated with deterministic RNG seeds so CI observes the same
//! commitments and proof blobs across runs.

use ed25519_dalek::{Keypair, Signer};
use plonky3_backend::HashFormat;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rpp_chain::crypto::address_from_public_key;
use rpp_chain::plonky3::circuit::transaction::{TransactionCircuit, TransactionWitness};
use rpp_chain::plonky3::crypto;
use rpp_chain::plonky3::experimental::force_enable_for_tests;
use rpp_chain::plonky3::params::Plonky3Parameters;
use rpp_chain::plonky3::proof::Plonky3Proof;
use rpp_chain::plonky3::prover::Plonky3Prover;
use rpp_chain::plonky3::public_inputs;
use rpp_chain::plonky3::verifier::Plonky3Verifier;
use rpp_chain::proof_system::{ProofProver, ProofVerifier};
use rpp_chain::types::{ChainProof, SignedTransaction, Transaction};
use std::convert::TryInto;

const TRANSACTION_SEED: [u8; 32] = [23u8; 32];

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
    force_enable_for_tests();
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

    let (commitment, _, canonical_bytes) =
        public_inputs::compute_commitment_and_inputs(&parsed.public_inputs).unwrap();
    assert_eq!(commitment, parsed.commitment);
    assert_eq!(
        parsed.payload.metadata.canonical_public_inputs,
        canonical_bytes
    );

    let canonical_inputs: serde_json::Value =
        serde_json::from_slice(&parsed.payload.metadata.canonical_public_inputs).unwrap();
    assert_eq!(canonical_inputs, parsed.public_inputs);

    let witness_value = parsed
        .public_inputs
        .get("witness")
        .cloned()
        .expect("witness payload");
    let decoded: TransactionWitness = serde_json::from_value(witness_value).unwrap();
    assert_eq!(decoded.transaction, tx);

    let params = Plonky3Parameters::default();
    assert_eq!(parsed.payload.metadata.security_bits, params.security_bits);
    assert_eq!(parsed.payload.metadata.use_gpu, params.use_gpu_acceleration);
    assert!(
        parsed.payload.metadata.derived_security_bits >= params.security_bits,
        "derived security cannot undershoot negotiated security"
    );

    assert_eq!(
        parsed.payload.metadata.hash_format,
        HashFormat::PoseidonMerkleCap
    );
    assert!(
        !parsed.payload.metadata.transcript.checkpoints.is_empty(),
        "transaction proofs must expose challenger checkpoints"
    );
    assert!(
        !parsed.payload.metadata.fri_commitments.is_empty(),
        "transaction proofs must record FRI commit-phase digests"
    );

    let expected_params = TransactionCircuit::PARAMS;
    assert_eq!(
        parsed.payload.metadata.trace_commitment, expected_params.domain_root,
        "trace commitment must match fixture domain digest"
    );
    assert_eq!(
        parsed.payload.metadata.quotient_commitment, expected_params.quotient_root,
        "quotient commitment must match fixture quotient digest"
    );
    assert_eq!(
        parsed
            .payload
            .metadata
            .fri_commitments
            .first()
            .copied()
            .expect("fri digest"),
        expected_params.fri_digest,
        "FRI digest must match fixture transcript digest"
    );

    assert!(matches!(parsed.public_inputs.get("block_height"), None));
    assert!(matches!(parsed.public_inputs.get("commitments"), None));
}

#[test]
fn transaction_roundtrip_rejects_tampered_public_inputs() {
    force_enable_for_tests();
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
    force_enable_for_tests();
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = deterministic_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut tampered = proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        let backend_proof = parsed
            .payload
            .to_backend(&parsed.circuit)
            .expect("decode backend proof");
        let mut truncated = backend_proof.serialized_proof().to_vec();
        truncated.truncate(truncated.len().saturating_sub(1));
        parsed.payload.stark_proof = truncated;
        *value = parsed.into_value().unwrap();
    }

    assert!(verifier.verify_transaction(&tampered).is_err());
}

#[test]
fn transaction_roundtrip_rejects_wrong_verifying_key() {
    force_enable_for_tests();
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = deterministic_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut tampered = proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed.payload.metadata.trace_commitment[0] ^= 0x40;
        if let Some(first) = parsed.payload.metadata.fri_commitments.first_mut() {
            first[0] ^= 0x80;
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
    force_enable_for_tests();
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
    force_enable_for_tests();
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = deterministic_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    let mut tampered = proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        let backend_proof = parsed
            .payload
            .to_backend(&parsed.circuit)
            .expect("decode backend proof");
        let mut expanded = backend_proof.serialized_proof().to_vec();
        expanded.push(0);
        parsed.payload.stark_proof = expanded;
        *value = parsed.into_value().unwrap();
    }

    let err = verifier.verify_transaction(&tampered).unwrap_err();
    assert!(
        err.to_string().contains("proof payload must be"),
        "unexpected verifier error: {err:?}"
    );
}
