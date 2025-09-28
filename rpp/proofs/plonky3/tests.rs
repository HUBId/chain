use ed25519_dalek::{Keypair, Signer};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde_json::Value;
use serde_json::json;

use crate::crypto::address_from_public_key;
use crate::plonky3::aggregation::RecursiveAggregator;
use crate::plonky3::prover::Plonky3Prover;
use crate::plonky3::verifier::Plonky3Verifier;
use crate::plonky3::{crypto, proof::Plonky3Proof};
use crate::proof_system::{ProofProver, ProofVerifier};
use crate::rpp::GlobalStateCommitments;
use crate::types::{BlockProofBundle, ChainProof, PruningProof, SignedTransaction, Transaction};

fn sample_transaction() -> SignedTransaction {
    let mut rng = StdRng::from_seed([7u8; 32]);
    let keypair = Keypair::generate(&mut rng);
    let from = address_from_public_key(&keypair.public);
    let tx = Transaction::new(from.clone(), from.clone(), 42, 1, 0, None);
    let signature = keypair.sign(&tx.canonical_bytes());
    SignedTransaction::new(tx, signature, &keypair.public)
}

#[test]
fn compute_commitment_is_stable_for_map_ordering() {
    let first: Value = serde_json::from_str(
        r#"{
            "outer": {
                "alpha": 1,
                "beta": {
                    "gamma": [
                        {"key": "value", "number": 7},
                        {"number": 8, "key": "other"}
                    ],
                    "delta": true
                }
            },
            "array": [
                {"x": 1, "y": 2},
                {"y": 3, "x": 4}
            ]
        }"#,
    )
    .unwrap();
    let second: Value = serde_json::from_str(
        r#"{
            "array": [
                {"y": 2, "x": 1},
                {"x": 4, "y": 3}
            ],
            "outer": {
                "beta": {
                    "delta": true,
                    "gamma": [
                        {"number": 7, "key": "value"},
                        {"key": "other", "number": 8}
                    ]
                },
                "alpha": 1
            }
        }"#,
    )
    .unwrap();

    let first_commitment = crypto::compute_commitment(&first).unwrap();
    let second_commitment = crypto::compute_commitment(&second).unwrap();

    assert_eq!(first_commitment, second_commitment);
}

#[test]
fn transaction_proof_roundtrip() {
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = sample_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    verifier.verify_transaction(&proof).unwrap();

    let parsed = match &proof {
        ChainProof::Plonky3(value) => Plonky3Proof::from_value(value).unwrap(),
        ChainProof::Stwo(_) => panic!("expected Plonky3 proof"),
    };
    assert_eq!(
        parsed.verifying_key,
        crypto::verifying_key("transaction").unwrap()
    );
    assert_eq!(parsed.proof.len(), 64);
    let computed = crypto::compute_commitment(&parsed.public_inputs).unwrap();
    assert_eq!(parsed.commitment, computed);
    let decoded: crate::plonky3::circuit::transaction::TransactionWitness = serde_json::from_value(
        parsed
            .public_inputs
            .get("witness")
            .cloned()
            .expect("transaction witness"),
    )
    .unwrap();
    assert_eq!(decoded.transaction, tx);
}

#[test]
fn recursive_aggregator_rejects_tampered_inputs() {
    let prover = Plonky3Prover::new();
    let tx = sample_transaction();
    let good_proof = prover
        .prove_transaction(prover.build_transaction_witness(&tx).unwrap())
        .unwrap();

    let mut tampered = good_proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        if let Some(object) = value.as_object_mut() {
            object.insert("commitment".into(), json!("deadbeef"));
        }
    }

    let aggregator = RecursiveAggregator::new(1, vec![tampered]);
    assert!(aggregator.finalize().is_err());

    let aggregator = RecursiveAggregator::new(1, vec![good_proof]);
    assert!(aggregator.finalize().is_ok());
}

#[test]
fn recursive_bundle_verification_detects_tampering() {
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = sample_transaction();
    let transaction_proof = prover
        .prove_transaction(prover.build_transaction_witness(&tx).unwrap())
        .unwrap();
    let state_inputs = json!({"witness": {"state_root": "abc"}});
    let state_proof = ChainProof::Plonky3(
        Plonky3Proof::new("state", state_inputs)
            .unwrap()
            .into_value()
            .unwrap(),
    );
    let pruning_inputs = json!({"witness": {"pruned": []}});
    let pruning_proof = ChainProof::Plonky3(
        Plonky3Proof::new("pruning", pruning_inputs)
            .unwrap()
            .into_value()
            .unwrap(),
    );
    let recursive_value = RecursiveAggregator::new(
        42,
        vec![
            transaction_proof.clone(),
            state_proof.clone(),
            pruning_proof.clone(),
        ],
    )
    .finalize()
    .unwrap()
    .into_value()
    .unwrap();
    let recursive_proof = ChainProof::Plonky3(recursive_value);

    let bundle = BlockProofBundle::new(
        vec![transaction_proof.clone()],
        state_proof.clone(),
        pruning_proof.clone(),
        recursive_proof.clone(),
    );
    verifier.verify_bundle(&bundle, None).unwrap();

    let mut bad_key_bundle = bundle.clone();
    if let ChainProof::Plonky3(value) = &mut bad_key_bundle.recursive_proof {
        if let Some(object) = value.as_object_mut() {
            object.insert("verifying_key".into(), json!("00"));
        }
    }
    assert!(verifier.verify_bundle(&bad_key_bundle, None).is_err());

    let mut tampered = recursive_proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        if let Some(object) = value.as_object_mut() {
            object.insert("commitment".into(), json!("deadbeef"));
        }
    }
    let tampered_bundle = BlockProofBundle::new(
        vec![transaction_proof],
        state_proof,
        pruning_proof,
        tampered,
    );
    assert!(verifier.verify_bundle(&tampered_bundle, None).is_err());
}

#[test]
fn recursive_roundtrip_spans_state_and_transactions() {
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();

    let tx = sample_transaction();
    let transaction_proof = prover
        .prove_transaction(prover.build_transaction_witness(&tx).unwrap())
        .unwrap();

    let state_witness = prover
        .build_state_witness("prev", "next", &[], &[tx.clone()])
        .unwrap();
    let state_proof = prover.prove_state_transition(state_witness).unwrap();

    let pruning = PruningProof::genesis("prev");
    let pruning_witness = prover
        .build_pruning_witness(&[], &[], &pruning, Vec::new())
        .unwrap();
    let pruning_proof = prover.prove_pruning(pruning_witness).unwrap();

    let recursive_witness = prover
        .build_recursive_witness(
            None,
            &[],
            &[transaction_proof.clone()],
            &[],
            &[],
            &GlobalStateCommitments::default(),
            &state_proof,
            &pruning_proof,
            7,
        )
        .unwrap();
    let recursive_proof = prover.prove_recursive(recursive_witness).unwrap();

    verifier.verify_transaction(&transaction_proof).unwrap();
    verifier.verify_state(&state_proof).unwrap();
    verifier.verify_pruning(&pruning_proof).unwrap();
    verifier.verify_recursive(&recursive_proof).unwrap();

    let bundle = BlockProofBundle::new(
        vec![transaction_proof.clone()],
        state_proof.clone(),
        pruning_proof.clone(),
        recursive_proof.clone(),
    );
    verifier.verify_bundle(&bundle, None).unwrap();

    // Tampering with any sub-proof now causes the bundle verification to fail.
    let mut broken_state = state_proof.clone();
    if let ChainProof::Plonky3(value) = &mut broken_state {
        if let Some(object) = value.as_object_mut() {
            object.insert("proof".into(), json!("ZG9nZ29nb28="));
        }
    }
    let broken_bundle = BlockProofBundle::new(
        vec![transaction_proof],
        broken_state,
        pruning_proof,
        recursive_proof,
    );
    assert!(verifier.verify_bundle(&broken_bundle, None).is_err());
}
