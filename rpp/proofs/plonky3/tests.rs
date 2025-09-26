use ed25519_dalek::{Keypair, Signer};
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde_json::json;

use crate::crypto::address_from_public_key;
use crate::plonky3::aggregation::RecursiveAggregator;
use crate::plonky3::prover::Plonky3Prover;
use crate::plonky3::verifier::Plonky3Verifier;
use crate::plonky3::{crypto, proof::Plonky3Proof};
use crate::proof_system::{ProofProver, ProofVerifier};
use crate::types::{BlockProofBundle, ChainProof, SignedTransaction, Transaction};

fn sample_transaction() -> SignedTransaction {
    let mut rng = StdRng::from_seed([7u8; 32]);
    let keypair = Keypair::generate(&mut rng);
    let from = address_from_public_key(&keypair.public);
    let tx = Transaction::new(from.clone(), from.clone(), 42, 1, 0, None);
    let signature = keypair.sign(&tx.canonical_bytes());
    SignedTransaction::new(tx, signature, &keypair.public)
}

#[test]
fn transaction_proof_roundtrip() {
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();
    let tx = sample_transaction();
    let witness = prover.build_transaction_witness(&tx).unwrap();
    let proof = prover.prove_transaction(witness).unwrap();

    verifier.verify_transaction(&proof).unwrap();

    let value = match &proof {
        ChainProof::Plonky3(value) => value,
        ChainProof::Stwo(_) => panic!("expected Plonky3 proof"),
    };
    let commitment = value.get("commitment").and_then(|v| v.as_str()).unwrap();
    let public_inputs = value.get("public_inputs").unwrap();
    let computed = crypto::compute_commitment(public_inputs).unwrap();
    assert_eq!(commitment, computed);
    let decoded: crate::plonky3::circuit::transaction::TransactionWitness =
        serde_json::from_value(public_inputs.get("witness").unwrap().clone()).unwrap();
    assert_eq!(decoded.transaction, tx);
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
