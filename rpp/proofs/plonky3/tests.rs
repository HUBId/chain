use blake3::hash as blake3_hash;
use ed25519_dalek::{Keypair, Signer};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::json;
use serde_json::Value;

use crate::crypto::address_from_public_key;
use crate::plonky3::circuit::pruning::PruningWitness;
use crate::plonky3::prover::Plonky3Prover;
use crate::plonky3::verifier::Plonky3Verifier;
use crate::plonky3::{crypto, proof::Plonky3Proof};
use crate::proof_system::{ProofProver, ProofVerifier};
use crate::rpp::GlobalStateCommitments;
use crate::types::{
    BlockHeader, BlockProofBundle, ChainProof, PruningProof, SignedTransaction, Transaction,
    pruning_from_previous,
};
use rpp_pruning::Envelope;

fn enable_experimental_backend() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| crate::plonky3::experimental::force_enable_for_tests());
}

fn test_prover() -> Plonky3Prover {
    enable_experimental_backend();
    Plonky3Prover::new()
}

fn test_verifier() -> Plonky3Verifier {
    enable_experimental_backend();
    Plonky3Verifier::default()
}

fn canonical_pruning_header() -> BlockHeader {
    BlockHeader::new(
        0,
        "00".repeat(32),
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32),
        "44".repeat(32),
        "55".repeat(32),
        "66".repeat(32),
        "77".repeat(32),
        "0".to_string(),
        "88".repeat(32),
        "99".repeat(32),
        "aa".repeat(32),
        "bb".repeat(64),
        format!("0x{}", "cc".repeat(20)),
        "TL1".to_string(),
        0,
    )
}

fn sample_transaction() -> SignedTransaction {
    let mut rng = StdRng::from_seed([7u8; 32]);
    let keypair = Keypair::generate(&mut rng);
    let from = address_from_public_key(&keypair.public);
    let tx = Transaction::new(from.clone(), from.clone(), 42, 1, 0, None);
    let signature = keypair.sign(&tx.canonical_bytes());
    SignedTransaction::new(tx, signature, &keypair.public)
}

fn sample_pruning_artifacts(prover: &Plonky3Prover) -> (PruningProof, ChainProof) {
    let header = canonical_pruning_header();
    let pruning_envelope = pruning_from_previous(None, &header);
    let witness = prover
        .build_pruning_witness(None, &[], &[], pruning_envelope.as_ref(), Vec::new())
        .unwrap();
    let proof = prover.prove_pruning(witness).unwrap();
    (pruning_envelope, proof)
}

fn extract_pruning_witness(proof: &ChainProof) -> PruningWitness {
    match proof {
        ChainProof::Plonky3(value) => {
            let parsed = Plonky3Proof::from_value(value).expect("parse pruning proof");
            let witness_value = parsed
                .public_inputs
                .get("witness")
                .cloned()
                .expect("pruning witness payload");
            serde_json::from_value(witness_value).expect("decode pruning witness")
        }
        ChainProof::Stwo(_) => panic!("expected Plonky3 pruning proof"),
    }
}

fn assert_pruning_matches_envelope(witness: &PruningWitness, envelope: &Envelope) {
    assert_eq!(witness.snapshot, envelope.snapshot().clone());
    assert_eq!(witness.segments, envelope.segments().to_vec());
    assert_eq!(
        witness.commitment.schema_version(),
        envelope.commitment().schema_version()
    );
    assert_eq!(
        witness.commitment.parameter_version(),
        envelope.commitment().parameter_version()
    );
    assert_eq!(
        witness.commitment.aggregate_commitment(),
        envelope.commitment().aggregate_commitment()
    );
    assert_eq!(witness.binding_digest, envelope.binding_digest());
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
    let prover = test_prover();
    let verifier = test_verifier();
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
    assert_eq!(parsed.proof.len(), crypto::PROOF_BLOB_LEN);
    let verifying_hash = blake3_hash(&parsed.verifying_key);
    assert_eq!(&parsed.proof[..32], verifying_hash.as_bytes());
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
    let prover = test_prover();
    let tx = sample_transaction();
    let transaction_proof = prover
        .prove_transaction(prover.build_transaction_witness(&tx).unwrap())
        .unwrap();

    let state_inputs = json!({"witness": {"state_root": "alpha"}});
    let state_proof = ChainProof::Plonky3(
        Plonky3Proof::new("state", state_inputs)
            .unwrap()
            .into_value()
            .unwrap(),
    );
    let (pruning_envelope, pruning_proof) = sample_pruning_artifacts(&prover);
    let pruning_witness = extract_pruning_witness(&pruning_proof);
    assert_pruning_matches_envelope(&pruning_witness, pruning_envelope.as_ref());

    let mut tampered = transaction_proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        if let Some(object) = value.as_object_mut() {
            object.insert("commitment".into(), json!("deadbeef"));
        }
    }

    let tampered_witness = prover
        .build_recursive_witness(
            None,
            &[],
            &[tampered.clone()],
            &[],
            &[],
            &GlobalStateCommitments::default(),
            &state_proof,
            pruning_envelope.as_ref(),
            &pruning_proof,
            1,
        )
        .unwrap();
    assert!(prover.prove_recursive(tampered_witness).is_err());

    let valid_witness = prover
        .build_recursive_witness(
            None,
            &[],
            &[transaction_proof.clone()],
            &[],
            &[],
            &GlobalStateCommitments::default(),
            &state_proof,
            pruning_envelope.as_ref(),
            &pruning_proof,
            1,
        )
        .unwrap();
    assert!(prover.prove_recursive(valid_witness).is_ok());
}

#[test]
fn recursive_bundle_verification_detects_tampering() {
    let prover = test_prover();
    let verifier = test_verifier();
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
    let (pruning_envelope, pruning_proof) = sample_pruning_artifacts(&prover);
    let pruning_witness = extract_pruning_witness(&pruning_proof);
    assert_pruning_matches_envelope(&pruning_witness, pruning_envelope.as_ref());
    let recursive_witness = prover
        .build_recursive_witness(
            None,
            &[],
            &[transaction_proof.clone()],
            &[],
            &[],
            &GlobalStateCommitments::default(),
            &state_proof,
            pruning_envelope.as_ref(),
            &pruning_proof,
            42,
        )
        .unwrap();
    let recursive_proof = prover.prove_recursive(recursive_witness).unwrap();

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
            object.insert("verifying_key".into(), json!("AA=="));
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
    let prover = test_prover();
    let verifier = test_verifier();

    let tx = sample_transaction();
    let transaction_proof = prover
        .prove_transaction(prover.build_transaction_witness(&tx).unwrap())
        .unwrap();

    let state_witness = prover
        .build_state_witness("prev", "next", &[], &[tx.clone()])
        .unwrap();
    let state_proof = prover.prove_state_transition(state_witness).unwrap();

    let header = canonical_pruning_header();
    let pruning = pruning_from_previous(None, &header);
    let pruning_witness = prover
        .build_pruning_witness(None, &[], &[], pruning.as_ref(), Vec::new())
        .unwrap();
    let pruning_proof = prover.prove_pruning(pruning_witness).unwrap();
    let pruning_witness = extract_pruning_witness(&pruning_proof);
    assert_pruning_matches_envelope(&pruning_witness, pruning.as_ref());

    let recursive_witness = prover
        .build_recursive_witness(
            None,
            &[],
            &[transaction_proof.clone()],
            &[],
            &[],
            &GlobalStateCommitments::default(),
            &state_proof,
            pruning.as_ref(),
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
