#![cfg(feature = "backend-plonky3")]

//! Recursive Plonky3 proof flows backed by deterministic fixtures.
//!
//! The tests emulate wallet and node workflows spanning transaction, state,
//! pruning, consensus, and recursive proofs while covering negative cases such
//! as tampered witnesses and malformed proof blobs. Deterministic RNG seeds
//! keep the generated witnesses stable across CI runs.

use ed25519_dalek::{Keypair, Signer};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::Value;

#[path = "consensus/common.rs"]
mod consensus_common;

use consensus_common::{digest, metadata_fixture, vrf_entry};
use rpp_chain::consensus::ConsensusCertificate;
use rpp_chain::crypto::address_from_public_key;
use rpp_chain::plonky3::circuit::pruning::PruningWitness;
use rpp_chain::plonky3::crypto;
use rpp_chain::plonky3::proof::Plonky3Proof;
use rpp_chain::plonky3::prover::Plonky3Prover;
use rpp_chain::plonky3::verifier::Plonky3Verifier;
use rpp_chain::proof_system::{ProofProver, ProofVerifier};
use rpp_chain::rpp::GlobalStateCommitments;
use rpp_chain::types::{
    pruning_from_previous, BlockHeader, BlockProofBundle, ChainProof, PruningProof,
    SignedTransaction, Transaction,
};
const TRANSACTION_SEED: [u8; 32] = [13u8; 32];

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
    let mut rng = StdRng::from_seed(TRANSACTION_SEED);
    let keypair = Keypair::generate(&mut rng);
    let from = address_from_public_key(&keypair.public);
    let tx = Transaction::new(from.clone(), from, 5, 1, 0, None);
    let signature = keypair.sign(&tx.canonical_bytes());
    SignedTransaction::new(tx, signature, &keypair.public)
}

fn sample_consensus_certificate() -> ConsensusCertificate {
    let block_hash = "11".repeat(32);
    let metadata = metadata_fixture(
        vec![vrf_entry(0x44, 0x55)],
        vec![digest(0x66)],
        vec![digest(0x77)],
        5,
        7,
        digest(0x22),
        digest(0x33),
    );

    ConsensusCertificate {
        block_hash: block_hash.clone().into(),
        height: 3,
        round: 2,
        total_power: 100,
        quorum_threshold: 67,
        prevote_power: 67,
        precommit_power: 67,
        commit_power: 80,
        prevotes: Vec::new(),
        precommits: Vec::new(),
        metadata,
    }
}

fn recursive_artifacts_for_tests() -> (
    Plonky3Verifier,
    ChainProof,
    ChainProof,
    ChainProof,
    ChainProof,
) {
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

    let header = canonical_pruning_header();
    let pruning_envelope = pruning_from_previous(None, &header);
    let pruning_witness = prover
        .build_pruning_witness(None, &[], &[], pruning_envelope.as_ref(), Vec::new())
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
            pruning_envelope.as_ref(),
            &pruning_proof,
            9,
        )
        .unwrap();
    let recursive_proof = prover.prove_recursive(recursive_witness).unwrap();

    (
        verifier,
        transaction_proof,
        state_proof,
        pruning_proof,
        recursive_proof,
    )
}

#[test]
fn plonky3_recursive_flow_roundtrip() {
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();

    let tx = sample_transaction();
    let tx_proof = prover
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

    if let ChainProof::Plonky3(value) = &pruning_proof {
        let parsed = Plonky3Proof::from_value(value).unwrap();
        let witness_value = parsed
            .public_inputs
            .get("witness")
            .cloned()
            .expect("pruning witness payload");
        let recorded: PruningWitness = serde_json::from_value(witness_value).unwrap();
        assert_eq!(recorded.snapshot, pruning.snapshot().clone());
        assert_eq!(recorded.segments, pruning.segments().to_vec());
        assert_eq!(
            recorded.commitment.schema_version(),
            pruning.commitment().schema_version()
        );
        assert_eq!(
            recorded.commitment.parameter_version(),
            pruning.commitment().parameter_version()
        );
        assert_eq!(
            recorded.commitment.aggregate_commitment(),
            pruning.commitment().aggregate_commitment()
        );
        assert_eq!(recorded.binding_digest, pruning.binding_digest());
        assert!(recorded.removed_transactions.is_empty());
    } else {
        panic!("expected pruning proof to use Plonky3 backend");
    }

    let recursive_witness = prover
        .build_recursive_witness(
            None,
            &[],
            &[tx_proof.clone()],
            &[],
            &[],
            &GlobalStateCommitments::default(),
            &state_proof,
            pruning.as_ref(),
            &pruning_proof,
            9,
        )
        .unwrap();
    let recursive_proof = prover.prove_recursive(recursive_witness).unwrap();

    verifier.verify_transaction(&tx_proof).unwrap();
    verifier.verify_state(&state_proof).unwrap();
    verifier.verify_pruning(&pruning_proof).unwrap();
    verifier.verify_recursive(&recursive_proof).unwrap();

    let bundle = BlockProofBundle::new(
        vec![tx_proof.clone()],
        state_proof.clone(),
        pruning_proof.clone(),
        recursive_proof.clone(),
    );
    verifier.verify_bundle(&bundle, None).unwrap();

    // Recursive proof must embed the same sub-proofs inside its witness payload.
    if let ChainProof::Plonky3(value) = &bundle.recursive_proof {
        let parsed = Plonky3Proof::from_value(value).unwrap();
        assert!(!parsed.payload.proof_blob.is_empty());
        let verifying_key = crypto::verifying_key("recursive").unwrap();
        let verifying_hash = blake3::hash(&verifying_key);
        assert_eq!(
            parsed.payload.metadata.verifying_key_hash,
            *verifying_hash.as_bytes()
        );
        let public_inputs = value
            .get("public_inputs")
            .cloned()
            .expect("recursive public inputs");
        let block_height = public_inputs
            .get("block_height")
            .and_then(Value::as_u64)
            .expect("recursive block height");
        assert_eq!(block_height, 9);
        let witness_value = public_inputs
            .get("witness")
            .cloned()
            .expect("recursive witness payload");
        let recorded: crate::plonky3::circuit::recursive::RecursiveWitness =
            serde_json::from_value(witness_value).unwrap();
        assert_eq!(recorded.block_height, 9);
        assert!(recorded
            .transaction_proofs
            .iter()
            .any(|proof| proof == &tx_proof));
        assert_eq!(recorded.state_proof, bundle.state_proof);
        assert_eq!(recorded.pruning_proof, bundle.pruning_proof);
    }
}

#[test]
fn recursive_bundle_rejects_wrong_verifying_key() {
    let (verifier, transaction_proof, state_proof, pruning_proof, recursive_proof) =
        recursive_artifacts_for_tests();

    let mut tampered = recursive_proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed.payload.metadata.verifying_key_hash[0] ^= 0x08;
        if let Some(first) = parsed.payload.proof_blob.first_mut() {
            *first ^= 0x01;
        }
        *value = parsed.into_value().unwrap();
    }

    let bundle = BlockProofBundle::new(
        vec![transaction_proof.clone()],
        state_proof.clone(),
        pruning_proof.clone(),
        tampered.clone(),
    );

    assert!(verifier.verify_recursive(&tampered).is_err());
    assert!(verifier.verify_bundle(&bundle, None).is_err());
}

#[test]
fn recursive_bundle_rejects_commitment_mismatch() {
    let (verifier, transaction_proof, state_proof, pruning_proof, recursive_proof) =
        recursive_artifacts_for_tests();

    let mut tampered = recursive_proof.clone();
    if let ChainProof::Plonky3(value) = &mut tampered {
        if let Some(object) = value.as_object_mut() {
            object.insert("commitment".into(), serde_json::json!("deadbeef"));
        }
    }

    let bundle = BlockProofBundle::new(
        vec![transaction_proof.clone()],
        state_proof.clone(),
        pruning_proof.clone(),
        tampered.clone(),
    );

    assert!(verifier.verify_recursive(&tampered).is_err());
    assert!(verifier.verify_bundle(&bundle, None).is_err());
}

#[test]
fn recursive_bundle_rejects_oversized_proof_blob() {
    let (verifier, transaction_proof, state_proof, pruning_proof, recursive_proof) =
        recursive_artifacts_for_tests();

    let mut oversized = recursive_proof.clone();
    if let ChainProof::Plonky3(value) = &mut oversized {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed.payload.proof_blob.push(0);
        *value = parsed.into_value().unwrap();
    }

    let bundle = BlockProofBundle::new(
        vec![transaction_proof.clone()],
        state_proof.clone(),
        pruning_proof.clone(),
        oversized.clone(),
    );

    assert!(verifier.verify_recursive(&oversized).is_err());
    assert!(verifier.verify_bundle(&bundle, None).is_err());
}

#[test]
fn consensus_proof_roundtrip_catches_tampering() {
    let prover = Plonky3Prover::new();
    let verifier = Plonky3Verifier::default();

    let certificate = sample_consensus_certificate();
    let block_hash = certificate.block_hash.0.clone();
    let witness = prover
        .build_consensus_witness(&block_hash, &certificate)
        .unwrap();
    let proof = prover.prove_consensus(witness).unwrap();

    verifier.verify_consensus(&proof).unwrap();

    let mut wrong_key = proof.clone();
    if let ChainProof::Plonky3(value) = &mut wrong_key {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed.payload.metadata.verifying_key_hash[0] ^= 0x04;
        if let Some(first) = parsed.payload.proof_blob.first_mut() {
            *first ^= 0x01;
        }
        *value = parsed.into_value().unwrap();
    }
    assert!(verifier.verify_consensus(&wrong_key).is_err());

    let mut mismatched_commitment = proof.clone();
    if let ChainProof::Plonky3(value) = &mut mismatched_commitment {
        if let Some(object) = value.as_object_mut() {
            object.insert("commitment".into(), serde_json::json!("deadbeef"));
        }
    }
    assert!(verifier.verify_consensus(&mismatched_commitment).is_err());

    let mut oversized = proof;
    if let ChainProof::Plonky3(value) = &mut oversized {
        let mut parsed = Plonky3Proof::from_value(value).unwrap();
        parsed.payload.proof_blob.push(0);
        *value = parsed.into_value().unwrap();
    }
    assert!(verifier.verify_consensus(&oversized).is_err());
}
