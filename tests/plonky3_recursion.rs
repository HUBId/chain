#![cfg(feature = "backend-plonky3")]

use ed25519_dalek::{Keypair, Signer};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::Value;

use rpp_chain::crypto::address_from_public_key;
use rpp_chain::plonky3::crypto;
use rpp_chain::plonky3::proof::Plonky3Proof;
use rpp_chain::plonky3::prover::Plonky3Prover;
use rpp_chain::plonky3::verifier::Plonky3Verifier;
use rpp_chain::proof_system::{ProofProver, ProofVerifier};
use rpp_chain::rpp::GlobalStateCommitments;
use rpp_chain::types::{
    BlockHeader, BlockProofBundle, ChainProof, PruningProof, SignedTransaction, Transaction,
    canonical_pruning_from_block,
};

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
    let mut rng = StdRng::from_seed([13u8; 32]);
    let keypair = Keypair::generate(&mut rng);
    let from = address_from_public_key(&keypair.public);
    let tx = Transaction::new(from.clone(), from, 5, 1, 0, None);
    let signature = keypair.sign(&tx.canonical_bytes());
    SignedTransaction::new(tx, signature, &keypair.public)
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
    let pruning = canonical_pruning_from_block(None, &header)
        .expect("construct canonical pruning proof");
    let pruning_witness = prover
        .build_pruning_witness(None, &[], &[], &pruning, Vec::new())
        .unwrap();
    let pruning_proof = prover.prove_pruning(pruning_witness).unwrap();

    let recursive_witness = prover
        .build_recursive_witness(
            None,
            &[],
            &[tx_proof.clone()],
            &[],
            &[],
            &GlobalStateCommitments::default(),
            &state_proof,
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
        assert!(!parsed.proof.is_empty());
        assert_eq!(
            parsed.verifying_key,
            crypto::verifying_key("recursive").unwrap()
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
