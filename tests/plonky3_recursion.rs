#![cfg(feature = "backend-plonky3")]

use ed25519_dalek::{Keypair, Signer};
use rand::SeedableRng;
use rand::rngs::StdRng;

use rpp_chain::crypto::address_from_public_key;
use rpp_chain::plonky3::crypto;
use rpp_chain::plonky3::proof::Plonky3Proof;
use rpp_chain::plonky3::prover::Plonky3Prover;
use rpp_chain::plonky3::verifier::Plonky3Verifier;
use rpp_chain::proof_system::{ProofProver, ProofVerifier};
use rpp_chain::rpp::GlobalStateCommitments;
use rpp_chain::types::{
    BlockProofBundle, ChainProof, PruningProof, SignedTransaction, Transaction,
};

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

    let pruning = PruningProof::genesis("prev");
    let pruning_witness = prover
        .build_pruning_witness(&[], &[], &pruning, Vec::new())
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

    // Recursive proof must reference all commitments from the bundle.
    if let ChainProof::Plonky3(value) = &bundle.recursive_proof {
        let parsed = Plonky3Proof::from_value(value).unwrap();
        assert_eq!(parsed.proof.len(), 64);
        assert_eq!(
            parsed.verifying_key,
            crypto::verifying_key("recursive").unwrap()
        );
        let commitments = value
            .get("public_inputs")
            .and_then(|inputs| inputs.get("commitments"))
            .and_then(|commitments| commitments.as_array())
            .cloned()
            .unwrap();
        let state_commitment = match &bundle.state_proof {
            ChainProof::Plonky3(state_value) => {
                Plonky3Proof::from_value(state_value).unwrap().commitment
            }
            ChainProof::Stwo(_) => panic!("expected Plonky3 state proof"),
        };
        assert!(
            commitments
                .iter()
                .any(|entry| entry.as_str() == Some(&state_commitment))
        );
    }
}
