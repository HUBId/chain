#![cfg(feature = "backend-plonky3")]

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

fn deterministic_transaction() -> SignedTransaction {
    let mut rng = StdRng::from_seed([23u8; 32]);
    let keypair = Keypair::generate(&mut rng);
    let sender = address_from_public_key(&keypair.public);
    let tx = Transaction::new(sender.clone(), sender, 17, 5, 0, None);
    let signature = keypair.sign(&tx.canonical_bytes());
    SignedTransaction::new(tx, signature, &keypair.public)
}

#[test]
fn transaction_roundtrip_produces_stable_commitment() {
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
    assert_eq!(
        parsed.verifying_key,
        crypto::verifying_key("transaction").unwrap()
    );
    assert!(!parsed.proof.is_empty());

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
