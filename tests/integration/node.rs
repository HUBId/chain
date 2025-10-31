#![cfg(feature = "prover-stwo")]

use rpp_chain::errors::ChainError;
use rpp_chain::proof_system::ProofVerifierRegistry;
use rpp_chain::runtime::types::proofs::ChainProof;

use super::fixture;

#[test]
fn node_verifier_rejects_mutated_witness_payload() {
    let (_, _, proof, _) = fixture::prove_fixture(&prover_stwo_backend::backend::StwoBackend::new());
    let mut tampered = proof.clone();
    fixture::tamper_transaction_amount(&mut tampered);
    let registry = ProofVerifierRegistry::new();

    let error = registry.verify_transaction(&ChainProof::Stwo(tampered));
    match error {
        Err(ChainError::Crypto(message)) => {
            assert!(
                message.contains("witness"),
                "tampering should surface as a witness integrity error: {message}",
            );
        }
        other => panic!("expected crypto error for tampered witness, got {other:?}"),
    }
}

#[test]
fn node_verifier_accepts_pristine_fixture() {
    let (_, _, proof, _) = fixture::prove_fixture(&prover_stwo_backend::backend::StwoBackend::new());
    let registry = ProofVerifierRegistry::new();
    registry
        .verify_transaction(&ChainProof::Stwo(proof))
        .expect("fixture proof should verify without mutation");
}
