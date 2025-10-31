#![cfg(feature = "prover-stwo")]

use prover_stwo_backend::backend::StwoBackend;
use rpp_chain::errors::ChainError;
use rpp_chain::proof_backend::ProofBytes;
use rpp_chain::proof_system::ProofVerifierRegistry;
use rpp_chain::runtime::types::proofs::ChainProof;

use super::fixture;

fn registry() -> ProofVerifierRegistry {
    ProofVerifierRegistry::new()
}

fn prove_transaction() -> (ProofBytes, ChainProof, prover_backend_interface::TxPublicInputs) {
    let backend = StwoBackend::new();
    let (proof_bytes, header, proof, inputs) = fixture::prove_fixture(&backend);
    fixture::assert_proof_header(&header);
    let chain = ChainProof::Stwo(proof.clone());
    (proof_bytes, chain, inputs)
}

#[test]
fn wallet_fixture_verifies_via_registry() {
    let (proof_bytes, chain_proof, inputs) = prove_transaction();
    let registry = registry();
    registry
        .verify_stwo_proof_bytes(&proof_bytes, &inputs)
        .expect("raw proof bytes should verify");
    registry
        .verify_transaction(&chain_proof)
        .expect("chain proof should verify");
}

#[test]
fn tampered_public_inputs_are_rejected() {
    let (proof_bytes, _, mut inputs) = prove_transaction();
    inputs.transaction_commitment[0] ^= 0xFF;

    let registry = registry();
    let error = registry.verify_stwo_proof_bytes(&proof_bytes, &inputs);
    match error {
        Err(ChainError::Crypto(message)) => {
            assert!(
                message.contains("public input"),
                "error should point to mismatched public inputs: {message}",
            );
        }
        other => panic!("expected crypto error for tampered inputs, got {other:?}"),
    }
}
