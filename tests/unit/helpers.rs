#![cfg(feature = "prover-stwo")]

use rpp_chain::errors::ChainResult;
use rpp_chain::rpp::ProofSystemKind;
use rpp_chain::runtime::types::proofs::ChainProof;

use super::fixture;

#[test]
fn chain_proof_roundtrip_preserves_payload() -> ChainResult<()> {
    let proof = fixture::load_proof();
    let chain_proof = ChainProof::Stwo(proof.clone());
    assert_eq!(chain_proof.system(), ProofSystemKind::Stwo);

    let serialized = serde_json::to_value(&chain_proof).expect("chain proof serializes");
    let restored: ChainProof = serde_json::from_value(serialized).expect("chain proof deserializes");
    let recovered = restored.expect_stwo()?;
    assert_eq!(recovered.payload, proof.payload);
    Ok(())
}

#[test]
fn stwo_fixture_can_be_recovered_from_chain_proof() -> ChainResult<()> {
    let (_, _, proof, _) = fixture::prove_fixture(&prover_stwo_backend::backend::StwoBackend::new());
    let chain_proof = ChainProof::Stwo(proof.clone());
    let recovered = chain_proof.into_stwo()?;
    assert_eq!(recovered.commitment, proof.commitment);
    Ok(())
}
