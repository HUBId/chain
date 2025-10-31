#![cfg(feature = "prover-stwo")]

use prover_backend_interface::TxCircuitDef;
use prover_stwo_backend::backend::StwoBackend;
use prover_stwo_backend::official::proof::StarkProof;

use super::fixture;

#[test]
fn transaction_fixture_roundtrips_through_backend() {
    let backend = StwoBackend::new();
    let circuit = TxCircuitDef::new(fixture::TX_CIRCUIT_ID);
    let (proving_key, verifying_key) = backend
        .keygen_tx(&circuit)
        .expect("key generation succeeds");

    let witness_bytes = fixture::witness_bytes();
    let (witness_header, decoded_witness) = fixture::decode_witness_bytes(&witness_bytes);
    fixture::assert_witness_header(&witness_header);
    assert_eq!(
        decoded_witness,
        fixture::witness(),
        "fixture witness should round-trip through serialization",
    );

    let (proof_bytes, proof_header, decoded_proof, expected_inputs) =
        fixture::prove_fixture(&backend);
    fixture::assert_proof_header(&proof_header);
    fixture::assert_transaction_payload(&decoded_proof, &decoded_witness);

    let reconstructed_inputs = fixture::inputs_from_fields(&decoded_proof.public_inputs);
    assert_eq!(
        reconstructed_inputs, expected_inputs,
        "public inputs derived from the proof should match the fixture",
    );

    let verified = backend
        .verify_tx(&verifying_key, &proof_bytes, &expected_inputs)
        .expect("verification succeeds for fixture proof");
    assert!(verified, "backend verification should return true");
}

#[test]
fn transaction_commitment_is_deterministic() {
    let backend = StwoBackend::new();
    let (_, _, proof, _) = fixture::prove_fixture(&backend);
    let repeated = serde_json::from_str::<StarkProof>(&serde_json::to_string(&proof).unwrap())
        .expect("proof rehydrates from JSON");
    assert_eq!(
        proof.commitment, repeated.commitment,
        "serializing the proof should not alter the derived commitment",
    );
}
