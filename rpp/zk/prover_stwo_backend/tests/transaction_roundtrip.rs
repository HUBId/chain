#![cfg(feature = "prover-stwo")]

use prover_backend_interface::{
    BackendError, ProofBytes, ProofHeader, ProofSystemKind, TxCircuitDef, TxPublicInputs,
    WitnessBytes, WitnessHeader, PROOF_FORMAT_VERSION, WITNESS_FORMAT_VERSION,
};
use prover_stwo_backend::backend::StwoBackend;
use prover_stwo_backend::official::circuit::transaction::TransactionWitness;
use prover_stwo_backend::official::proof::{ProofKind, ProofPayload, StarkProof};

mod fixture {
    use super::*;

    const VALID_PROOF_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../proofs/stwo/tests/vectors/valid_proof.json"
    ));

    pub(super) const TX_CIRCUIT: &str = "tx";

    pub(super) fn witness() -> TransactionWitness {
        match load_proof().payload {
            ProofPayload::Transaction(witness) => witness,
            other => panic!("fixture embedded unexpected payload: {other:?}"),
        }
    }

    pub(super) fn witness_bytes() -> WitnessBytes {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, TX_CIRCUIT);
        WitnessBytes::encode(&header, &witness()).expect("fixture witness encodes")
    }

    pub(super) fn public_inputs() -> TxPublicInputs {
        inputs_from_fields(&load_proof().public_inputs)
    }

    pub(super) fn inputs_from_fields(fields: &[String]) -> TxPublicInputs {
        assert!(
            fields.len() >= 8,
            "transaction public inputs must encode at least 8 field elements",
        );

        let mut utxo_root = [0u8; 32];
        let mut tx_commitment = [0u8; 32];

        for (idx, field) in fields.iter().take(4).enumerate() {
            let chunk = field_chunk_bytes(field);
            utxo_root[idx * 8..(idx + 1) * 8].copy_from_slice(&chunk);
        }
        for (idx, field) in fields.iter().skip(4).take(4).enumerate() {
            let chunk = field_chunk_bytes(field);
            tx_commitment[idx * 8..(idx + 1) * 8].copy_from_slice(&chunk);
        }

        TxPublicInputs {
            utxo_root,
            transaction_commitment: tx_commitment,
        }
    }

    pub(super) fn load_proof() -> StarkProof {
        serde_json::from_str(VALID_PROOF_JSON).expect("valid proof fixture decodes")
    }

    fn field_chunk_bytes(value: &str) -> [u8; 8] {
        let mut chunk = [0u8; 8];
        if value.is_empty() {
            return chunk;
        }

        let bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
        let take = bytes.len().min(chunk.len());
        chunk[chunk.len() - take..].copy_from_slice(&bytes[bytes.len() - take..]);
        chunk
    }
}

#[test]
fn transaction_roundtrip_succeeds_with_fixture_witness() {
    let backend = StwoBackend::new();
    let circuit = TxCircuitDef::new("transaction");
    let (proving_key, verifying_key) = backend
        .keygen_tx(&circuit)
        .expect("key generation succeeds");

    let witness_bytes = fixture::witness_bytes();
    let (witness_header, decoded_witness) = witness_bytes
        .decode::<TransactionWitness>()
        .expect("witness bytes decode");
    assert_eq!(
        witness_header.version, WITNESS_FORMAT_VERSION,
        "witness header should match the canonical format version",
    );
    assert_eq!(
        witness_header.backend,
        ProofSystemKind::Stwo,
        "witness header should point to the STWO backend",
    );
    assert_eq!(
        witness_header.circuit, fixture::TX_CIRCUIT,
        "witness header should describe the transaction circuit",
    );
    assert_eq!(
        decoded_witness, fixture::witness(),
        "fixture witness should round-trip through serialization",
    );

    let proof_bytes = backend
        .prove_tx(&proving_key, &witness_bytes)
        .expect("proving succeeds for deterministic fixture witness");

    let (proof_header, decoded_proof) = proof_bytes
        .decode::<StarkProof>()
        .expect("proof bytes decode");
    assert_eq!(
        proof_header.version, PROOF_FORMAT_VERSION,
        "proof header should match the canonical format version",
    );
    assert_eq!(
        proof_header.backend,
        ProofSystemKind::Stwo,
        "proof header should point to the STWO backend",
    );
    assert_eq!(
        proof_header.circuit, fixture::TX_CIRCUIT,
        "proof header should describe the transaction circuit",
    );
    assert_eq!(
        decoded_proof.kind,
        ProofKind::Transaction,
        "proof should be tagged as a transaction proof",
    );
    match &decoded_proof.payload {
        ProofPayload::Transaction(recovered) => {
            assert_eq!(
                recovered, &fixture::witness(),
                "proving should embed the original witness",
            );
        }
        other => panic!("unexpected proof payload variant: {other:?}"),
    }

    let expected_inputs = fixture::public_inputs();
    let reconstructed_inputs = fixture::inputs_from_fields(&decoded_proof.public_inputs);
    assert_eq!(
        reconstructed_inputs, expected_inputs,
        "public inputs derived from the proof should match the fixture",
    );

    let verification = backend
        .verify_tx(&verifying_key, &proof_bytes, &expected_inputs)
        .expect("verification succeeds for fixture proof");
    assert!(verification, "backend verification should return true");
}

#[test]
fn tampered_proof_bytes_are_rejected() {
    let backend = StwoBackend::new();
    let circuit = TxCircuitDef::new("transaction");
    let (proving_key, verifying_key) = backend
        .keygen_tx(&circuit)
        .expect("key generation succeeds");
    let witness_bytes = fixture::witness_bytes();

    let proof_bytes = backend
        .prove_tx(&proving_key, &witness_bytes)
        .expect("proving succeeds for deterministic fixture witness");
    let public_inputs = fixture::public_inputs();

    let mut tampered = proof_bytes.clone().into_inner();
    assert!(tampered.len() > 16, "fixture proof bytes should be non-trivial");
    tampered[16] ^= 0x42;
    let tampered = ProofBytes(tampered);

    let err = backend
        .verify_tx(&verifying_key, &tampered, &public_inputs)
        .expect_err("tampered proof bytes should not verify");
    match err {
        BackendError::Serialization(_) => {}
        BackendError::Failure(message) => {
            assert!(
                message.contains("proof") || message.contains("commitment"),
                "unexpected verification failure message: {message}",
            );
        }
        other => panic!("unexpected backend error: {other:?}"),
    }
}

#[test]
fn mismatched_proof_headers_are_rejected() {
    let backend = StwoBackend::new();
    let circuit = TxCircuitDef::new("transaction");
    let (proving_key, verifying_key) = backend
        .keygen_tx(&circuit)
        .expect("key generation succeeds");
    let witness_bytes = fixture::witness_bytes();

    let proof_bytes = backend
        .prove_tx(&proving_key, &witness_bytes)
        .expect("proving succeeds for deterministic fixture witness");
    let (_, decoded_proof) = proof_bytes
        .decode::<StarkProof>()
        .expect("proof bytes decode");
    let public_inputs = fixture::public_inputs();

    let bad_header = ProofHeader {
        version: PROOF_FORMAT_VERSION,
        backend: ProofSystemKind::Mock,
        circuit: fixture::TX_CIRCUIT.into(),
    };
    let tampered_bytes = ProofBytes::encode(&bad_header, &decoded_proof)
        .expect("tampered proof encodes");

    let err = backend
        .verify_tx(&verifying_key, &tampered_bytes, &public_inputs)
        .expect_err("mismatched proof headers should fail verification");
    assert!(
        matches!(
            err,
            BackendError::Failure(ref message) if message.contains("expected STWO proof header")
        ),
        "unexpected verification failure variant: {err:?}",
    );
}
