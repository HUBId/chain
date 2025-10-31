#![cfg(feature = "prover-stwo")]

use prover_backend_interface::ProofSystemKind;
use prover_backend_interface::{
    ProofBytes, ProofHeader, TxCircuitDef, TxPublicInputs, WitnessBytes, WitnessHeader,
    PROOF_FORMAT_VERSION, WITNESS_FORMAT_VERSION,
};
use prover_stwo_backend::backend::StwoBackend;
use prover_stwo_backend::official::circuit::transaction::TransactionWitness;
use prover_stwo_backend::official::proof::{ProofKind, ProofPayload, StarkProof};

pub const TX_CIRCUIT_ID: &str = "transaction";

fn fixture_json() -> &'static str {
    include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/rpp/proofs/stwo/tests/vectors/valid_proof.json"
    ))
}

pub fn load_proof() -> StarkProof {
    serde_json::from_str(fixture_json()).expect("valid proof fixture decodes")
}

pub fn witness() -> TransactionWitness {
    match load_proof().payload {
        ProofPayload::Transaction(witness) => witness,
        other => panic!("fixture embedded unexpected payload: {other:?}"),
    }
}

pub fn witness_bytes() -> WitnessBytes {
    let header = WitnessHeader::new(ProofSystemKind::Stwo, TX_CIRCUIT_ID);
    WitnessBytes::encode(&header, &witness()).expect("fixture witness encodes")
}

pub fn public_inputs() -> TxPublicInputs {
    inputs_from_fields(&load_proof().public_inputs)
}

pub fn inputs_from_fields(fields: &[String]) -> TxPublicInputs {
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

pub fn prove_fixture(backend: &StwoBackend) -> (ProofBytes, ProofHeader, StarkProof, TxPublicInputs) {
    let circuit = TxCircuitDef::new(TX_CIRCUIT_ID);
    let (proving_key, _) = backend
        .keygen_tx(&circuit)
        .expect("key generation succeeds for fixture circuit");
    let witness_bytes = witness_bytes();
    let proof_bytes = backend
        .prove_tx(&proving_key, &witness_bytes)
        .expect("proving succeeds for deterministic fixture witness");
    let (header, proof) = proof_bytes
        .decode::<StarkProof>()
        .expect("proof bytes decode");
    (proof_bytes, header, proof, public_inputs())
}

pub fn decode_witness_bytes(
    bytes: &WitnessBytes,
) -> (WitnessHeader, TransactionWitness) {
    bytes
        .decode::<TransactionWitness>()
        .expect("witness bytes decode")
}

pub fn tamper_transaction_amount(proof: &mut StarkProof) {
    if let ProofPayload::Transaction(witness) = &mut proof.payload {
        witness.signed_tx.payload.amount = witness
            .signed_tx
            .payload
            .amount
            .saturating_add(1);
    }
}

fn field_chunk_bytes(value: &str) -> [u8; 8] {
    let mut chunk = [0u8; 8];
    if value.is_empty() {
        return chunk;
    }

    let bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
    let take = bytes.len().min(chunk.len());
    let start = chunk.len() - take;
    chunk[start..].copy_from_slice(&bytes[bytes.len() - take..]);
    chunk
}

pub fn assert_witness_header(header: &WitnessHeader) {
    assert_eq!(
        header.version, WITNESS_FORMAT_VERSION,
        "witness header should match the canonical format version",
    );
    assert_eq!(
        header.backend, ProofSystemKind::Stwo,
        "witness header should point to the STWO backend",
    );
    assert_eq!(
        header.circuit, TX_CIRCUIT_ID,
        "witness header should describe the transaction circuit",
    );
}

pub fn assert_proof_header(header: &ProofHeader) {
    assert_eq!(
        header.version, PROOF_FORMAT_VERSION,
        "proof header should match the canonical format version",
    );
    assert_eq!(
        header.backend, ProofSystemKind::Stwo,
        "proof header should point to the STWO backend",
    );
    assert_eq!(
        header.circuit, TX_CIRCUIT_ID,
        "proof header should describe the transaction circuit",
    );
}

pub fn assert_transaction_payload(proof: &StarkProof, expected: &TransactionWitness) {
    assert_eq!(
        proof.kind, ProofKind::Transaction,
        "proof should be tagged as a transaction proof",
    );
    match &proof.payload {
        ProofPayload::Transaction(recovered) => {
            assert_eq!(
                recovered, expected,
                "proving should embed the original witness",
            );
        }
        other => panic!("unexpected proof payload variant: {other:?}"),
    }
}
