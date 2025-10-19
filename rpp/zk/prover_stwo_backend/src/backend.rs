#[cfg(feature = "official")]
mod io;
#[cfg(feature = "official")]
mod keys;

#[cfg(feature = "official")]
pub use io::{decode_tx_proof, decode_tx_witness, encode_tx_proof};

use prover_backend_interface::{
    BackendError, BackendResult, ProofBackend, ProofBytes, ProvingKey, SecurityLevel, TxCircuitDef,
    TxPublicInputs, VerifyingKey, WitnessBytes,
};

#[cfg(feature = "official")]
use crate::official::params::{FieldElement, StarkParameters};
#[cfg(feature = "official")]
use crate::official::verifier::NodeVerifier;
#[cfg(feature = "official")]
use keys::{encode_key_payload, SupportedTxCircuit, TxKeyPayload};

/// Thin adapter exposing the STWO integration through the shared backend
/// interface.  The concrete proving routines are wired in lazily to keep the
/// nightly-only dependencies isolated from stable crates.
#[derive(Debug, Default)]
pub struct StwoBackend;

impl StwoBackend {
    pub fn new() -> Self {
        Self
    }
}

impl ProofBackend for StwoBackend {
    fn name(&self) -> &'static str {
        "stwo"
    }

    fn setup_params(&self, _security: SecurityLevel) -> BackendResult<()> {
        Ok(())
    }

    fn keygen_tx(&self, circuit: &TxCircuitDef) -> BackendResult<(ProvingKey, VerifyingKey)> {
        #[cfg(feature = "official")]
        {
            return keygen_tx_keys(circuit);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = circuit;
            Err(BackendError::Unsupported("transaction keygen"))
        }
    }

    fn prove_tx(&self, pk: &ProvingKey, witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        #[cfg(feature = "official")]
        {
            let payload = keys::decode_key_payload(pk.as_slice())?;
            let witness = decode_tx_witness(witness)?;
            let prover = crate::official::prover::WalletProver::new(payload.parameters);
            let proof = prover
                .prove_transaction_witness(witness)
                .map_err(|err| BackendError::Failure(err.to_string()))?;
            return encode_tx_proof(&proof);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (pk, witness);
            Err(BackendError::Unsupported("transaction proving"))
        }
    }

    fn verify_tx(
        &self,
        vk: &VerifyingKey,
        proof: &ProofBytes,
        public_inputs: &TxPublicInputs,
    ) -> BackendResult<bool> {
        #[cfg(feature = "official")]
        {
            let payload = keys::decode_key_payload(vk.as_slice())?;
            let parameters = payload.parameters;
            let decoded = decode_tx_proof(proof)?;
            let expected_fields = rebuild_tx_public_inputs(&parameters, public_inputs);
            let expected_inputs: Vec<String> =
                expected_fields.iter().map(FieldElement::to_hex).collect();

            if decoded.public_inputs != expected_inputs {
                return Err(BackendError::Failure(
                    "transaction public inputs mismatch".into(),
                ));
            }

            let hasher = parameters.poseidon_hasher();
            let expected_commitment = hasher.hash(&expected_fields);
            if decoded.commitment != expected_commitment.to_hex() {
                return Err(BackendError::Failure(
                    "transaction commitment mismatch".into(),
                ));
            }

            if field_to_padded_bytes(&expected_commitment) != public_inputs.transaction_commitment {
                return Err(BackendError::Failure(
                    "transaction commitment digest mismatch".into(),
                ));
            }

            if decoded.commitment_proof.to_official().is_none() {
                return Err(BackendError::Failure(
                    "missing commitment proof data".into(),
                ));
            }

            if decoded.fri_proof.to_official().is_none() {
                return Err(BackendError::Failure("missing fri proof data".into()));
            }

            let verifier = NodeVerifier::with_parameters(parameters);
            verifier
                .verify_transaction_proof(&decoded)
                .map_err(|err| BackendError::Failure(err.to_string()))?;

            return Ok(true);
        }

        #[cfg(not(feature = "official"))]
        {
            let _ = (vk, proof, public_inputs);
            Err(BackendError::Unsupported("transaction verification"))
        }
    }
}

#[cfg(feature = "official")]
fn rebuild_tx_public_inputs(
    parameters: &StarkParameters,
    inputs: &TxPublicInputs,
) -> Vec<FieldElement> {
    fn digest_chunks(
        parameters: &StarkParameters,
        digest: &[u8; 32],
    ) -> Vec<FieldElement> {
        digest
            .chunks(8)
            .map(|chunk| parameters.element_from_bytes(chunk))
            .collect()
    }

    let mut fields = digest_chunks(parameters, &inputs.utxo_root);
    fields.extend(digest_chunks(
        parameters,
        &inputs.transaction_commitment,
    ));
    fields
}

#[cfg(feature = "official")]
fn field_to_padded_bytes(value: &FieldElement) -> [u8; 32] {
    let repr = value.to_bytes();
    let mut bytes = [0u8; 32];
    let offset = bytes.len().saturating_sub(repr.len());
    bytes[offset..offset + repr.len()].copy_from_slice(&repr);
    bytes
}

#[cfg(feature = "official")]
fn keygen_tx_keys(circuit: &TxCircuitDef) -> BackendResult<(ProvingKey, VerifyingKey)> {
    let selected = decode_tx_circuit_identifier(&circuit.identifier)?;
    let parameters = StarkParameters::blueprint_default();
    let payload = TxKeyPayload::new(selected, parameters);
    let encoded = encode_key_payload(&payload)?;

    let proving_key = ProvingKey(encoded.clone());
    let verifying_key = VerifyingKey(encoded);
    Ok((proving_key, verifying_key))
}

#[cfg(feature = "official")]
fn decode_tx_circuit_identifier(identifier: &str) -> BackendResult<SupportedTxCircuit> {
    if identifier.trim().is_empty() {
        return Err(BackendError::Failure(
            "transaction circuit identifier cannot be empty".into(),
        ));
    }

    // Attempt to parse structured identifiers, falling back to raw circuit names.
    #[derive(serde::Deserialize)]
    struct Identifier<'a> {
        #[serde(borrow)]
        circuit: &'a str,
    }

    let parsed = if identifier.trim_start().starts_with('{') {
        serde_json::from_str::<Identifier>(identifier)
            .map(|value| value.circuit.to_string())
            .map_err(|err| {
                BackendError::Failure(format!(
                    "invalid transaction circuit identifier '{}': {err}",
                    identifier
                ))
            })?
    } else {
        identifier.to_string()
    };

    SupportedTxCircuit::from_identifier(&parsed)
}

#[cfg(all(test, feature = "official"))]
mod tests {
    use super::keys::{decode_key_payload, encode_key_payload, SupportedTxCircuit, TxKeyPayload};
    use super::*;
    use crate::crypto::address_from_public_key;
    use crate::official::circuit::transaction::TransactionWitness;
    use crate::official::proof::{ProofPayload, StarkProof};
    use crate::reputation::{ReputationWeights, Tier};
    use crate::types::{Account, SignedTransaction, Stake, Transaction};
    use ed25519_dalek::{Keypair, Signer};
    use prover_backend_interface::{
        ProofBytes, ProofSystemKind, TxPublicInputs, VerifyingKey, WitnessBytes, WitnessHeader,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn tx_key_payload_roundtrip() {
        let payload = TxKeyPayload::new(
            SupportedTxCircuit::Transaction,
            StarkParameters::blueprint_default(),
        );
        let encoded = encode_key_payload(&payload).expect("payload serialises");
        let decoded = decode_key_payload(&encoded).expect("payload roundtrips");
        assert_eq!(payload, decoded);
    }

    #[test]
    fn rejects_unknown_circuit_ids() {
        use crate::official::params::StarkParameters;

        let mut payload = TxKeyPayload::new(
            SupportedTxCircuit::Transaction,
            StarkParameters::blueprint_default(),
        );
        payload.circuit = "unsupported".into();
        let encoded = encode_key_payload(&payload).expect("payload serialises");
        let error = decode_key_payload(&encoded).expect_err("unknown circuit is rejected");
        assert!(matches!(error, BackendError::Failure(message) if message.contains("unsupported transaction circuit")));
    }

    #[test]
    fn rejects_empty_identifiers() {
        let result = decode_tx_circuit_identifier("");
        assert!(matches!(result, Err(BackendError::Failure(message)) if message.contains("cannot be empty")));
    }

    #[test]
    fn transaction_proof_round_trip_from_witness_fixture() {
        let backend = StwoBackend::new();
        let proving_key = proving_key();
        let witness = sample_transaction_witness();
        let witness_bytes = encode_witness(&witness);

        let proof_bytes = backend
            .prove_tx(&proving_key, &witness_bytes)
            .expect("proving should succeed for valid witness");
        let proof = decode_tx_proof(&proof_bytes).expect("proof decodes");

        match &proof.payload {
            ProofPayload::Transaction(decoded) => {
                assert_eq!(decoded, &witness, "witness payload should round-trip");
            }
            other => panic!("unexpected payload variant: {other:?}"),
        }

        assert!(
            proof.commitment_proof.to_official().is_some(),
            "commitment proof should be preserved"
        );
        assert!(
            proof.fri_proof.to_official().is_some(),
            "fri transcript should be preserved"
        );
    }

    #[test]
    fn transaction_prover_failures_map_to_backend_errors() {
        let backend = StwoBackend::new();
        let proving_key = proving_key();
        let mut witness = sample_transaction_witness();
        witness.sender_account.nonce = witness.signed_tx.payload.nonce;
        let witness_bytes = encode_witness(&witness);

        let err = backend
            .prove_tx(&proving_key, &witness_bytes)
            .expect_err("invalid witness should fail proving");
        match err {
            BackendError::Failure(message) => {
                assert!(message.contains("nonce"), "unexpected failure message: {message}");
            }
            other => panic!("unexpected backend error variant: {other:?}"),
        }
    }

    fn key_payload_bytes() -> Vec<u8> {
        let payload = TxKeyPayload::new(
            SupportedTxCircuit::Transaction,
            StarkParameters::blueprint_default(),
        );
        encode_key_payload(&payload).expect("payload serialises")
    }

    fn proving_key() -> ProvingKey {
        ProvingKey(key_payload_bytes())
    }

    fn verifying_key() -> VerifyingKey {
        VerifyingKey(key_payload_bytes())
    }

    fn encode_witness(witness: &TransactionWitness) -> WitnessBytes {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "tx");
        WitnessBytes::encode(&header, witness).expect("witness encodes")
    }

    fn field_chunk_bytes(value: &str) -> [u8; 8] {
        let mut chunk = [0u8; 8];
        if value.is_empty() {
            return chunk;
        }

        let bytes = hex::decode(value).expect("field hex decodes");
        let take = bytes.len().min(chunk.len());
        chunk[chunk.len() - take..].copy_from_slice(&bytes[bytes.len() - take..]);
        chunk
    }

    fn recover_tx_public_inputs(proof: &StarkProof) -> TxPublicInputs {
        assert!(
            proof.public_inputs.len() >= 8,
            "transaction proofs must encode at least eight public inputs",
        );

        let mut utxo_root = [0u8; 32];
        let mut tx_commitment = [0u8; 32];

        for (idx, value) in proof.public_inputs.iter().take(4).enumerate() {
            let chunk = field_chunk_bytes(value);
            utxo_root[idx * 8..(idx + 1) * 8].copy_from_slice(&chunk);
        }

        for (idx, value) in proof.public_inputs.iter().skip(4).take(4).enumerate() {
            let chunk = field_chunk_bytes(value);
            tx_commitment[idx * 8..(idx + 1) * 8].copy_from_slice(&chunk);
        }

        TxPublicInputs {
            utxo_root,
            transaction_commitment: tx_commitment,
        }
    }

    #[test]
    fn transaction_verification_succeeds_for_valid_inputs() {
        let backend = StwoBackend::new();
        let proving_key = proving_key();
        let verifying_key = verifying_key();
        let witness = sample_transaction_witness();
        let witness_bytes = encode_witness(&witness);

        let proof_bytes = backend
            .prove_tx(&proving_key, &witness_bytes)
            .expect("proving should succeed for valid witness");
        let proof = decode_tx_proof(&proof_bytes).expect("proof decodes");
        let public_inputs = recover_tx_public_inputs(&proof);

        let parameters = StarkParameters::blueprint_default();
        let expected_fields = rebuild_tx_public_inputs(&parameters, &public_inputs);
        let hasher = parameters.poseidon_hasher();
        let expected_commitment_bytes = field_to_padded_bytes(&hasher.hash(&expected_fields));
        assert_eq!(
            expected_commitment_bytes, public_inputs.transaction_commitment,
            "transaction commitment digest should match reconstructed inputs",
        );

        let result = backend.verify_tx(&verifying_key, &proof_bytes, &public_inputs);
        assert!(matches!(result, Ok(true)), "verification should succeed");
    }

    #[test]
    fn transaction_verification_rejects_tampered_public_inputs() {
        let backend = StwoBackend::new();
        let proving_key = proving_key();
        let verifying_key = verifying_key();
        let witness = sample_transaction_witness();
        let witness_bytes = encode_witness(&witness);

        let proof_bytes = backend
            .prove_tx(&proving_key, &witness_bytes)
            .expect("proving should succeed for valid witness");
        let proof = decode_tx_proof(&proof_bytes).expect("proof decodes");
        let mut public_inputs = recover_tx_public_inputs(&proof);
        public_inputs.utxo_root[0] ^= 0x01;

        let result = backend.verify_tx(&verifying_key, &proof_bytes, &public_inputs);
        assert!(matches!(result, Err(BackendError::Failure(message)) if message.contains("public inputs") || message.contains("commitment")), "tampered public inputs should be rejected");
    }

    #[test]
    fn transaction_verification_rejects_tampered_proof_commitment() {
        let backend = StwoBackend::new();
        let proving_key = proving_key();
        let verifying_key = verifying_key();
        let witness = sample_transaction_witness();
        let witness_bytes = encode_witness(&witness);

        let proof_bytes = backend
            .prove_tx(&proving_key, &witness_bytes)
            .expect("proving should succeed for valid witness");
        let proof = decode_tx_proof(&proof_bytes).expect("proof decodes");
        let public_inputs = recover_tx_public_inputs(&proof);

        let mut tampered = proof.clone();
        let mut commitment_bytes = hex::decode(&tampered.commitment).expect("commitment hex");
        if commitment_bytes.is_empty() {
            commitment_bytes.push(0);
        }
        commitment_bytes[0] ^= 0x01;
        tampered.commitment = hex::encode(commitment_bytes);

        let tampered_bytes = encode_tx_proof(&tampered).expect("encode tampered proof");
        let result = backend.verify_tx(&verifying_key, &tampered_bytes, &public_inputs);
        assert!(matches!(result, Err(BackendError::Failure(message)) if message.contains("commitment")), "tampered commitment should be rejected");
    }

    fn sample_transaction_witness() -> TransactionWitness {
        let mut rng = StdRng::seed_from_u64(0xdead_beef_u64);
        let keypair = Keypair::generate(&mut rng);
        let sender = address_from_public_key(&keypair.public);
        let receiver = hex::encode([0x33u8; 32]);
        let payload = Transaction {
            from: sender.clone(),
            to: receiver.clone(),
            amount: 75,
            fee: 5,
            nonce: 3,
            memo: Some("backend-roundtrip".into()),
            timestamp: 1_717_171_717,
        };
        let signature = keypair.sign(&payload.canonical_bytes());
        let signed_tx = SignedTransaction::new(payload.clone(), signature, &keypair.public);

        let mut sender_account = Account::new(
            sender,
            payload
                .amount
                .saturating_add(payload.fee as u128)
                .saturating_add(1_000),
            Stake::default(),
        );
        sender_account.nonce = payload.nonce - 1;
        sender_account.reputation.tier = Tier::Tl3;
        sender_account.reputation.last_decay_timestamp = payload.timestamp;
        sender_account.reputation.zsi.validated = true;
        sender_account
            .reputation
            .timetokes
            .last_decay_timestamp = payload.timestamp;

        let mut receiver_account = Account::new(receiver, 500, Stake::default());
        receiver_account.reputation.tier = Tier::Tl2;
        receiver_account.reputation.last_decay_timestamp = payload.timestamp;
        receiver_account.reputation.zsi.validated = true;
        receiver_account
            .reputation
            .timetokes
            .last_decay_timestamp = payload.timestamp;

        TransactionWitness {
            signed_tx,
            sender_account,
            receiver_account: Some(receiver_account),
            required_tier: Tier::Tl1,
            reputation_weights: ReputationWeights::default(),
        }
    }
}
