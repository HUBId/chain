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
use crate::official::params::StarkParameters;
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
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &TxPublicInputs,
    ) -> BackendResult<bool> {
        Err(BackendError::Unsupported("transaction verification"))
    }
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
    use crate::official::proof::ProofPayload;
    use crate::reputation::{ReputationWeights, Tier};
    use crate::types::{Account, SignedTransaction, Stake, Transaction};
    use ed25519_dalek::{Keypair, Signer};
    use prover_backend_interface::{ProofSystemKind, WitnessBytes, WitnessHeader};
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

    fn proving_key() -> ProvingKey {
        let payload = TxKeyPayload::new(
            SupportedTxCircuit::Transaction,
            StarkParameters::blueprint_default(),
        );
        let encoded = encode_key_payload(&payload).expect("payload serialises");
        ProvingKey(encoded)
    }

    fn encode_witness(witness: &TransactionWitness) -> WitnessBytes {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "tx");
        WitnessBytes::encode(&header, witness).expect("witness encodes")
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
