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

    fn prove_tx(&self, _pk: &ProvingKey, _witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        Err(BackendError::Unsupported("transaction proving"))
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
}
