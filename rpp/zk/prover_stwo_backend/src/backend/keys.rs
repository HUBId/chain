#![cfg(feature = "official")]

use bincode::Options;
use prover_backend_interface::{BackendError, BackendResult};
use serde::{Deserialize, Serialize};

use crate::official::params::StarkParameters;

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_little_endian()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedTxCircuit {
    Transaction,
}

impl SupportedTxCircuit {
    pub fn identifier(&self) -> &'static str {
        match self {
            SupportedTxCircuit::Transaction => "transaction",
        }
    }

    pub fn from_identifier(value: &str) -> BackendResult<Self> {
        let trimmed = value.trim();
        if trimmed.eq_ignore_ascii_case("transaction") || trimmed.eq_ignore_ascii_case("tx") {
            Ok(SupportedTxCircuit::Transaction)
        } else {
            Err(BackendError::Failure(format!(
                "unsupported transaction circuit '{trimmed}'"
            )))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxKeyPayload {
    pub circuit: String,
    pub parameters: StarkParameters,
}

impl TxKeyPayload {
    pub fn new(circuit: SupportedTxCircuit, parameters: StarkParameters) -> Self {
        Self {
            circuit: circuit.identifier().to_string(),
            parameters,
        }
    }
}

pub fn encode_key_payload(payload: &TxKeyPayload) -> BackendResult<Vec<u8>> {
    bincode_options()
        .serialize(payload)
        .map_err(BackendError::Serialization)
}

pub fn decode_key_payload(bytes: &[u8]) -> BackendResult<TxKeyPayload> {
    let payload: TxKeyPayload = bincode_options()
        .deserialize(bytes)
        .map_err(BackendError::Serialization)?;
    SupportedTxCircuit::from_identifier(&payload.circuit)?;
    Ok(payload)
}
