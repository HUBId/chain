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
pub enum SupportedCircuit {
    Transaction,
    Identity,
    State,
    Pruning,
    Recursive,
    Uptime,
    Consensus,
}

impl SupportedCircuit {
    pub fn identifier(&self) -> &'static str {
        match self {
            SupportedCircuit::Transaction => "transaction",
            SupportedCircuit::Identity => "identity",
            SupportedCircuit::State => "state",
            SupportedCircuit::Pruning => "pruning",
            SupportedCircuit::Recursive => "recursive",
            SupportedCircuit::Uptime => "uptime",
            SupportedCircuit::Consensus => "consensus",
        }
    }

    pub fn from_identifier(value: &str) -> BackendResult<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(BackendError::Failure(
                "circuit identifier cannot be empty".into(),
            ));
        }

        if trimmed.eq_ignore_ascii_case("transaction") || trimmed.eq_ignore_ascii_case("tx") {
            Ok(SupportedCircuit::Transaction)
        } else if trimmed.eq_ignore_ascii_case("identity") {
            Ok(SupportedCircuit::Identity)
        } else if trimmed.eq_ignore_ascii_case("state") {
            Ok(SupportedCircuit::State)
        } else if trimmed.eq_ignore_ascii_case("pruning") {
            Ok(SupportedCircuit::Pruning)
        } else if trimmed.eq_ignore_ascii_case("recursive") {
            Ok(SupportedCircuit::Recursive)
        } else if trimmed.eq_ignore_ascii_case("uptime") {
            Ok(SupportedCircuit::Uptime)
        } else if trimmed.eq_ignore_ascii_case("consensus") || trimmed.starts_with("consensus-") {
            Ok(SupportedCircuit::Consensus)
        } else {
            Err(BackendError::Failure(format!(
                "unsupported circuit '{trimmed}'"
            )))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyPayload {
    pub circuit: String,
    pub parameters: StarkParameters,
}

impl KeyPayload {
    pub fn new(circuit: SupportedCircuit, parameters: StarkParameters) -> Self {
        Self {
            circuit: circuit.identifier().to_string(),
            parameters,
        }
    }

    pub fn circuit_kind(&self) -> BackendResult<SupportedCircuit> {
        SupportedCircuit::from_identifier(&self.circuit)
    }

    pub fn ensure_kind(&self, expected: SupportedCircuit) -> BackendResult<()> {
        let actual = self.circuit_kind()?;
        if actual == expected {
            Ok(())
        } else {
            Err(BackendError::Failure(format!(
                "key payload expected {:?} circuit, found {:?}",
                expected, actual
            )))
        }
    }
}

pub fn encode_key_payload(payload: &KeyPayload) -> BackendResult<Vec<u8>> {
    bincode_options()
        .serialize(payload)
        .map_err(BackendError::Serialization)
}

pub fn decode_key_payload(bytes: &[u8]) -> BackendResult<KeyPayload> {
    let payload: KeyPayload = bincode_options()
        .deserialize(bytes)
        .map_err(BackendError::Serialization)?;
    // Accept legacy payloads that only set the transaction circuit string.
    let _ = payload.circuit_kind()?;
    Ok(payload)
}
