use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::errors::{ChainError, ChainResult};

/// Generic representation of a Plonky3 proof artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plonky3Proof {
    pub circuit: String,
    pub witness: Value,
    pub payload: Value,
}

impl Plonky3Proof {
    pub fn placeholder(circuit: impl Into<String>, witness: Value, block_height: u64) -> Self {
        Self {
            circuit: circuit.into(),
            witness,
            payload: json!({
                "status": "unimplemented",
                "block_height": block_height,
            }),
        }
    }

    pub fn from_parts(circuit: impl Into<String>, witness: Value, payload: Value) -> Self {
        Self {
            circuit: circuit.into(),
            witness,
            payload,
        }
    }

    pub fn into_value(self) -> ChainResult<Value> {
        serde_json::to_value(self).map_err(|err| {
            ChainError::Crypto(format!("failed to encode Plonky3 proof placeholder: {err}"))
        })
    }
}
