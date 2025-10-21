//! Lightweight witness representations for the Plonky3 circuits.
//!
//! The real constraint systems are not wired up yet, but the prover and
//! verifier integration requires a consistent way to expose public inputs for
//! each witness.  The [`Plonky3CircuitWitness`] trait centralises the
//! serialization logic so that callers can focus on higher level plumbing
//! without duplicating boilerplate conversions.

use serde::Serialize;
use serde_json::{Map, Number, Value};

use crate::errors::{ChainError, ChainResult};

pub mod consensus;
pub mod identity;
pub mod pruning;
pub mod recursive;
pub mod state;
pub mod transaction;
pub mod uptime;

/// Helper trait implemented by all Plonky3 witness structures.
///
/// Each witness exposes its circuit identifier and the JSON structure that
/// should be committed as public inputs by the prover.  This mirrors the shape
/// of the STWO integration and provides a stable surface area while the real
/// circuits are implemented incrementally.
pub trait Plonky3CircuitWitness: Serialize {
    /// Name of the circuit the witness belongs to.
    fn circuit(&self) -> &'static str;

    /// Optional block height metadata attached to the public inputs.
    fn block_height(&self) -> Option<u64> {
        None
    }

    /// Serialize the witness into the canonical public input structure.
    fn public_inputs(&self) -> ChainResult<Value> {
        let mut object = Map::new();
        let witness_value = serde_json::to_value(self).map_err(|err| {
            ChainError::Crypto(format!(
                "failed to serialize {} witness for Plonky3 public inputs: {err}",
                self.circuit()
            ))
        })?;
        object.insert("witness".into(), witness_value);
        if let Some(height) = self.block_height() {
            object.insert("block_height".into(), Value::Number(Number::from(height)));
        }
        Ok(Value::Object(object))
    }
}
