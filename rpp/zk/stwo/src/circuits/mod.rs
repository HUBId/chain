//! High level circuit descriptions used by the local STWO prover.
//!
//! The implementations in this module intentionally keep the witness
//! generation logic straightforward.  Each circuit encapsulates the public
//! inputs relevant for its domain (transactions, reputation, pruning, etc.) and
//! exposes helper functions used by the prover and verifier.

pub mod identity;
pub mod pruning;
pub mod reputation;
pub mod transaction;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Marker trait implemented by all circuit witnesses.
pub trait CircuitWitness: Serialize + for<'de> Deserialize<'de> {
    /// Returns a descriptive label for logging and proof metadata.
    fn label(&self) -> &'static str;

    /// Serialise the witness into JSON for hashing and proof commitments.
    fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("witness is serialisable")
    }
}

/// Execution trace metadata shared by all circuits.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CircuitTrace {
    /// Blake2s commitment to the witness columns.
    pub trace_commitment: [u8; 32],
    /// Additional domain specific commitment, typically Poseidon based.
    pub constraint_commitment: [u8; 32],
    /// Full trace data used during proving for deterministic verification.
    pub trace_data: Value,
}

impl CircuitTrace {
    pub fn new(
        trace_commitment: [u8; 32],
        constraint_commitment: [u8; 32],
        trace_data: Value,
    ) -> Self {
        Self {
            trace_commitment,
            constraint_commitment,
            trace_data,
        }
    }
}
