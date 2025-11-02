//! Definitions for STARK constraint systems used across the stack.

use serde::{Deserialize, Serialize};

use crate::official::air::{AirDefinition, ConstraintCompressor};
use crate::official::params::{FieldElement, StarkParameters};

pub mod consensus;
pub mod identity;
pub mod pruning;
pub mod recursive;
pub mod state;
pub mod transaction;
pub mod uptime;

pub use consensus::{
    ConsensusVrfPoseidonInput, ConsensusVrfWitnessEntry, ConsensusWitness, VotePower,
};
pub use identity::IdentityWitness;
pub use pruning::PruningWitness;
pub use recursive::RecursiveWitness;
pub use state::StateWitness;
pub use transaction::TransactionWitness;
pub use uptime::UptimeWitness;

/// Execution trace segment captured while evaluating a circuit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceSegment {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<Vec<FieldElement>>,
}

impl TraceSegment {
    pub fn new(
        name: impl Into<String>,
        columns: Vec<String>,
        rows: Vec<Vec<FieldElement>>,
    ) -> Result<Self, CircuitError> {
        if columns.is_empty() {
            return Err(CircuitError::InvalidWitness(
                "trace segment requires at least one column".into(),
            ));
        }
        let name = name.into();
        let width = columns.len();
        for (index, row) in rows.iter().enumerate() {
            if row.len() != width {
                return Err(CircuitError::InvalidWitness(format!(
                    "trace segment '{}' row {} width mismatch: expected {}, found {}",
                    name,
                    index,
                    width,
                    row.len()
                )));
            }
        }
        Ok(Self {
            name,
            columns,
            rows,
        })
    }
}

/// Execution trace emitted by a circuit. Consists of one or more named segments.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionTrace {
    pub segments: Vec<TraceSegment>,
}

impl ExecutionTrace {
    pub fn from_segments(segments: Vec<TraceSegment>) -> Result<Self, CircuitError> {
        if segments.is_empty() {
            return Err(CircuitError::InvalidWitness(
                "execution trace must contain at least one segment".into(),
            ));
        }
        Ok(Self { segments })
    }

    pub fn single(segment: TraceSegment) -> Result<Self, CircuitError> {
        Self::from_segments(vec![segment])
    }
}

/// Convert arbitrary string encodings into field elements. Hex inputs are
/// decoded preferentially, falling back to ASCII encoding when decoding fails.
pub fn string_to_field(parameters: &StarkParameters, value: &str) -> FieldElement {
    let bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
    parameters.element_from_bytes(&bytes)
}

/// Generic trait implemented by all STARK-compatible circuits in the system.
pub trait StarkCircuit {
    /// Structured name of the circuit. Used for logging, metrics and serialization headers.
    fn name(&self) -> &'static str;

    /// Compute all constraints over the execution trace and permutation arguments.
    fn evaluate_constraints(&self) -> Result<(), CircuitError>;

    /// Materialize the execution trace associated with the witness and circuit.
    fn generate_trace(&self, parameters: &StarkParameters) -> Result<ExecutionTrace, CircuitError>;

    /// Describe the AIR constraints associated with the generated execution trace.
    fn define_air(
        &self,
        parameters: &StarkParameters,
        trace: &ExecutionTrace,
    ) -> Result<AirDefinition, CircuitError>;

    /// Evaluate and compress the AIR constraints over the execution trace.
    fn verify_air(
        &self,
        parameters: &StarkParameters,
        trace: &ExecutionTrace,
    ) -> Result<(), CircuitError> {
        let air = self.define_air(parameters, trace)?;
        let evaluations = air
            .evaluate(trace, parameters)
            .map_err(|err| CircuitError::InvalidWitness(err.to_string()))?;
        for evaluation in &evaluations {
            if let Some((row, value)) = evaluation.first_violation() {
                return Err(CircuitError::ConstraintViolation(format!(
                    "AIR constraint '{}' failed at row {} with value {}",
                    evaluation.name,
                    row,
                    value.to_hex()
                )));
            }
        }
        let compressor = ConstraintCompressor::new(parameters, &air);
        let compressed = compressor
            .compress(&evaluations)
            .map_err(|err| CircuitError::InvalidWitness(err.to_string()))?;
        if let Some((row, value)) = compressed.first_violation() {
            return Err(CircuitError::ConstraintViolation(format!(
                "compressed AIR evaluation failed at row {} with value {}",
                row,
                value.to_hex()
            )));
        }
        Ok(())
    }
}

/// Errors that can be raised while evaluating STARK constraints.
#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    /// Raised when an execution trace fails a constraint.
    #[error("constraint violation: {0}")]
    ConstraintViolation(String),

    /// Raised when witness data is malformed or inconsistent.
    #[error("invalid witness data: {0}")]
    InvalidWitness(String),

    /// Raised for unsupported features or configuration mismatches.
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
}
