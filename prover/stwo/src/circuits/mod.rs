//! Domain specific circuits used by the wallet before invoking STWO proofs.

pub mod balance;
pub mod double_spend;
pub mod tier_attestation;

/// Error reported when a circuit fails to validate a witness.
#[derive(Debug, thiserror::Error, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "detail")]
pub enum CircuitError {
    /// Raised when a witness is structurally invalid.
    #[error("invalid witness: {0}")]
    InvalidWitness(String),
    /// Raised when the provided witness violates a circuit constraint.
    #[error("constraint violation: {0}")]
    ConstraintViolation(String),
}

impl CircuitError {
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::InvalidWitness(msg.into())
    }

    pub fn violated(msg: impl Into<String>) -> Self {
        Self::ConstraintViolation(msg.into())
    }
}
