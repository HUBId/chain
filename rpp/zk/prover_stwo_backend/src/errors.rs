use thiserror::Error;

/// Result alias used by the blueprint verifier and circuits.
pub type ChainResult<T> = Result<T, ChainError>;

/// Lightweight error type mirroring the variants used across the official
/// circuit scaffolding.  The intent is to keep the blueprint focused on the
/// high level control flow rather than exposing the full runtime error
/// surface.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    /// Raised when a cryptographic consistency check fails.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// Raised when witness or transaction data violates basic invariants.
    #[error("transaction error: {0}")]
    Transaction(String),
}
