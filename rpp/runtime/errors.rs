use std::io;

use prover_backend_interface::BackendError;
use rpp_identity_tree::IdentityTreeError;
use storage_firewood::kv::KvError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("storage error: {0}")]
    Storage(#[from] KvError),
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("configuration error: {0}")]
    Config(String),
    #[error(
        "storage schema is outdated (found version {found}, requires {required}); run `cargo run -- migrate` to upgrade"
    )]
    MigrationRequired { found: u32, required: u32 },
    #[error("cryptography error: {0}")]
    Crypto(String),
    #[error("transaction rejected: {0}")]
    Transaction(String),
    #[error("invalid proof: {0}")]
    InvalidProof(String),
    #[error("commitment mismatch: {0}")]
    CommitmentMismatch(String),
    #[error("commitment monotonicity violated: {0}")]
    MonotonicityViolation(String),
    #[error("snapshot replay failed: {0}")]
    SnapshotReplayFailed(String),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

pub type ChainResult<T> = Result<T, ChainError>;

impl From<BackendError> for ChainError {
    fn from(err: BackendError) -> Self {
        match err {
            BackendError::Serialization(inner) => ChainError::Serialization(inner),
            BackendError::Unsupported(msg) | BackendError::Failure(msg) => {
                ChainError::Crypto(msg.into())
            }
        }
    }
}

impl From<IdentityTreeError> for ChainError {
    fn from(err: IdentityTreeError) -> Self {
        ChainError::Transaction(err.to_string())
    }
}
