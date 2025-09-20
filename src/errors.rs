use std::io;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("storage error: {0}")]
    Storage(#[from] rocksdb::Error),
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
    #[error("io error: {0}")]
    Io(#[from] io::Error),
}

pub type ChainResult<T> = Result<T, ChainError>;
