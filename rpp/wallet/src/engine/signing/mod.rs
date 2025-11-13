use super::DraftTransaction;

pub mod prover;

pub use prover::build_wallet_prover;

use prover_backend_interface::{BackendError, ProofBytes};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverOutput {
    pub backend: String,
    pub proof: Option<ProofBytes>,
    pub witness_bytes: usize,
    pub duration_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("backend error: {0}")]
    Backend(#[from] BackendError),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("unsupported prover backend: {0}")]
    Unsupported(&'static str),
}

pub trait WalletProver: Send + Sync {
    fn backend(&self) -> &'static str;
    fn prove(&self, draft: &DraftTransaction) -> Result<ProverOutput, ProverError>;
}

