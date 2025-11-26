use std::time::{Duration, Instant};

use super::DraftTransaction;

pub mod prover;
#[cfg(feature = "prover-stwo")]
pub mod stwo;

pub use prover::build_wallet_prover;

use prover_backend_interface::{BackendError, ProofBytes, WitnessBytes};

#[derive(Clone, Debug)]
pub struct DraftProverContext<'a> {
    draft: &'a DraftTransaction,
    started_at: Instant,
}

impl<'a> DraftProverContext<'a> {
    pub fn new(draft: &'a DraftTransaction) -> Self {
        Self {
            draft,
            started_at: Instant::now(),
        }
    }

    pub fn draft(&self) -> &'a DraftTransaction {
        self.draft
    }

    pub fn started_at(&self) -> Instant {
        self.started_at
    }
}

#[derive(Debug)]
pub struct WitnessPlan {
    witness: Option<WitnessBytes>,
    witness_bytes: usize,
    prepared_at: Instant,
    backend: &'static str,
}

impl WitnessPlan {
    pub fn empty() -> Self {
        Self {
            witness: None,
            witness_bytes: 0,
            prepared_at: Instant::now(),
            backend: "unknown",
        }
    }

    pub fn new(witness: WitnessBytes) -> Self {
        let bytes = witness.as_slice().len();
        Self {
            witness: Some(witness),
            witness_bytes: bytes,
            prepared_at: Instant::now(),
            backend: "unknown",
        }
    }

    pub fn with_parts(witness: WitnessBytes, prepared_at: Instant) -> Self {
        let bytes = witness.as_slice().len();
        Self {
            witness: Some(witness),
            witness_bytes: bytes,
            prepared_at,
            backend: "unknown",
        }
    }

    pub fn witness_bytes(&self) -> usize {
        self.witness_bytes
    }

    pub fn prepared_at(&self) -> Instant {
        self.prepared_at
    }

    pub fn backend(&self) -> &'static str {
        self.backend
    }

    pub fn with_backend(mut self, backend: &'static str) -> Self {
        self.backend = backend;
        self
    }

    pub fn take_witness(&mut self) -> Option<WitnessBytes> {
        self.witness.take()
    }

    pub fn into_witness(mut self) -> Option<WitnessBytes> {
        self.witness.take()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProveResult {
    backend: &'static str,
    proof: Option<ProofBytes>,
    witness_bytes: usize,
    started_at: Instant,
    finished_at: Instant,
}

impl ProveResult {
    pub fn new(
        backend: &'static str,
        proof: Option<ProofBytes>,
        witness_bytes: usize,
        started_at: Instant,
        finished_at: Instant,
    ) -> Self {
        Self {
            backend,
            proof,
            witness_bytes,
            started_at,
            finished_at,
        }
    }

    pub fn proof(&self) -> Option<&ProofBytes> {
        self.proof.as_ref()
    }

    pub fn backend(&self) -> &'static str {
        self.backend
    }

    pub fn into_proof(self) -> Option<ProofBytes> {
        self.proof
    }

    pub fn witness_bytes(&self) -> usize {
        self.witness_bytes
    }

    pub fn duration(&self) -> Duration {
        self.finished_at
            .checked_duration_since(self.started_at)
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverMeta {
    pub backend: &'static str,
    pub witness_bytes: usize,
    pub proof_bytes: Option<usize>,
    pub proof_hash: Option<[u8; 32]>,
    pub duration_ms: u64,
}

impl ProverMeta {
    pub fn proof_size(&self) -> Option<usize> {
        self.proof_bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProverIdentity {
    pub backend: &'static str,
    pub allow_empty_proof: bool,
}

impl ProverIdentity {
    pub const fn new(backend: &'static str, allow_empty_proof: bool) -> Self {
        Self {
            backend,
            allow_empty_proof,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("backend error: {0}")]
    Backend(#[from] BackendError),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("unsupported prover backend: {0}")]
    Unsupported(&'static str),
    #[error("wallet prover runtime unavailable: {0}")]
    Runtime(String),
    #[error("wallet prover job timed out after {0} seconds")]
    Timeout(u64),
    #[error("wallet prover job was cancelled")]
    Cancelled,
    #[error("wallet prover is busy")]
    Busy,
    #[error("witness too large ({size} bytes > limit {limit})")]
    WitnessTooLarge { size: usize, limit: u64 },
}

pub trait WalletProver: Send + Sync {
    fn identity(&self) -> ProverIdentity;
    fn prepare_witness(&self, ctx: &DraftProverContext<'_>) -> Result<WitnessPlan, ProverError>;
    fn prove(
        &self,
        ctx: &DraftProverContext<'_>,
        plan: WitnessPlan,
    ) -> Result<ProveResult, ProverError>;
    fn attest_metadata(
        &self,
        ctx: &DraftProverContext<'_>,
        result: &ProveResult,
    ) -> Result<ProverMeta, ProverError>;
}
