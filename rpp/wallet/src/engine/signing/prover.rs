use std::sync::Arc;
use std::time::Instant;

use crate::config::wallet::WalletProverConfig;

use super::{ProverError, ProverOutput, WalletProver};
use crate::engine::DraftTransaction;
use prover_backend_interface::{ProofBytes, ProofHeader, ProofSystemKind, WitnessBytes, WitnessHeader};

pub fn build_wallet_prover(config: &WalletProverConfig) -> Result<Arc<dyn WalletProver>, ProverError> {
    if config.enabled {
        #[cfg(feature = "prover-stwo")]
        {
            return Ok(Arc::new(StwoWalletProver::default()));
        }
        #[cfg(not(feature = "prover-stwo"))]
        {
            if !config.mock_fallback {
                return Ok(Arc::new(DisabledWalletProver::new(
                    "STWO prover requested but feature disabled",
                )));
            }
        }
    }
    #[cfg(feature = "prover-mock")]
    {
        return Ok(Arc::new(MockWalletProver::new()?));
    }
    Ok(Arc::new(DisabledWalletProver::new(
        "wallet prover backend disabled",
    )))
}

#[cfg(feature = "prover-mock")]
struct MockWalletProver;

#[cfg(feature = "prover-mock")]
impl MockWalletProver {
    fn new() -> Result<Self, ProverError> {
        Ok(Self)
    }
}

#[cfg(feature = "prover-mock")]
impl WalletProver for MockWalletProver {
    fn backend(&self) -> &'static str {
        "mock"
    }

    fn prove(&self, draft: &DraftTransaction) -> Result<ProverOutput, ProverError> {
        let start = Instant::now();
        let witness_header = WitnessHeader::new(ProofSystemKind::Mock, "wallet.tx");
        let payload = bincode::serialize(draft)
            .map_err(|err| ProverError::Serialization(err.to_string()))?;
        let witness = WitnessBytes::encode(&witness_header, &payload)?;
        let witness_bytes = witness.as_slice().len();
        let proof_header = ProofHeader::new(ProofSystemKind::Mock, "wallet.tx");
        let proof = ProofBytes::encode(&proof_header, witness.as_slice())?;
        let duration = start.elapsed();
        Ok(ProverOutput {
            backend: self.backend().to_string(),
            proof: Some(proof),
            witness_bytes,
            duration_ms: duration.as_millis() as u64,
        })
    }
}

#[cfg(feature = "prover-stwo")]
#[derive(Default)]
struct StwoWalletProver;

#[cfg(feature = "prover-stwo")]
impl WalletProver for StwoWalletProver {
    fn backend(&self) -> &'static str {
        "stwo"
    }

    fn prove(&self, _draft: &DraftTransaction) -> Result<ProverOutput, ProverError> {
        Err(ProverError::Unsupported("STWO prover integration pending"))
    }
}

struct DisabledWalletProver {
    reason: &'static str,
}

impl DisabledWalletProver {
    fn new(reason: &'static str) -> Self {
        Self { reason }
    }
}

impl WalletProver for DisabledWalletProver {
    fn backend(&self) -> &'static str {
        "disabled"
    }

    fn prove(&self, _draft: &DraftTransaction) -> Result<ProverOutput, ProverError> {
        Err(ProverError::Unsupported(self.reason))
    }
}

