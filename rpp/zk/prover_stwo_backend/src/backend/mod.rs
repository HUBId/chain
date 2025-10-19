#[cfg(feature = "official")]
mod io;

#[cfg(feature = "official")]
pub use io::{decode_tx_proof, decode_tx_witness, encode_tx_proof};

use prover_backend_interface::{
    BackendError, BackendResult, ProofBackend, ProofBytes, ProvingKey, SecurityLevel, TxCircuitDef,
    TxPublicInputs, VerifyingKey, WitnessBytes,
};

/// Thin adapter exposing the STWO integration through the shared backend
/// interface.  The concrete proving routines are wired in lazily to keep the
/// nightly-only dependencies isolated from stable crates.
#[derive(Debug, Default)]
pub struct StwoBackend;

impl StwoBackend {
    pub fn new() -> Self {
        Self
    }
}

impl ProofBackend for StwoBackend {
    fn name(&self) -> &'static str {
        "stwo"
    }

    fn setup_params(&self, _security: SecurityLevel) -> BackendResult<()> {
        Ok(())
    }

    fn keygen_tx(&self, _circuit: &TxCircuitDef) -> BackendResult<(ProvingKey, VerifyingKey)> {
        Err(BackendError::Unsupported("transaction keygen"))
    }

    fn prove_tx(&self, _pk: &ProvingKey, _witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        Err(BackendError::Unsupported("transaction proving"))
    }

    fn verify_tx(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &TxPublicInputs,
    ) -> BackendResult<bool> {
        Err(BackendError::Unsupported("transaction verification"))
    }
}
