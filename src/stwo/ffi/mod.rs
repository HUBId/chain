//! FFI and accelerator bindings for the STWO/STARK stack.

/// Placeholder trait capturing GPU or specialized prover acceleration.
pub trait ProverAccelerator {
    /// Returns whether the accelerator is currently available.
    fn is_available(&self) -> bool;

    /// Submits a witness computation job and returns a handle to the result bytes.
    fn submit_job(&self, witness: &[u8]) -> Result<Vec<u8>, AcceleratorError>;
}

/// Errors raised while interacting with external accelerators.
#[derive(Debug, thiserror::Error)]
pub enum AcceleratorError {
    #[error("accelerator backend not configured")]
    NotConfigured,
    #[error("accelerator job failed: {0}")]
    JobFailed(String),
}

/// No-op accelerator used while native integrations are under development.
pub struct NullAccelerator;

impl ProverAccelerator for NullAccelerator {
    fn is_available(&self) -> bool {
        false
    }

    fn submit_job(&self, _witness: &[u8]) -> Result<Vec<u8>, AcceleratorError> {
        Err(AcceleratorError::NotConfigured)
    }
}
