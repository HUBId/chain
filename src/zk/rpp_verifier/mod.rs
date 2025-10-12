#![cfg(feature = "backend-rpp-stark")]

mod error;
mod report;

pub use error::RppStarkVerifierError;
pub use report::RppStarkVerificationReport;

/// Thin facade around the vendored `rpp-stark` verifier. Currently stubbed.
#[derive(Debug, Default, Clone, Copy)]
pub struct RppStarkVerifier;

impl RppStarkVerifier {
    /// Creates a new verifier instance.
    #[inline]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the backend identifier for logging and metrics.
    #[inline]
    pub const fn backend_name(&self) -> &'static str {
        "rpp-stark"
    }

    /// Indicates whether the backend wiring is complete.
    #[inline]
    pub const fn is_ready(&self) -> bool {
        false
    }

    /// Placeholder verification entry point. Always returns a stub error for now.
    pub fn verify_golden_vector(
        &self,
        _params: &[u8],
        _public_inputs: &[u8],
        _proof: &[u8],
    ) -> Result<RppStarkVerificationReport, RppStarkVerifierError> {
        Err(RppStarkVerifierError::backend_unavailable())
    }
}

/// Convenience function mirroring [`RppStarkVerifier::verify_golden_vector`].
pub fn verify_golden_vector(
    params: &[u8],
    public_inputs: &[u8],
    proof: &[u8],
) -> Result<RppStarkVerificationReport, RppStarkVerifierError> {
    RppStarkVerifier::new().verify_golden_vector(params, public_inputs, proof)
}
