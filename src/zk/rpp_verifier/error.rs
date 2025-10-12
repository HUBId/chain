#![cfg(feature = "backend-rpp-stark")]

use thiserror::Error;

/// Errors produced by the placeholder `rpp-stark` verifier integration.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RppStarkVerifierError {
    /// Indicates that the vendored backend is not fully wired in yet.
    #[error("rpp-stark backend is not vendored or activated: {0}")]
    BackendUnavailable(&'static str),
}

impl RppStarkVerifierError {
    /// Helper constructor for a consistent unavailable error message.
    pub const fn backend_unavailable() -> Self {
        Self::BackendUnavailable("integration pending")
    }
}
