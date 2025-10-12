#![cfg(feature = "backend-rpp-stark")]

/// Minimal verification report used while the backend wiring is stubbed out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RppStarkVerificationReport {
    backend: &'static str,
    verified: bool,
    notes: &'static str,
}

impl RppStarkVerificationReport {
    /// Creates a placeholder report for the vendored backend.
    pub const fn pending(notes: &'static str) -> Self {
        Self {
            backend: "rpp-stark",
            verified: false,
            notes,
        }
    }

    /// Returns the backend identifier attached to the report.
    pub const fn backend(&self) -> &'static str {
        self.backend
    }

    /// Indicates whether the proof was fully verified.
    pub const fn is_verified(&self) -> bool {
        self.verified
    }

    /// Provides additional context on the verification outcome.
    pub const fn notes(&self) -> &'static str {
        self.notes
    }
}
