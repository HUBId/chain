#![cfg(feature = "backend-rpp-stark")]

use core::fmt;
use std::vec::Vec;

use rpp_stark::proof::types::VerifyReport;

/// Boolean verification stages bundled for convenient assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RppStarkVerificationFlags {
    params: bool,
    public: bool,
    merkle: bool,
    fri: bool,
    composition: bool,
}

impl RppStarkVerificationFlags {
    /// Construct flags directly from stage outcomes.
    pub const fn from_bools(
        params: bool,
        public: bool,
        merkle: bool,
        fri: bool,
        composition: bool,
    ) -> Self {
        Self {
            params,
            public,
            merkle,
            fri,
            composition,
        }
    }

    /// Returns whether parameter hashing checks succeeded.
    pub const fn params(self) -> bool {
        self.params
    }

    /// Returns whether public input binding checks succeeded.
    pub const fn public(self) -> bool {
        self.public
    }

    /// Returns whether Merkle commitment checks succeeded.
    pub const fn merkle(self) -> bool {
        self.merkle
    }

    /// Returns whether the FRI verifier accepted the proof.
    pub const fn fri(self) -> bool {
        self.fri
    }

    /// Returns whether composition openings matched expectations.
    pub const fn composition(self) -> bool {
        self.composition
    }

    /// Indicates whether all stages reported success.
    pub const fn all_passed(self) -> bool {
        self.params && self.public && self.merkle && self.fri && self.composition
    }
}

/// Structured verification report exposed by the chain facade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RppStarkVerificationReport {
    backend: &'static str,
    params_ok: bool,
    public_ok: bool,
    merkle_ok: bool,
    fri_ok: bool,
    composition_ok: bool,
    total_bytes: u64,
    verified: bool,
    notes: Option<&'static str>,
    trace_query_indices: Option<Vec<u32>>,
}

impl RppStarkVerificationReport {
    /// Creates a placeholder report for the vendored backend.
    pub const fn pending(notes: &'static str) -> Self {
        Self {
            backend: "rpp-stark",
            params_ok: false,
            public_ok: false,
            merkle_ok: false,
            fri_ok: false,
            composition_ok: false,
            total_bytes: 0,
            verified: false,
            notes: Some(notes),
            trace_query_indices: None,
        }
    }

    /// Creates a report from the backend verification summary.
    pub(crate) fn from_backend(report: &VerifyReport) -> Self {
        let trace_query_indices = report
            .proof
            .as_ref()
            .map(|handles| handles.openings().trace().indices().to_vec());
        Self {
            backend: "rpp-stark",
            params_ok: report.params_ok,
            public_ok: report.public_ok,
            merkle_ok: report.merkle_ok,
            fri_ok: report.fri_ok,
            composition_ok: report.composition_ok,
            total_bytes: report.total_bytes,
            verified: report.error.is_none(),
            notes: None,
            trace_query_indices,
        }
    }

    /// Returns the backend identifier attached to the report.
    pub const fn backend(&self) -> &'static str {
        self.backend
    }

    /// Returns the stage flags emitted by the backend.
    pub const fn flags(&self) -> RppStarkVerificationFlags {
        RppStarkVerificationFlags {
            params: self.params_ok,
            public: self.public_ok,
            merkle: self.merkle_ok,
            fri: self.fri_ok,
            composition: self.composition_ok,
        }
    }

    /// Indicates whether the proof was fully verified.
    pub const fn is_verified(&self) -> bool {
        self.verified
    }

    /// Flag indicating whether parameter hashing checks succeeded.
    pub const fn params_ok(&self) -> bool {
        self.params_ok
    }

    /// Flag indicating whether public input binding checks succeeded.
    pub const fn public_ok(&self) -> bool {
        self.public_ok
    }

    /// Flag indicating whether Merkle commitment checks succeeded.
    pub const fn merkle_ok(&self) -> bool {
        self.merkle_ok
    }

    /// Flag indicating whether the FRI verifier accepted the proof.
    pub const fn fri_ok(&self) -> bool {
        self.fri_ok
    }

    /// Flag indicating whether composition openings matched expectations.
    pub const fn composition_ok(&self) -> bool {
        self.composition_ok
    }

    /// Total serialized byte length observed during verification.
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Provides additional context on the verification outcome, when present.
    pub const fn notes(&self) -> Option<&'static str> {
        self.notes
    }

    /// Returns the optional trace query indices surfaced by the backend report.
    pub fn trace_query_indices(&self) -> Option<&[u32]> {
        self.trace_query_indices.as_deref()
    }
}

impl fmt::Display for RppStarkVerificationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{backend} verification: verified={verified} params={params} public={public} merkle={merkle} fri={fri} composition={composition} total_bytes={bytes}",
            backend = self.backend,
            verified = self.verified,
            params = self.params_ok,
            public = self.public_ok,
            merkle = self.merkle_ok,
            fri = self.fri_ok,
            composition = self.composition_ok,
            bytes = self.total_bytes,
        )?;
        if let Some(notes) = self.notes {
            write!(f, " notes={notes}")?;
        }
        Ok(())
    }
}
