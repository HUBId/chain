#![cfg(feature = "backend-rpp-stark")]

use core::fmt;

use rpp_stark::backend::ProofSizeMappingError;
use rpp_stark::params::SerKind as ParamsSerKind;
use rpp_stark::proof::types::{FriVerifyIssue, MerkleSection, VerifyError};
use thiserror::Error;

use super::RppStarkVerificationReport;

/// High-level errors surfaced by the `rpp-stark` verifier facade.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RppStarkVerifierError {
    /// Indicates that the vendored backend is not fully wired in yet.
    #[error("rpp-stark backend is not vendored or activated: {0}")]
    BackendUnavailable(&'static str),

    /// Parameters failed to decode using the canonical serialization rules.
    #[error("failed to decode Stark parameters ({context})")]
    MalformedParams {
        /// Serialization context that triggered the failure.
        context: RppStarkSerializationContext,
    },

    /// The provided parameter blob does not match any supported profile.
    #[error("unsupported Stark parameter profile: {profile_id}")]
    UnsupportedParamsProfile {
        /// Deterministic identifier derived from the parameter blob.
        profile_id: String,
    },

    /// The node configuration disagrees with the parameter-encoded proof limit.
    #[error(
        "proof size limit mismatch between params ({params_kib} KiB) and node limit ({expected_kib} KiB)"
    )]
    ProofSizeLimitMismatch {
        /// Limit recorded inside the parameter blob (in kibibytes).
        params_kib: u32,
        /// Limit derived from the node configuration (in kibibytes).
        expected_kib: u32,
    },

    /// The parameter proof-size limit overflows when converted back to bytes.
    #[error("proof size limit {max_kib} KiB overflows when mapped to bytes")]
    ProofSizeLimitOverflow {
        /// Overflowing limit encoded in the parameter blob.
        max_kib: u32,
    },

    /// Public-input bytes do not follow the documented execution layout.
    #[error("failed to decode execution public inputs: {reason}")]
    MalformedPublicInputs {
        /// Human-readable description of the violation.
        reason: &'static str,
    },

    /// Verification failed inside the backend verifier and returned a structured report.
    #[error("verification failed: {failure}")]
    VerificationFailed {
        /// Stable mapping of the backend verification error.
        failure: RppStarkVerifyFailure,
        /// Structured verification report returned by the backend.
        report: RppStarkVerificationReport,
    },
}

impl RppStarkVerifierError {
    /// Helper constructor for a consistent unavailable error message.
    pub const fn backend_unavailable() -> Self {
        Self::BackendUnavailable("integration pending")
    }

    /// Maps backend proof-size mapping errors to facade errors.
    pub fn from_size_mapping_error(error: ProofSizeMappingError) -> Self {
        match error {
            ProofSizeMappingError::Mismatch {
                params_kb,
                expected_kb,
            } => Self::ProofSizeLimitMismatch {
                params_kib: params_kb,
                expected_kib: expected_kb,
            },
            ProofSizeMappingError::Overflow { max_size_kb } => Self::ProofSizeLimitOverflow {
                max_kib: max_size_kb,
            },
        }
    }
}

/// Stable mapping of serialization contexts surfaced by the verifier facade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RppStarkSerializationContext {
    Proof,
    TraceCommitment,
    CompositionCommitment,
    Fri,
    Openings,
    Telemetry,
    PublicInputs,
    Params,
}

impl fmt::Display for RppStarkSerializationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Proof => "proof",
            Self::TraceCommitment => "trace commitment",
            Self::CompositionCommitment => "composition commitment",
            Self::Fri => "fri",
            Self::Openings => "openings",
            Self::Telemetry => "telemetry",
            Self::PublicInputs => "public inputs",
            Self::Params => "params",
        };
        write!(f, "{label}")
    }
}

impl From<ParamsSerKind> for RppStarkSerializationContext {
    fn from(kind: ParamsSerKind) -> Self {
        match kind {
            ParamsSerKind::Proof => Self::Proof,
            ParamsSerKind::TraceCommitment => Self::TraceCommitment,
            ParamsSerKind::CompositionCommitment => Self::CompositionCommitment,
            ParamsSerKind::Fri => Self::Fri,
            ParamsSerKind::Openings => Self::Openings,
            ParamsSerKind::Telemetry => Self::Telemetry,
            ParamsSerKind::PublicInputs => Self::PublicInputs,
            ParamsSerKind::Params => Self::Params,
        }
    }
}

/// Stable representation of Merkle sections reported by the backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RppStarkMerkleSection {
    FriRoots,
    FriPath,
    TraceCommit,
    CompositionCommit,
}

impl fmt::Display for RppStarkMerkleSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::FriRoots => "fri_roots",
            Self::FriPath => "fri_path",
            Self::TraceCommit => "trace_commit",
            Self::CompositionCommit => "composition_commit",
        };
        write!(f, "{label}")
    }
}

impl From<MerkleSection> for RppStarkMerkleSection {
    fn from(section: MerkleSection) -> Self {
        match section {
            MerkleSection::FriRoots => Self::FriRoots,
            MerkleSection::FriPath => Self::FriPath,
            MerkleSection::TraceCommit => Self::TraceCommit,
            MerkleSection::CompositionCommit => Self::CompositionCommit,
        }
    }
}

/// Stable representation of FRI verification issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RppStarkFriIssue {
    QueryOutOfRange,
    PathInvalid,
    LayerMismatch,
    SecurityLevelMismatch,
    LayerBudgetExceeded,
    EmptyCodeword,
    VersionMismatch,
    QueryBudgetMismatch,
    FoldingConstraint,
    OodsInvalid,
    Generic,
}

impl fmt::Display for RppStarkFriIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::QueryOutOfRange => "query_out_of_range",
            Self::PathInvalid => "path_invalid",
            Self::LayerMismatch => "layer_mismatch",
            Self::SecurityLevelMismatch => "security_level_mismatch",
            Self::LayerBudgetExceeded => "layer_budget_exceeded",
            Self::EmptyCodeword => "empty_codeword",
            Self::VersionMismatch => "version_mismatch",
            Self::QueryBudgetMismatch => "query_budget_mismatch",
            Self::FoldingConstraint => "folding_constraint",
            Self::OodsInvalid => "oods_invalid",
            Self::Generic => "generic",
        };
        write!(f, "{label}")
    }
}

impl From<FriVerifyIssue> for RppStarkFriIssue {
    fn from(issue: FriVerifyIssue) -> Self {
        match issue {
            FriVerifyIssue::QueryOutOfRange => Self::QueryOutOfRange,
            FriVerifyIssue::PathInvalid => Self::PathInvalid,
            FriVerifyIssue::LayerMismatch => Self::LayerMismatch,
            FriVerifyIssue::SecurityLevelMismatch => Self::SecurityLevelMismatch,
            FriVerifyIssue::LayerBudgetExceeded => Self::LayerBudgetExceeded,
            FriVerifyIssue::EmptyCodeword => Self::EmptyCodeword,
            FriVerifyIssue::VersionMismatch => Self::VersionMismatch,
            FriVerifyIssue::QueryBudgetMismatch => Self::QueryBudgetMismatch,
            FriVerifyIssue::FoldingConstraint => Self::FoldingConstraint,
            FriVerifyIssue::OodsInvalid => Self::OodsInvalid,
            FriVerifyIssue::Generic => Self::Generic,
        }
    }
}

/// Stable mapping of backend verification failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RppStarkVerifyFailure {
    VersionMismatch {
        expected: u16,
        actual: u16,
    },
    UnknownProofKind(u8),
    HeaderLengthMismatch {
        declared: u32,
        actual: u32,
    },
    BodyLengthMismatch {
        declared: u32,
        actual: u32,
    },
    UnexpectedEndOfBuffer {
        detail: String,
    },
    IntegrityDigestMismatch,
    InvalidFriSection {
        detail: String,
    },
    NonCanonicalFieldElement,
    ParamsHashMismatch,
    PublicInputMismatch,
    PublicDigestMismatch,
    TranscriptOrder,
    OutOfDomainInvalid,
    UnsupportedMerkleScheme,
    RootMismatch {
        section: RppStarkMerkleSection,
    },
    MerkleVerifyFailed {
        section: RppStarkMerkleSection,
    },
    TraceLeafMismatch,
    CompositionLeafMismatch,
    TraceOodMismatch,
    CompositionOodMismatch,
    CompositionInconsistent {
        reason: String,
    },
    FriVerifyFailed {
        issue: RppStarkFriIssue,
    },
    DegreeBoundExceeded,
    ProofTooLarge {
        max_kib: u32,
        got_kib: u32,
    },
    EmptyOpenings,
    IndicesNotSorted,
    IndicesDuplicate {
        index: u32,
    },
    IndicesMismatch,
    AggregationDigestMismatch,
    Serialization {
        context: RppStarkSerializationContext,
    },
    DeterministicHashSlice {
        expected: usize,
    },
}

impl fmt::Display for RppStarkVerifyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionMismatch { expected, actual } => {
                write!(f, "version mismatch: expected {expected}, got {actual}")
            }
            Self::UnknownProofKind(kind) => {
                write!(f, "unknown proof kind: 0x{kind:02x}")
            }
            Self::HeaderLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "header length mismatch: declared {declared} bytes, observed {actual} bytes"
                )
            }
            Self::BodyLengthMismatch { declared, actual } => {
                write!(
                    f,
                    "body length mismatch: declared {declared} bytes, observed {actual} bytes"
                )
            }
            Self::UnexpectedEndOfBuffer { detail } => {
                write!(f, "unexpected end of buffer: {detail}")
            }
            Self::IntegrityDigestMismatch => {
                write!(f, "integrity digest mismatch")
            }
            Self::InvalidFriSection { detail } => {
                write!(f, "invalid fri section: {detail}")
            }
            Self::NonCanonicalFieldElement => {
                write!(f, "non-canonical field element")
            }
            Self::ParamsHashMismatch => {
                write!(f, "parameter hash mismatch")
            }
            Self::PublicInputMismatch => {
                write!(f, "public input mismatch")
            }
            Self::PublicDigestMismatch => {
                write!(f, "public digest mismatch")
            }
            Self::TranscriptOrder => write!(f, "transcript order violation"),
            Self::OutOfDomainInvalid => write!(f, "out-of-domain opening invalid"),
            Self::UnsupportedMerkleScheme => write!(f, "unsupported merkle scheme"),
            Self::RootMismatch { section } => {
                write!(f, "merkle root mismatch ({section})")
            }
            Self::MerkleVerifyFailed { section } => {
                write!(f, "merkle verification failed ({section})")
            }
            Self::TraceLeafMismatch => write!(f, "trace leaf mismatch"),
            Self::CompositionLeafMismatch => write!(f, "composition leaf mismatch"),
            Self::TraceOodMismatch => write!(f, "trace out-of-domain mismatch"),
            Self::CompositionOodMismatch => write!(f, "composition out-of-domain mismatch"),
            Self::CompositionInconsistent { reason } => {
                write!(f, "composition inconsistent: {reason}")
            }
            Self::FriVerifyFailed { issue } => {
                write!(f, "fri verification failed: {issue}")
            }
            Self::DegreeBoundExceeded => write!(f, "degree bound exceeded"),
            Self::ProofTooLarge { max_kib, got_kib } => {
                write!(f, "proof too large: limit {max_kib} KiB, got {got_kib} KiB")
            }
            Self::EmptyOpenings => write!(f, "openings section empty"),
            Self::IndicesNotSorted => write!(f, "query indices not strictly increasing"),
            Self::IndicesDuplicate { index } => {
                write!(f, "duplicate query index: {index}")
            }
            Self::IndicesMismatch => write!(f, "query indices mismatch"),
            Self::AggregationDigestMismatch => {
                write!(f, "aggregation digest mismatch")
            }
            Self::Serialization { context } => {
                write!(f, "serialization failure in {context}")
            }
            Self::DeterministicHashSlice { expected } => {
                write!(
                    f,
                    "deterministic hash slice conversion failed (expected {expected} bytes)"
                )
            }
        }
    }
}

impl From<VerifyError> for RppStarkVerifyFailure {
    fn from(error: VerifyError) -> Self {
        match error {
            VerifyError::VersionMismatch { expected, actual } => {
                Self::VersionMismatch { expected, actual }
            }
            VerifyError::UnknownProofKind(kind) => Self::UnknownProofKind(kind),
            VerifyError::HeaderLengthMismatch { declared, actual } => {
                Self::HeaderLengthMismatch { declared, actual }
            }
            VerifyError::BodyLengthMismatch { declared, actual } => {
                Self::BodyLengthMismatch { declared, actual }
            }
            VerifyError::UnexpectedEndOfBuffer(detail) => Self::UnexpectedEndOfBuffer { detail },
            VerifyError::IntegrityDigestMismatch => Self::IntegrityDigestMismatch,
            VerifyError::InvalidFriSection(detail) => Self::InvalidFriSection { detail },
            VerifyError::NonCanonicalFieldElement => Self::NonCanonicalFieldElement,
            VerifyError::ParamsHashMismatch => Self::ParamsHashMismatch,
            VerifyError::PublicInputMismatch => Self::PublicInputMismatch,
            VerifyError::PublicDigestMismatch => Self::PublicDigestMismatch,
            VerifyError::TranscriptOrder => Self::TranscriptOrder,
            VerifyError::OutOfDomainInvalid => Self::OutOfDomainInvalid,
            VerifyError::UnsupportedMerkleScheme => Self::UnsupportedMerkleScheme,
            VerifyError::RootMismatch { section } => Self::RootMismatch {
                section: section.into(),
            },
            VerifyError::MerkleVerifyFailed { section } => Self::MerkleVerifyFailed {
                section: section.into(),
            },
            VerifyError::TraceLeafMismatch => Self::TraceLeafMismatch,
            VerifyError::CompositionLeafMismatch => Self::CompositionLeafMismatch,
            VerifyError::TraceOodMismatch => Self::TraceOodMismatch,
            VerifyError::CompositionOodMismatch => Self::CompositionOodMismatch,
            VerifyError::CompositionInconsistent { reason } => {
                Self::CompositionInconsistent { reason }
            }
            VerifyError::FriVerifyFailed { issue } => Self::FriVerifyFailed {
                issue: issue.into(),
            },
            VerifyError::DegreeBoundExceeded => Self::DegreeBoundExceeded,
            VerifyError::ProofTooLarge { max_kb, got_kb } => Self::ProofTooLarge {
                max_kib: max_kb,
                got_kib: got_kb,
            },
            VerifyError::EmptyOpenings => Self::EmptyOpenings,
            VerifyError::IndicesNotSorted => Self::IndicesNotSorted,
            VerifyError::IndicesDuplicate { index } => Self::IndicesDuplicate { index },
            VerifyError::IndicesMismatch => Self::IndicesMismatch,
            VerifyError::AggregationDigestMismatch => Self::AggregationDigestMismatch,
            VerifyError::Serialization(kind) => Self::Serialization {
                context: kind.into(),
            },
            VerifyError::DeterministicHash(err) => match err {
                rpp_stark::hash::deterministic::DeterministicHashError::SliceConversion {
                    expected,
                } => Self::DeterministicHashSlice { expected },
            },
        }
    }
}
