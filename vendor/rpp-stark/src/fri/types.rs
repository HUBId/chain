use core::fmt;

use crate::field::prime_field::FieldConstraintError;
use crate::hash::deterministic::DeterministicHashError;
use crate::hash::merkle::MerkleError;
use crate::params::StarkParams;

/// Transcript seed used when instantiating the FRI prover and verifier.
pub type FriTranscriptSeed = [u8; 32];

/// Security profiles supported by the FRI engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriSecurityLevel {
    /// Standard profile with 64 queries.
    Standard,
    /// High security profile with 96 queries.
    HiSec,
    /// Throughput oriented profile with 48 queries.
    Throughput,
}

impl FriSecurityLevel {
    /// Returns the query budget associated with the profile.
    pub const fn query_budget(self) -> usize {
        match self {
            FriSecurityLevel::Standard => 64,
            FriSecurityLevel::HiSec => 96,
            FriSecurityLevel::Throughput => 48,
        }
    }

    /// Infers the security profile corresponding to a query budget.
    pub fn from_query_count(count: usize) -> Option<Self> {
        match count {
            c if c == FriSecurityLevel::Standard.query_budget() => Some(FriSecurityLevel::Standard),
            c if c == FriSecurityLevel::HiSec.query_budget() => Some(FriSecurityLevel::HiSec),
            c if c == FriSecurityLevel::Throughput.query_budget() => {
                Some(FriSecurityLevel::Throughput)
            }
            _ => None,
        }
    }

    pub(crate) fn tag(self) -> &'static str {
        match self {
            FriSecurityLevel::Standard => "STD",
            FriSecurityLevel::HiSec => "HISEC",
            FriSecurityLevel::Throughput => "THR",
        }
    }

    pub(crate) fn code(self) -> u8 {
        match self {
            FriSecurityLevel::Standard => 0,
            FriSecurityLevel::HiSec => 1,
            FriSecurityLevel::Throughput => 2,
        }
    }

    pub(crate) fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(FriSecurityLevel::Standard),
            1 => Some(FriSecurityLevel::HiSec),
            2 => Some(FriSecurityLevel::Throughput),
            _ => None,
        }
    }
}

/// Version tag attached to FRI proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriProofVersion {
    /// Initial version of the binary FRI proof format.
    V1,
}

impl FriProofVersion {
    /// Latest supported proof version.
    pub const CURRENT: FriProofVersion = FriProofVersion::V1;

    pub(crate) fn to_u16(self) -> u16 {
        match self {
            FriProofVersion::V1 => 1,
        }
    }

    pub(crate) fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(FriProofVersion::V1),
            _ => None,
        }
    }
}

/// Kind markers used when reporting serialization errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerKind {
    /// Parameters payload framing.
    Params,
    /// Proof body framing.
    Proof,
    /// Query openings payload framing.
    Query,
    /// Layer openings payload framing.
    Layer,
    /// Final polynomial encoding.
    FinalPolynomial,
}

impl fmt::Display for SerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerKind::Params => write!(f, "parameters"),
            SerKind::Proof => write!(f, "proof"),
            SerKind::Query => write!(f, "query"),
            SerKind::Layer => write!(f, "layer"),
            SerKind::FinalPolynomial => write!(f, "final polynomial"),
        }
    }
}

/// FRI verification errors mapped to the specification failure classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FriError {
    /// Proof version mismatch.
    VersionMismatch {
        /// Expected proof version for the verifier.
        expected: FriProofVersion,
        /// Version declared by the proof being processed.
        actual: FriProofVersion,
    },
    /// Folding constraints were violated during verification.
    FoldingConstraintViolated {
        /// Layer index where the folding constraint failed.
        layer: usize,
    },
    /// Out-of-domain sampling failed.
    OodsInvalid,
    /// Serialization failure when decoding proof artefacts.
    Serialization(SerKind),
    /// No evaluations were provided to the prover.
    EmptyCodeword,
    /// Query position exceeded the LDE domain size.
    QueryOutOfRange {
        /// Position outside the evaluation domain.
        position: usize,
    },
    /// Merkle path was malformed (index byte mismatch or inconsistent height).
    PathInvalid {
        /// Layer where the invalid path was detected.
        layer: usize,
        /// Underlying Merkle verification error.
        reason: MerkleError,
    },
    /// Merkle layer root mismatch.
    LayerRootMismatch {
        /// Layer index that produced a different root.
        layer: usize,
    },
    /// Proof declared a different security profile.
    SecurityLevelMismatch,
    /// Proof declared an unexpected number of queries.
    QueryBudgetMismatch {
        /// Expected number of queries for the security profile.
        expected: usize,
        /// Actual number of queries provided by the proof.
        actual: usize,
    },
    /// Generic structure error (missing layer, inconsistent lengths, etc.).
    InvalidStructure(&'static str),
    /// Deterministic hashing helper failed while sampling challenges.
    DeterministicHash(DeterministicHashError),
    /// Field element violated canonical encoding constraints.
    FieldConstraint(FieldConstraintError),
}

impl fmt::Display for FriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FriError::VersionMismatch { expected, actual } => {
                write!(
                    f,
                    "proof version mismatch (expected {expected:?}, got {actual:?})"
                )
            }
            FriError::FoldingConstraintViolated { layer } => {
                write!(f, "folding constraint violated at layer {layer}")
            }
            FriError::OodsInvalid => write!(f, "out-of-domain sampling constraint failed"),
            FriError::Serialization(kind) => {
                write!(f, "failed to serialize/deserialize FRI {kind}")
            }
            FriError::EmptyCodeword => write!(f, "codeword is empty"),
            FriError::QueryOutOfRange { position } => {
                write!(f, "query position {position} outside evaluation domain")
            }
            FriError::PathInvalid { layer, reason } => {
                write!(f, "invalid Merkle path at layer {layer}: {reason}")
            }
            FriError::LayerRootMismatch { layer } => {
                write!(f, "layer {layer} root mismatch")
            }
            FriError::SecurityLevelMismatch => write!(f, "security profile mismatch"),
            FriError::QueryBudgetMismatch { expected, actual } => write!(
                f,
                "query budget mismatch (expected {expected}, got {actual})"
            ),
            FriError::InvalidStructure(reason) => write!(f, "invalid proof structure: {reason}"),
            FriError::DeterministicHash(err) => {
                write!(f, "deterministic hash error: {err}")
            }
            FriError::FieldConstraint(err) => {
                write!(f, "field constraint violation: {err}")
            }
        }
    }
}

impl std::error::Error for FriError {}

impl From<DeterministicHashError> for FriError {
    fn from(err: DeterministicHashError) -> Self {
        FriError::DeterministicHash(err)
    }
}

impl From<FieldConstraintError> for FriError {
    fn from(err: FieldConstraintError) -> Self {
        FriError::FieldConstraint(err)
    }
}

/// Borrowed view over the parameters required when verifying a proof.
#[derive(Debug, Clone, Copy)]
pub struct FriParamsView {
    /// Declared proof version.
    pub version: FriProofVersion,
    /// Security profile used for the proof.
    pub security_level: FriSecurityLevel,
    /// Query plan identifier derived from the security level.
    pub query_plan: [u8; 32],
    /// Number of verifier queries requested by the parameter set.
    pub query_count: usize,
    /// Maximum number of folding layers executed by the prover.
    pub num_layers: usize,
    /// Log<sub>2</sub> of the initial evaluation domain size.
    pub domain_log2: usize,
}

impl FriParamsView {
    /// Constructs a view binding the static parameter fields used by the prover.
    pub fn from_params(
        params: &StarkParams,
        security_level: FriSecurityLevel,
        query_plan: [u8; 32],
    ) -> Self {
        let fri_params = params.fri();
        Self {
            version: FriProofVersion::CURRENT,
            security_level,
            query_plan,
            query_count: fri_params.queries as usize,
            num_layers: fri_params.num_layers as usize,
            domain_log2: fri_params.domain_log2 as usize,
        }
    }

    /// Returns the initial domain size derived from the parameter set.
    pub fn initial_domain_size(&self) -> usize {
        1usize << self.domain_log2
    }

    /// Returns the configured query count.
    pub fn query_count(&self) -> usize {
        self.query_count
    }

    /// Returns the number of folding layers.
    pub fn num_layers(&self) -> usize {
        self.num_layers
    }
}
