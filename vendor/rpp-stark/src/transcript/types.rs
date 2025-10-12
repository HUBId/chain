use core::fmt;

use crate::field::FieldElement;
use crate::hash::deterministic::DeterministicHashError;

/// Canonical field element type absorbed by the transcript.
pub type Felt = FieldElement;

/// Transcript contexts provide coarse domain separation for prover components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TranscriptContext {
    /// Main STARK pipeline transcript.
    StarkMain,
    /// FRI-specific sub transcript.
    Fri,
    /// AIR-specific transcript for constraint binding.
    Air,
    /// Merkle transcript used when deriving commitments for trace polynomials.
    MerkleTrace,
    /// Merkle transcript for composition polynomial commitments.
    MerkleComp,
    /// Transcript driving the public-input commitments.
    PublicInputs,
    /// Custom user supplied domain separation tag.
    Custom(u64),
}

impl TranscriptContext {
    /// Returns the canonical little-endian encoding of the context tag.
    pub(crate) fn to_le_bytes(self) -> [u8; 8] {
        match self {
            TranscriptContext::StarkMain => 0x5250505f53544b4du64.to_le_bytes(),
            TranscriptContext::Fri => 0x5250505f4652495fu64.to_le_bytes(),
            TranscriptContext::Air => 0x5250505f4149525fu64.to_le_bytes(),
            TranscriptContext::MerkleTrace => 0x5250505f54524345u64.to_le_bytes(),
            TranscriptContext::MerkleComp => 0x5250505f4d455243u64.to_le_bytes(),
            TranscriptContext::PublicInputs => 0x5250505f50554249u64.to_le_bytes(),
            TranscriptContext::Custom(tag) => tag.to_le_bytes(),
        }
    }
}

/// Transcript phases exposed for diagnostics and sequencing checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranscriptPhase {
    /// Initialisation phase: params hash, protocol tag, seed and context.
    Init,
    /// Public input binding phase.
    Public,
    /// Trace commitment phase.
    TraceCommit,
    /// Constraint/composition commitment phase.
    CompCommit,
    /// FRI layer phase identified by its index.
    FriLayer(u8),
    /// Query sampling phase for trace/FRI openings.
    Queries,
    /// Final binding phase producing the proof close digest.
    Final,
}

/// Canonical transcript labels.  Every variant appears exactly once in the
/// transcript order unless otherwise documented.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TranscriptLabel {
    /// Canonical parameter hash absorbed during initialisation.
    ParamsHash,
    /// Protocol tag separating transcript families.
    ProtocolTag,
    /// Deterministic seed provided by the parameter set.
    Seed,
    /// Context tag used when forking or initialising the transcript.
    ContextTag,
    /// Digest of the canonical public inputs layout.
    PublicInputsDigest,
    /// Merkle root of the trace commitment.
    TraceRoot,
    /// First algebraic challenge after trace commitment.
    TraceChallengeA,
    /// Merkle root of the composition polynomial commitment.
    CompRoot,
    /// First challenge emitted after the composition commitment.
    CompChallengeA,
    /// Merkle root of FRI layer `i`.
    FriRoot(u8),
    /// Folding challenge for FRI layer `i`.
    FriFoldChallenge(u8),
    /// Number of queries announced by the prover.
    QueryCount,
    /// Challenge stream used to derive query indices.
    QueryIndexStream,
    /// Final binding bytes stored in the proof envelope.
    ProofClose,
    /// Fork label used when creating deterministic sub transcripts.
    Fork,
}

impl TranscriptLabel {
    pub(crate) fn domain_tag(self) -> [u8; 16] {
        match self {
            TranscriptLabel::ParamsHash => *b"TR_LABEL_PARAMSH",
            TranscriptLabel::ProtocolTag => *b"TR_LABEL_PROTO__",
            TranscriptLabel::Seed => *b"TR_LABEL_SEED___",
            TranscriptLabel::ContextTag => *b"TR_LABEL_CTX____",
            TranscriptLabel::PublicInputsDigest => *b"TR_LABEL_PUBDIG_",
            TranscriptLabel::TraceRoot => *b"TR_LABEL_TRROOT_",
            TranscriptLabel::TraceChallengeA => *b"TR_LABEL_TRCHAL_",
            TranscriptLabel::CompRoot => *b"TR_LABEL_CPROOT_",
            TranscriptLabel::CompChallengeA => *b"TR_LABEL_CPCHAL_",
            TranscriptLabel::FriRoot(idx) => {
                let mut tag = *b"TR_LABEL_FRROOT_";
                tag[15] = idx;
                tag
            }
            TranscriptLabel::FriFoldChallenge(idx) => {
                let mut tag = *b"TR_LABEL_FRCHAL_";
                tag[15] = idx;
                tag
            }
            TranscriptLabel::QueryCount => *b"TR_LABEL_QCOUNT_",
            TranscriptLabel::QueryIndexStream => *b"TR_LABEL_QINDXS_",
            TranscriptLabel::ProofClose => *b"TR_LABEL_CLOSE__",
            TranscriptLabel::Fork => *b"TR_LABEL_FORK___",
        }
    }
}

/// Serialization error kinds surfaced by the transcript helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerKind {
    /// Field element encoding failed.
    Felt,
    /// Digest encoding failed.
    Digest,
    /// Byte absorption encoding failed.
    Bytes,
    /// Transcript state serialization error.
    State,
}

/// Error type returned by the transcript API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptError {
    /// Label was used outside of the documented phase ordering.
    InvalidLabel,
    /// Range exclusive argument was zero during `challenge_usize`.
    RangeZero,
    /// Internal counter overflowed the supported range.
    Overflow,
    /// Serialization error surfaced while absorbing inputs.
    Serialization(SerKind),
    /// Transcript usage violated documented bounds.
    BoundsViolation,
    /// Feature not supported by the deterministic transcript.
    Unsupported,
    /// Deterministic hashing helper failed.
    DeterministicHash(DeterministicHashError),
}

impl fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TranscriptError::InvalidLabel => write!(f, "label used outside canonical phase order"),
            TranscriptError::RangeZero => write!(f, "challenge range must be non-zero"),
            TranscriptError::Overflow => write!(f, "internal counter overflow"),
            TranscriptError::Serialization(kind) => write!(f, "serialization error: {:?}", kind),
            TranscriptError::BoundsViolation => write!(f, "transcript bounds violated"),
            TranscriptError::Unsupported => {
                write!(f, "feature unsupported in deterministic transcript")
            }
            TranscriptError::DeterministicHash(err) => {
                write!(f, "deterministic hash error: {err}")
            }
        }
    }
}

impl std::error::Error for TranscriptError {}

impl From<DeterministicHashError> for TranscriptError {
    fn from(err: DeterministicHashError) -> Self {
        TranscriptError::DeterministicHash(err)
    }
}
