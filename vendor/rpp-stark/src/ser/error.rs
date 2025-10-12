use core::fmt;
use serde::{Deserialize, Serialize};

/// Context markers used when reporting serialization failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerKind {
    /// Top-level proof framing.
    Proof,
    /// Merkle commitment bundle section.
    TraceCommitment,
    /// Optional composition commitment digest.
    CompositionCommitment,
    /// Embedded FRI proof payload.
    Fri,
    /// Out-of-domain openings section.
    Openings,
    /// Telemetry frame storing auxiliary metadata.
    Telemetry,
    /// Serialized public-input body.
    PublicInputs,
    /// Parameter set framing.
    Params,
}

impl fmt::Display for SerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerKind::Proof => write!(f, "proof"),
            SerKind::TraceCommitment => write!(f, "trace commitment"),
            SerKind::CompositionCommitment => write!(f, "composition commitment"),
            SerKind::Fri => write!(f, "fri"),
            SerKind::Openings => write!(f, "openings"),
            SerKind::Telemetry => write!(f, "telemetry"),
            SerKind::PublicInputs => write!(f, "public inputs"),
            SerKind::Params => write!(f, "params"),
        }
    }
}

/// Canonical serialization error surfaced while encoding or decoding data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SerError {
    /// Input ended before the expected number of bytes were read.
    UnexpectedEnd {
        /// Structure or section that failed to decode.
        kind: SerKind,
        /// Field that was being processed.
        field: &'static str,
    },
    /// A length prefix exceeded the configured bounds or remaining buffer.
    InvalidLength {
        /// Structure or section that failed to decode.
        kind: SerKind,
        /// Field that was being processed.
        field: &'static str,
    },
    /// Encountered an unexpected discriminant or mismatching digest.
    InvalidValue {
        /// Structure or section that failed to decode.
        kind: SerKind,
        /// Field that was being processed.
        field: &'static str,
    },
    /// Additional bytes remained after consuming the expected payload.
    TrailingBytes {
        /// Structure or section that failed to decode.
        kind: SerKind,
        /// Position reached by the decoder.
        consumed: usize,
        /// Number of remaining bytes.
        remaining: usize,
    },
}

impl SerError {
    /// Creates an unexpected-end error helper.
    pub fn unexpected_end(kind: SerKind, field: &'static str) -> Self {
        SerError::UnexpectedEnd { kind, field }
    }

    /// Creates an invalid-length error helper.
    pub fn invalid_length(kind: SerKind, field: &'static str) -> Self {
        SerError::InvalidLength { kind, field }
    }

    /// Creates an invalid-value error helper.
    pub fn invalid_value(kind: SerKind, field: &'static str) -> Self {
        SerError::InvalidValue { kind, field }
    }

    /// Creates a trailing-bytes error helper.
    pub fn trailing_bytes(kind: SerKind, consumed: usize, remaining: usize) -> Self {
        SerError::TrailingBytes {
            kind,
            consumed,
            remaining,
        }
    }

    /// Returns the serialization context associated with the error.
    pub fn kind(&self) -> SerKind {
        match *self {
            SerError::UnexpectedEnd { kind, .. }
            | SerError::InvalidLength { kind, .. }
            | SerError::InvalidValue { kind, .. }
            | SerError::TrailingBytes { kind, .. } => kind,
        }
    }
}

/// Convenient alias for serialization results.
pub type SerResult<T> = core::result::Result<T, SerError>;
