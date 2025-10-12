//! Serialization utilities for proofs and transcripts.
//!
//! The types in this module model the byte-level representation of the
//! proof interface. They are intentionally thin wrappers around byte slices
//! but come with extensive documentation that mirrors the constraints imposed
//! by the proof formats documented elsewhere.

use serde::{Deserialize, Serialize};

/// Wrapper around proof bytes ensuring explicit conversions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBytes {
    /// Raw proof representation.
    bytes: Vec<u8>,
}

impl ProofBytes {
    /// Creates a new proof byte container.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// Opaque wrapper representing a byte encoded witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessBlob<'a> {
    /// Borrowed witness bytes provided by the caller.
    pub bytes: &'a [u8],
}

/// Fixed width digest byte array used throughout the documentation layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DigestBytes {
    /// Raw digest bytes (e.g. BLAKE3, SHA-256 etc.).
    pub bytes: [u8; 32],
}

/// Wrapper around field element encodings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldElementBytes {
    /// Little endian encoding of a field element.
    pub bytes: [u8; 32],
}
