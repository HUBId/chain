use crate::params::{Endianness, MerkleArity};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Canonical digest used inside Merkle proofs and auxiliary data.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest {
    bytes: Vec<u8>,
}

impl Digest {
    /// Creates a digest from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the canonical zero digest of the provided size.
    pub fn zero(len: usize) -> Self {
        Self {
            bytes: vec![0u8; len],
        }
    }

    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the digest and returns the bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Mutable view into the digest bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest(0x")?;
        for byte in &self.bytes {
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ")")
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Canonical leaf representation – concatenated little-endian field bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leaf {
    bytes: Vec<u8>,
}

impl Leaf {
    /// Creates a leaf from already ordered bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns a view of the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the leaf and returns its byte payload.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Merkle node helper storing the digest together with its index within the level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub index: u32,
    pub digest: Digest,
}

/// Helper describing the tree depth measured in number of levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeDepth(pub u32);

/// Canonical proof node for Merkle paths.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofNode {
    /// Binary tree siblings ordered left-to-right.
    Arity2([Digest; 1]),
    /// Quaternary tree siblings ordered left-to-right.
    Arity4([Digest; 3]),
}

impl ProofNode {
    /// Returns the siblings stored in the node.
    pub fn siblings(&self) -> &[Digest] {
        match self {
            ProofNode::Arity2(list) => list,
            ProofNode::Arity4(list) => list,
        }
    }

    /// Mutable access to siblings.
    pub fn siblings_mut(&mut self) -> &mut [Digest] {
        match self {
            ProofNode::Arity2(list) => list,
            ProofNode::Arity4(list) => list,
        }
    }
}

/// Canonical serialisation error domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerKind {
    Proof,
    CommitAux,
}

/// Errors emitted by the Merkle layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    EmptyLeaves,
    LeafWidthMismatch { expected: u8, got: u8 },
    IndexOutOfRange { index: u32, max: u32 },
    DuplicateIndex { index: u32 },
    NotCommitted,
    ArityMismatch,
    Serialization(SerKind),
    IncompatibleParams { reason: &'static str },
    ProofVersionMismatch { expected: u16, got: u16 },
    InvalidPathLength,
    InvalidTreeState { reason: &'static str },
    VerificationFailed,
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleError::EmptyLeaves => write!(f, "no leaves supplied"),
            MerkleError::LeafWidthMismatch { expected, got } => {
                write!(f, "leaf width mismatch: expected {}, got {}", expected, got)
            }
            MerkleError::IndexOutOfRange { index, max } => {
                write!(f, "index {} out of range (max {})", index, max)
            }
            MerkleError::DuplicateIndex { index } => {
                write!(f, "duplicate index {}", index)
            }
            MerkleError::NotCommitted => write!(f, "tree not committed"),
            MerkleError::ArityMismatch => write!(f, "arity mismatch"),
            MerkleError::Serialization(kind) => {
                write!(f, "serialisation error in {:?}", kind)
            }
            MerkleError::IncompatibleParams { reason } => {
                write!(f, "incompatible parameters: {}", reason)
            }
            MerkleError::ProofVersionMismatch { expected, got } => write!(
                f,
                "proof version mismatch: expected {}, got {}",
                expected, got
            ),
            MerkleError::InvalidPathLength => write!(f, "invalid path length"),
            MerkleError::InvalidTreeState { reason } => {
                write!(f, "invalid tree state: {}", reason)
            }
            MerkleError::VerificationFailed => write!(f, "verification failed"),
        }
    }
}

impl std::error::Error for MerkleError {}

/// Newtype alias exported for documentation clarity.
pub type EndianEncoding = Endianness;

/// Additional helpers for [`MerkleArity`].
pub trait MerkleArityExt {
    fn as_usize(&self) -> usize;
}

impl MerkleArityExt for MerkleArity {
    fn as_usize(&self) -> usize {
        match self {
            MerkleArity::Binary => 2,
            MerkleArity::Quaternary => 4,
        }
    }
}
