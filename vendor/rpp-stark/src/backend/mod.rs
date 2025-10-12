//! Chain integration adapters for the `rpp-stark` backend.
//!
//! The types exposed here bridge the core primitives to the lightweight
//! interfaces that the node expects when the optional `backend-rpp-stark`
//! feature is enabled.  The adapters remain allocation-free and retain the
//! deterministic behaviour of the reference implementation.

use crate::field::prime_field::{
    CanonicalSerialize, ConstantTimeAssertions, FieldConstraintError, FieldDeserializeError,
    FieldElement,
};
use crate::hash::config::BLAKE2S_COMMITMENT_DOMAIN_TAG;
use crate::hash::deterministic::{
    Blake2sInteropHasher, Hash as DeterministicHash, Hasher as DeterministicHasher,
};
use crate::params::StarkParams;

/// Error emitted when converting between canonical field encodings and the
/// chain-specific felt wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeltConversionError {
    /// Canonicality constraint reported by the core field implementation.
    Constraint(FieldConstraintError),
    /// Deserialisation failure due to a non-canonical byte representation.
    Deserialize(FieldDeserializeError),
}

impl From<FieldConstraintError> for FeltConversionError {
    fn from(error: FieldConstraintError) -> Self {
        Self::Constraint(error)
    }
}

impl From<FieldDeserializeError> for FeltConversionError {
    fn from(error: FieldDeserializeError) -> Self {
        Self::Deserialize(error)
    }
}

/// Chain-facing felt wrapper around [`FieldElement`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Felt(pub FieldElement);

impl Felt {
    /// Attempts to wrap a field element after enforcing canonicality.
    pub fn from_field(element: FieldElement) -> Result<Self, FeltConversionError> {
        element.assert_canonical()?;
        Ok(Self(element))
    }

    /// Returns the inner field element without additional checks.
    pub fn into_field(self) -> FieldElement {
        self.0
    }

    /// Serialises the felt into little-endian bytes accepted by the node.
    pub fn to_le_bytes(&self) -> Result<[u8; 8], FeltConversionError> {
        Ok(self.0.to_bytes()?)
    }

    /// Deserialises the felt from canonical little-endian bytes.
    pub fn from_le_bytes(bytes: &[u8; 8]) -> Result<Self, FeltConversionError> {
        let element = FieldElement::from_bytes(bytes)?;
        Ok(Self(element))
    }
}

/// Trait describing the chain-level felt contract.
pub trait ChainFelt {
    /// Serialises the felt into canonical little-endian bytes.
    fn to_chain_bytes(&self) -> Result<[u8; 8], FeltConversionError>;
    /// Constructs the felt from canonical little-endian bytes.
    fn from_chain_bytes(bytes: &[u8; 8]) -> Result<Self, FeltConversionError>
    where
        Self: Sized;
    /// Provides access to the wrapped [`FieldElement`].
    fn as_field(&self) -> &FieldElement;
}

impl ChainFelt for Felt {
    fn to_chain_bytes(&self) -> Result<[u8; 8], FeltConversionError> {
        self.to_le_bytes()
    }

    fn from_chain_bytes(bytes: &[u8; 8]) -> Result<Self, FeltConversionError> {
        Self::from_le_bytes(bytes)
    }

    fn as_field(&self) -> &FieldElement {
        &self.0
    }
}

/// Chain-facing digest wrapper that retains the deterministic 32-byte output of
/// the Blake2s backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Digest {
    inner: DeterministicHash,
}

impl Digest {
    /// Length in bytes of the canonical digest representation.
    pub const LENGTH: usize = 32;

    /// Creates a digest adapter from deterministic hash bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            inner: DeterministicHash::from_bytes(bytes),
        }
    }

    /// Wraps an existing deterministic hash value.
    pub const fn from_hash(hash: DeterministicHash) -> Self {
        Self { inner: hash }
    }

    /// Returns the underlying deterministic hash.
    pub const fn into_hash(self) -> DeterministicHash {
        self.inner
    }

    /// Returns a reference to the digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.inner.as_bytes()
    }

    /// Consumes the digest and returns the raw byte array.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.inner.into_bytes()
    }
}

/// Trait describing the chain-level digest contract.
pub trait ChainDigest {
    /// Returns the canonical byte representation of the digest.
    fn as_chain_bytes(&self) -> &[u8; 32];
    /// Consumes the digest and returns the canonical byte array.
    fn into_chain_bytes(self) -> [u8; 32];
}

impl ChainDigest for Digest {
    fn as_chain_bytes(&self) -> &[u8; 32] {
        self.as_bytes()
    }

    fn into_chain_bytes(self) -> [u8; 32] {
        self.into_bytes()
    }
}

/// Deterministic Blake2s hasher seeded with the chain domain tag.
#[derive(Clone)]
pub struct Hasher {
    inner: DeterministicHasher<Blake2sInteropHasher>,
}

impl Hasher {
    /// Domain separation tag agreed upon with the node backend.
    pub const DOMAIN_TAG: &'static [u8] = BLAKE2S_COMMITMENT_DOMAIN_TAG;

    /// Creates a new hasher instance without absorbing the domain tag.
    pub fn new() -> Self {
        Self {
            inner: DeterministicHasher::<Blake2sInteropHasher>::with_backend(),
        }
    }

    /// Creates a new hasher instance and immediately absorbs the domain tag.
    pub fn new_with_domain_tag() -> Self {
        let mut hasher = Self::new();
        hasher.absorb_domain_tag();
        hasher
    }

    /// Absorbs the canonical domain tag into the hash state.
    pub fn absorb_domain_tag(&mut self) {
        self.inner.update(Self::DOMAIN_TAG);
    }

    /// Absorbs bytes into the deterministic Blake2s state.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalises the hasher and returns the chain digest wrapper.
    pub fn finalize(self) -> Digest {
        Digest::from_hash(self.inner.finalize())
    }
}

/// Trait describing the chain-level hashing contract.
pub trait ChainHasher {
    /// Associated digest type returned by the hasher.
    type Digest: ChainDigest;

    /// Returns the domain separation tag applied by the hasher.
    fn domain_tag() -> &'static [u8];
    /// Absorbs the canonical domain separation tag.
    fn absorb_domain_tag(&mut self);
    /// Absorbs bytes into the hash state.
    fn update(&mut self, data: &[u8]);
    /// Finalises the hash computation.
    fn finalize(self) -> Self::Digest;
}

impl ChainHasher for Hasher {
    type Digest = Digest;

    fn domain_tag() -> &'static [u8] {
        Self::DOMAIN_TAG
    }

    fn absorb_domain_tag(&mut self) {
        Hasher::absorb_domain_tag(self);
    }

    fn update(&mut self, data: &[u8]) {
        Hasher::update(self, data);
    }

    fn finalize(self) -> Self::Digest {
        Hasher::finalize(self)
    }
}

/// Errors that can be emitted while mapping proof size limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofSizeMappingError {
    /// Overflow when converting from kilobytes to bytes.
    Overflow { max_size_kb: u32 },
    /// Parameter and node limits disagree after applying ceiling semantics.
    Mismatch { params_kb: u32, expected_kb: u32 },
}

/// Converts the proof size limit from kilobytes (stored in [`StarkParams`]) to
/// bytes as enforced by the node configuration.
pub fn params_limit_to_node_bytes(params: &StarkParams) -> Result<u32, ProofSizeMappingError> {
    params
        .proof()
        .max_size_kb
        .checked_mul(1024)
        .ok_or(ProofSizeMappingError::Overflow {
            max_size_kb: params.proof().max_size_kb,
        })
}

/// Converts the node proof size limit in bytes to the canonical kilobyte value
/// stored inside [`StarkParams`].  The node applies ceiling semantics when
/// rounding to kilobytes.
pub fn node_limit_to_params_kb(node_limit_bytes: u32) -> u32 {
    node_limit_bytes.div_ceil(1024)
}

/// Ensures that the proof size limit stored in [`StarkParams`] matches the
/// configured node limit after applying canonical rounding semantics.
pub fn ensure_proof_size_consistency(
    params: &StarkParams,
    node_limit_bytes: u32,
) -> Result<(), ProofSizeMappingError> {
    let expected_kb = node_limit_to_params_kb(node_limit_bytes);
    let params_kb = params.proof().max_size_kb;
    if params_kb != expected_kb {
        return Err(ProofSizeMappingError::Mismatch {
            params_kb,
            expected_kb,
        });
    }
    // Also check for overflow when mapping back to bytes to catch large values.
    let _ = params_limit_to_node_bytes(params)?;
    Ok(())
}
