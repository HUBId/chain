use core::convert::TryInto;
use core::fmt;

use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};

/// Error surfaced by deterministic hashing helpers when slice conversions fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeterministicHashError {
    /// Conversion from a slice into a fixed-size array failed.
    SliceConversion {
        /// Length expected by the conversion routine.
        expected: usize,
    },
}

impl fmt::Display for DeterministicHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeterministicHashError::SliceConversion { expected } => {
                write!(f, "failed to convert slice into array of length {expected}")
            }
        }
    }
}

impl std::error::Error for DeterministicHashError {}

/// Internal deterministic hash value produced by the canonical helper.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash {
    bytes: [u8; 32],
}

impl Hash {
    /// Constructs a hash value from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Returns the canonical byte representation of the digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Consumes the hash and returns the underlying byte array.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.bytes
    }

    /// Returns a helper that formats the digest as lowercase hexadecimal.
    pub fn to_hex(&self) -> HexOutput {
        HexOutput(self.bytes)
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl From<Hash> for [u8; 32] {
    fn from(hash: Hash) -> Self {
        hash.into_bytes()
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash(0x{})", self.to_hex())
    }
}

/// Hexadecimal representation of a deterministic digest.
#[derive(Clone, Copy)]
pub struct HexOutput([u8; 32]);

impl fmt::Display for HexOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::Debug for HexOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Backend interface implemented by deterministic hashers.
pub trait DeterministicHasherBackend: Sized {
    /// Extendable output reader associated with the backend.
    type Xof: DeterministicXofBackend;

    /// Creates a new hasher instance.
    fn new() -> Self;

    /// Absorbs additional bytes into the hasher state.
    fn update(&mut self, bytes: &[u8]);

    /// Finalises the hasher and returns a 32-byte digest.
    fn finalize(self) -> [u8; 32];

    /// Finalises the hasher into an extendable output reader.
    fn finalize_xof(self) -> Self::Xof;
}

/// Backend interface implemented by deterministic XOF readers.
pub trait DeterministicXofBackend {
    /// Returns the next 64 bits from the deterministic stream.
    fn next_u64(&mut self) -> Result<u64, DeterministicHashError>;

    /// Fills the provided buffer with deterministic bytes from the XOF stream.
    fn fill(&mut self, output: &mut [u8]) -> Result<(), DeterministicHashError> {
        let mut offset = 0;
        while offset < output.len() {
            let word = self.next_u64()?;
            let bytes = word.to_le_bytes();
            let remaining = output.len() - offset;
            let take = remaining.min(bytes.len());
            output[offset..offset + take].copy_from_slice(&bytes[..take]);
            offset += take;
        }
        Ok(())
    }
}

/// Deterministic streaming helper mirroring the `blake3::Hasher` interface.
#[derive(Clone)]
pub struct Hasher<B: DeterministicHasherBackend = Blake2sInteropHasher> {
    backend: B,
}

impl Hasher<Blake2sInteropHasher> {
    /// Creates a new deterministic hasher instance using the default backend.
    pub fn new() -> Self {
        Self {
            backend: Blake2sInteropHasher::new(),
        }
    }
}

impl Default for Hasher<Blake2sInteropHasher> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: DeterministicHasherBackend> Hasher<B> {
    /// Creates a new deterministic hasher with an explicit backend.
    pub fn with_backend() -> Self {
        Self { backend: B::new() }
    }

    /// Absorbs additional bytes into the hasher state.
    pub fn update(&mut self, bytes: &[u8]) {
        self.backend.update(bytes);
    }

    /// Finalises the hasher and returns a 32-byte digest.
    pub fn finalize(self) -> Hash {
        Hash::from(self.backend.finalize())
    }

    /// Finalises the hasher into an extendable output reader.
    pub fn finalize_xof(self) -> OutputReader<B::Xof> {
        OutputReader {
            xof: self.backend.finalize_xof(),
        }
    }
}

/// Extendable output reader mirroring the `blake3::OutputReader` API.
#[derive(Debug, Clone)]
pub struct OutputReader<X = Blake2sXof> {
    xof: X,
}

impl<X: DeterministicXofBackend> OutputReader<X> {
    /// Fills the provided buffer with deterministic bytes from the XOF stream.
    ///
    /// Returns an error if the underlying slice conversion fails.
    pub fn fill(&mut self, output: &mut [u8]) -> Result<(), DeterministicHashError> {
        self.xof.fill(output)
    }

    /// Returns the next 64 bits from the deterministic stream.
    pub fn next_u64(&mut self) -> Result<u64, DeterministicHashError> {
        self.xof.next_u64()
    }
}

/// Computes a deterministic 32-byte hash of the provided payload using the
/// default backend.
pub fn hash(input: &[u8]) -> Hash {
    hash_with_backend::<Blake2sInteropHasher>(input)
}

/// Computes a deterministic 32-byte hash of the provided payload with a
/// user-specified backend.
pub fn hash_with_backend<B: DeterministicHasherBackend>(input: &[u8]) -> Hash {
    let mut hasher = Hasher::<B>::with_backend();
    hasher.update(input);
    hasher.finalize()
}

/// Deterministic Blake2s backend compatible with the STWO transcript layout.
#[derive(Clone)]
pub struct Blake2sInteropHasher {
    state: Blake2s256,
}

impl DeterministicHasherBackend for Blake2sInteropHasher {
    type Xof = Blake2sXof;

    fn new() -> Self {
        Self {
            state: Blake2s256::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        blake2::Digest::update(&mut self.state, bytes);
    }

    fn finalize(self) -> [u8; 32] {
        self.state.finalize().into()
    }

    fn finalize_xof(self) -> Self::Xof {
        Blake2sXof::from_state(self.state.finalize().into())
    }
}

impl Default for Blake2sInteropHasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Blake2s-based extendable output reader mirroring the STWO pseudo-XOF.
#[derive(Debug, Clone)]
pub struct Blake2sXof {
    state: [u8; 32],
    counter: u64,
}

impl Blake2sXof {
    /// Creates a new XOF instance from an arbitrary seed.
    pub fn new(seed: &[u8]) -> Self {
        let mut hasher = Blake2s256::new();
        blake2::Digest::update(&mut hasher, seed);
        blake2::Digest::update(&mut hasher, b"/XOF");
        Self {
            state: hasher.finalize().into(),
            counter: 0,
        }
    }

    /// Creates a new XOF starting from an existing 32-byte hash state.
    pub fn from_state(state: [u8; 32]) -> Self {
        Self { state, counter: 0 }
    }

    /// Returns the next 64 bits from the deterministic stream.
    pub fn next_u64(&mut self) -> Result<u64, DeterministicHashError> {
        DeterministicXofBackend::next_u64(self)
    }

    /// Fills the provided buffer with bytes from the stream.
    pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), DeterministicHashError> {
        DeterministicXofBackend::fill(self, output)
    }

    fn squeeze_block(&mut self) -> [u8; 32] {
        let mut hasher = Blake2s256::new();
        blake2::Digest::update(&mut hasher, self.state);
        blake2::Digest::update(&mut hasher, self.counter.to_le_bytes());
        let block: [u8; 32] = hasher.finalize().into();
        self.state = block;
        self.counter = self.counter.wrapping_add(1);
        block
    }
}

impl DeterministicXofBackend for Blake2sXof {
    fn next_u64(&mut self) -> Result<u64, DeterministicHashError> {
        let block = self.squeeze_block();
        let bytes: [u8; 8] = block[0..8]
            .try_into()
            .map_err(|_| DeterministicHashError::SliceConversion { expected: 8 })?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn fill(&mut self, output: &mut [u8]) -> Result<(), DeterministicHashError> {
        let mut remaining = output;
        while !remaining.is_empty() {
            let block = self.squeeze_block();
            let take = remaining.len().min(block.len());
            let (dst, rest) = remaining.split_at_mut(take);
            dst.copy_from_slice(&block[..take]);
            remaining = rest;
        }
        Ok(())
    }
}

/// Adapter backend that exposes Poseidon interoperability over Blake2s.
#[derive(Clone, Default)]
pub struct PoseidonInteropHasher {
    inner: Blake2sInteropHasher,
}

impl DeterministicHasherBackend for PoseidonInteropHasher {
    type Xof = Blake2sXof;

    fn new() -> Self {
        Self {
            inner: Blake2sInteropHasher::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    fn finalize(self) -> [u8; 32] {
        self.inner.finalize()
    }

    fn finalize_xof(self) -> Self::Xof {
        self.inner.finalize_xof()
    }
}

/// Adapter backend that exposes Rescue interoperability over Blake2s.
#[derive(Clone, Default)]
pub struct RescueInteropHasher {
    inner: Blake2sInteropHasher,
}

impl DeterministicHasherBackend for RescueInteropHasher {
    type Xof = Blake2sXof;

    fn new() -> Self {
        Self {
            inner: Blake2sInteropHasher::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes);
    }

    fn finalize(self) -> [u8; 32] {
        self.inner.finalize()
    }

    fn finalize_xof(self) -> Self::Xof {
        self.inner.finalize_xof()
    }
}
