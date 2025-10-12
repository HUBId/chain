#![cfg(feature = "backend-rpp-stark")]

use blake3::Hasher;

use super::digest::Digest32;

/// Wrapper exposing the 32-byte hash function used by the `rpp-stark` backend.
#[derive(Clone, Default)]
pub struct RppStarkHasher(Hasher);

impl RppStarkHasher {
    /// Creates a new hasher instance.
    #[inline]
    pub fn new() -> Self {
        Self(Hasher::new())
    }

    /// Feeds additional bytes into the hasher state.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Finalises the hasher and returns a [`Digest32`].
    #[inline]
    pub fn finalize(self) -> Digest32 {
        Digest32(self.0.finalize().into())
    }
}

/// Hashes the provided bytes into a 32-byte digest compatible with `rpp-stark`.
#[inline]
pub fn hash_bytes(data: &[u8]) -> Digest32 {
    let mut hasher = RppStarkHasher::new();
    hasher.update(data);
    hasher.finalize()
}
