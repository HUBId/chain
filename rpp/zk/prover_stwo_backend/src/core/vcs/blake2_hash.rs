use blake2::{Blake2s256, Digest};

/// Simple Blake2s hasher mirroring the interface exposed by the upstream
/// StarkWare crate.  The implementation is intentionally tiny; it only exposes
/// the primitives required by the RPP codebase (namely a deterministic hash of
/// arbitrary bytes).
#[derive(Debug, Default, Clone, Copy)]
pub struct Blake2sHasher;

/// Wrapper returned by [`Blake2sHasher::hash`] so callers can convert into a
/// fixed-size byte array using `.into()` just like with the original crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blake2sHash(pub [u8; 32]);

impl Blake2sHasher {
    /// Hash an arbitrary byte slice using Blake2s-256 and return the digest as a
    /// helper wrapper that can be converted into a `[u8; 32]` array.
    pub fn hash(input: &[u8]) -> Blake2sHash {
        let digest: [u8; 32] = Blake2s256::digest(input).into();
        Blake2sHash(digest)
    }
}

impl From<Blake2sHash> for [u8; 32] {
    fn from(value: Blake2sHash) -> Self {
        value.0
    }
}
