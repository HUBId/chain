use crate::core::vcs::blake2_hash::Blake2sHasher;
use crate::params::{poseidon_constants, FieldElement};

/// Compute a Poseidon-style hash over a list of field elements.  The
/// implementation is intentionally simplified: instead of executing the full
/// Poseidon permutation it concatenates the field element bytes and hashes them
/// with Blake2s.  This keeps proofs deterministic while avoiding heavy
/// arithmetic, which is sufficient for local development and integration tests.
pub fn hash_elements(inputs: &[FieldElement]) -> [u8; 32] {
    let mut buffer = Vec::with_capacity(inputs.len() * 16);
    for (index, element) in inputs.iter().enumerate() {
        let mut bytes = element.to_bytes();
        if let Some(constant) = poseidon_constants::ROUND_CONSTANTS.get(index) {
            for (i, byte) in constant.iter().enumerate() {
                if i < bytes.len() {
                    bytes[i] ^= *byte;
                }
            }
        }
        buffer.extend_from_slice(&bytes);
    }
    Blake2sHasher::hash(&buffer).0
}
