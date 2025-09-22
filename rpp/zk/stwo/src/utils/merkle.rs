use crate::core::vcs::blake2_hash::Blake2sHasher;

/// Compute a simple binary Merkle root from a list of leaves.  Missing siblings
/// are replaced with the hash of the constant string `"stwo-empty"`.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return Blake2sHasher::hash(b"stwo-empty").0;
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 {
                chunk[1]
            } else {
                Blake2sHasher::hash(b"stwo-empty").0
            };
            let mut bytes = Vec::with_capacity(64);
            bytes.extend(left);
            bytes.extend(right);
            next.push(Blake2sHasher::hash(&bytes).0);
        }
        level = next;
    }
    level[0]
}
