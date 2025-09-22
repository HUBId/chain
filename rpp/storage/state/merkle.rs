use stwo::core::vcs::blake2_hash::Blake2sHasher;

/// Compute a binary merkle root over the provided leaves.
///
/// Leaves are hashed as provided and sorted lexicographically before building
/// the tree to guarantee deterministic aggregation across modules.
pub fn compute_merkle_root(leaves: &mut Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return Blake2sHasher::hash(b"rpp-empty").into();
    }
    leaves.sort();
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for chunk in leaves.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&left);
            data.extend_from_slice(&right);
            next.push(Blake2sHasher::hash(&data).into());
        }
        *leaves = next;
    }
    leaves[0]
}
