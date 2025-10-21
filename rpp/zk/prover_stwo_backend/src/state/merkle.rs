/// Compute a binary Merkle root over the provided leaves using the blueprint
/// Blake2s hasher.  The implementation reuses the helper from the utils module
/// to keep the behaviour consistent across the crate.
pub fn compute_merkle_root(leaves: &mut Vec<[u8; 32]>) -> [u8; 32] {
    crate::utils::merkle::merkle_root(leaves.as_slice())
}
