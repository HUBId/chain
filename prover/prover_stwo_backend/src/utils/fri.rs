use prover_backend_interface::determinism::deterministic_seed;
use rand::{rngs::OsRng, rngs::StdRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::core::vcs::blake2_hash::Blake2sHasher;
use crate::params::FieldElement;

/// Number of random queries sampled for the lightweight FRI proof.
const FRI_QUERY_COUNT: usize = 8;

/// Authentication query for a Merkle opening.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriQuery {
    pub position: usize,
    pub authentication_path: Vec<[u8; 32]>,
}

/// Lightweight FRI proof consisting of a Merkle commitment and random queries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriProof {
    seed: [u8; 32],
    commitment: [u8; 32],
    queries: Vec<FriQuery>,
}

impl FriProof {
    /// Create an empty proof wrapper used by tests and default values.
    pub fn empty() -> Self {
        Self {
            seed: [0u8; 32],
            commitment: empty_hash(),
            queries: Vec::new(),
        }
    }

    pub(crate) fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("fri proof is serialisable")
    }
}

pub struct FriProver;

impl FriProver {
    /// Commit to a list of field elements by hashing them into a Merkle tree.
    pub fn commit(values: &[FieldElement]) -> [u8; 32] {
        let leaves: Vec<[u8; 32]> = values.iter().map(hash_leaf).collect();
        merkle_root(&leaves)
    }

    /// Produce a proof by sampling random query positions and returning their authentication paths.
    pub fn prove(values: &[FieldElement]) -> FriProof {
        let seed = random_seed();
        let leaves: Vec<[u8; 32]> = values.iter().map(hash_leaf).collect();
        let tree = build_merkle_tree(&leaves);
        let commitment = tree.last().unwrap()[0];
        let query_count = desired_query_count(values.len());
        let positions = sample_positions(seed, values.len(), query_count);
        let queries = positions
            .into_iter()
            .map(|position| FriQuery {
                position,
                authentication_path: authentication_path(&tree, position),
            })
            .collect();

        FriProof {
            seed,
            commitment,
            queries,
        }
    }

    /// Verify a proof by recomputing the expected commitment and checking all Merkle openings.
    pub fn verify(values: &[FieldElement], proof: &FriProof) -> bool {
        let expected_commitment = Self::commit(values);
        if proof.commitment != expected_commitment {
            return false;
        }

        let query_count = desired_query_count(values.len());
        if proof.queries.len() != query_count {
            return false;
        }

        let expected_positions = sample_positions(proof.seed, values.len(), query_count);
        for (query, expected_position) in proof.queries.iter().zip(expected_positions.iter()) {
            if query.position != *expected_position || query.position >= values.len() {
                return false;
            }
            if !verify_path(
                &values[query.position],
                query.position,
                &proof.commitment,
                &query.authentication_path,
            ) {
                return false;
            }
        }

        true
    }
}

/// Compress a proof by hashing its serialised representation.
pub fn compress_proof(proof: &FriProof) -> [u8; 32] {
    let encoded = proof.bytes();
    Blake2sHasher::hash(&encoded).0
}

fn desired_query_count(len: usize) -> usize {
    len.min(FRI_QUERY_COUNT)
}

fn random_seed() -> [u8; 32] {
    if let Some(seed) = deterministic_seed() {
        return seed;
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

fn empty_hash() -> [u8; 32] {
    Blake2sHasher::hash(b"stwo-empty").0
}

fn hash_leaf(value: &FieldElement) -> [u8; 32] {
    Blake2sHasher::hash(&value.to_bytes()).0
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buffer = [0u8; 64];
    buffer[..32].copy_from_slice(left);
    buffer[32..].copy_from_slice(right);
    Blake2sHasher::hash(&buffer).0
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return empty_hash();
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 {
                chunk[1]
            } else {
                empty_hash()
            };
            next.push(hash_pair(&left, &right));
        }
        level = next;
    }
    level[0]
}

fn build_merkle_tree(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() {
        return vec![vec![empty_hash()]];
    }

    let mut levels = Vec::new();
    let mut current = leaves.to_vec();
    levels.push(current.clone());

    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        for chunk in current.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 {
                chunk[1]
            } else {
                empty_hash()
            };
            next.push(hash_pair(&left, &right));
        }
        current = next;
        levels.push(current.clone());
    }

    levels
}

fn authentication_path(levels: &[Vec<[u8; 32]>], mut index: usize) -> Vec<[u8; 32]> {
    if levels.len() <= 1 {
        return Vec::new();
    }

    let mut path = Vec::with_capacity(levels.len() - 1);
    for level in levels.iter().take(levels.len() - 1) {
        let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
        let sibling = if sibling_index < level.len() {
            level[sibling_index]
        } else {
            empty_hash()
        };
        path.push(sibling);
        index /= 2;
    }
    path
}

fn verify_path(value: &FieldElement, mut index: usize, root: &[u8; 32], path: &[[u8; 32]]) -> bool {
    let mut node = hash_leaf(value);
    for sibling in path {
        if index % 2 == 0 {
            node = hash_pair(&node, sibling);
        } else {
            node = hash_pair(sibling, &node);
        }
        index /= 2;
    }
    node == *root
}

fn sample_positions(seed: [u8; 32], domain: usize, count: usize) -> Vec<usize> {
    if domain == 0 || count == 0 {
        return Vec::new();
    }

    let mut rng = StdRng::from_seed(seed);
    let mut positions = BTreeSet::new();
    while positions.len() < count {
        let draw = (rng.next_u64() as usize) % domain;
        positions.insert(draw);
    }
    positions.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prover_backend_interface::determinism::DETERMINISTIC_ENV;
    use std::env;

    struct DeterminismGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl DeterminismGuard {
        fn enabled() -> Self {
            let previous = env::var_os(DETERMINISTIC_ENV);
            env::set_var(DETERMINISTIC_ENV, "1");
            Self { previous }
        }
    }

    impl Drop for DeterminismGuard {
        fn drop(&mut self) {
            if let Some(value) = self.previous.take() {
                env::set_var(DETERMINISTIC_ENV, value);
            } else {
                env::remove_var(DETERMINISTIC_ENV);
            }
        }
    }

    #[test]
    fn proof_roundtrip_succeeds() {
        let values = vec![FieldElement::from(5u128), FieldElement::from(42u128)];
        let proof = FriProver::prove(&values);
        assert!(FriProver::verify(&values, &proof));
    }

    #[test]
    fn proof_detects_tampering() {
        let values = vec![FieldElement::from(7u128), FieldElement::from(11u128)];
        let mut proof = FriProver::prove(&values);
        assert!(FriProver::verify(&values, &proof));

        // Corrupt one authentication path entry.
        if let Some(first_query) = proof.queries.first_mut() {
            if let Some(first_hash) = first_query.authentication_path.first_mut() {
                first_hash[0] ^= 0xFF;
            }
        }
        assert!(!FriProver::verify(&values, &proof));
    }

    #[test]
    fn proofs_use_random_seeds() {
        let values = vec![FieldElement::from(3u128), FieldElement::from(9u128)];
        let proof_a = FriProver::prove(&values);
        let proof_b = FriProver::prove(&values);
        assert_ne!(proof_a.seed, proof_b.seed);
    }

    #[test]
    fn deterministic_mode_reuses_seeds() {
        let _guard = DeterminismGuard::enabled();
        let values = vec![FieldElement::from(7u128), FieldElement::from(13u128)];
        let proof_a = FriProver::prove(&values);
        let proof_b = FriProver::prove(&values);
        assert_eq!(proof_a, proof_b);
    }
}
