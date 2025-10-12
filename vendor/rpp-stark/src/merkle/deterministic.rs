use crate::hash::deterministic::Hasher;
use crate::params::HashFamily;
use std::convert::TryInto;

use super::traits::MerkleHasher;

/// Deterministic pseudo BLAKE-based Merkle hasher used for testing.
pub struct DeterministicMerkleHasher;

impl MerkleHasher for DeterministicMerkleHasher {
    type Digest = [u8; 32];

    fn hash_leaves(domain_sep: u64, ordered_leaf_bytes: &[u8]) -> Self::Digest {
        hash_with_tag(0x00, domain_sep, ordered_leaf_bytes)
    }

    fn hash_nodes(domain_sep: u64, ordered_children: &[Self::Digest]) -> Self::Digest {
        let mut hasher = Hasher::new();
        hasher.update(&[0x01]);
        hasher.update(&domain_sep.to_le_bytes());
        for digest in ordered_children {
            hasher.update(digest);
        }
        hasher.finalize().into_bytes()
    }

    fn digest_size() -> usize {
        32
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self::Digest> {
        bytes.try_into().ok()
    }

    fn hash_family() -> HashFamily {
        HashFamily::Blake2s
    }
}

fn hash_with_tag(tag: u8, domain_sep: u64, payload: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(&[tag]);
    hasher.update(&domain_sep.to_le_bytes());
    hasher.update(payload);
    hasher.finalize().into_bytes()
}
