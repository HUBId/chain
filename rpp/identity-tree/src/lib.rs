use std::collections::{HashMap, HashSet};

use prover_backend_interface::Blake2sHasher;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Depth of the sparse identity commitment tree.
pub const IDENTITY_TREE_DEPTH: usize = 32;
const EMPTY_LEAF_DOMAIN: &[u8] = b"rpp-zsi-empty-leaf";
const NODE_DOMAIN: &[u8] = b"rpp-zsi-node";

/// Errors that can be produced while manipulating the identity commitment tree.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityTreeError {
    /// Raised when a hex string fails to decode.
    #[error("invalid {label} encoding: {source}")]
    InvalidEncoding {
        label: String,
        #[source]
        source: hex::FromHexError,
    },
    /// Raised when a decoded value does not match the required length.
    #[error("{label} must encode exactly 32 bytes")]
    InvalidLength { label: String, actual: usize },
    /// Raised when an existing commitment does not match the expected value.
    #[error("identity commitment tree mismatch for wallet")]
    CommitmentMismatch,
    /// Raised when inserting a commitment that is already present in the tree.
    #[error("identity commitment already registered")]
    CommitmentAlreadyRegistered,
    /// Raised when a provided Merkle path does not match the configured depth.
    #[error("identity commitment proof has invalid length")]
    InvalidProofLength { expected: usize, actual: usize },
}

/// Convenient result alias for identity tree operations.
pub type IdentityTreeResult<T> = Result<T, IdentityTreeError>;

fn domain_hash(label: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(label.len() + bytes.len());
    data.extend_from_slice(label);
    data.extend_from_slice(bytes);
    Blake2sHasher::hash(&data).into()
}

fn hash_children(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(left);
    bytes.extend_from_slice(right);
    domain_hash(NODE_DOMAIN, &bytes)
}

fn default_leaf() -> [u8; 32] {
    domain_hash(EMPTY_LEAF_DOMAIN, &[])
}

fn decode_hex_leaf(value: &str, label: &str) -> IdentityTreeResult<[u8; 32]> {
    let bytes = hex::decode(value).map_err(|source| IdentityTreeError::InvalidEncoding {
        label: label.to_string(),
        source,
    })?;
    if bytes.len() != 32 {
        return Err(IdentityTreeError::InvalidLength {
            label: label.to_string(),
            actual: bytes.len(),
        });
    }
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(&bytes);
    Ok(leaf)
}

fn encode_hex_leaf(value: &[u8; 32]) -> String {
    hex::encode(value)
}

fn derive_index(wallet_addr: &str) -> u64 {
    let hash: [u8; 32] = Blake2sHasher::hash(wallet_addr.as_bytes()).into();
    u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]) as u64
}

fn compute_default_nodes(depth: usize) -> Vec<[u8; 32]> {
    let mut defaults = vec![[0u8; 32]; depth + 1];
    defaults[depth] = default_leaf();
    for level in (0..depth).rev() {
        defaults[level] = hash_children(&defaults[level + 1], &defaults[level + 1]);
    }
    defaults
}

fn node_value(
    level: usize,
    index: u64,
    depth: usize,
    leaves: &HashMap<u64, [u8; 32]>,
    defaults: &[[u8; 32]],
) -> [u8; 32] {
    if level == depth {
        return leaves.get(&index).copied().unwrap_or(defaults[depth]);
    }
    let left = node_value(level + 1, index * 2, depth, leaves, defaults);
    let right = node_value(level + 1, index * 2 + 1, depth, leaves, defaults);
    hash_children(&left, &right)
}

/// Sparse Merkle tree maintaining the identity commitment set.
#[derive(Clone, Debug)]
pub struct IdentityCommitmentTree {
    depth: usize,
    leaves: HashMap<u64, [u8; 32]>,
    slots: HashMap<u64, String>,
    commitments: HashSet<String>,
    defaults: Vec<[u8; 32]>,
}

impl IdentityCommitmentTree {
    pub fn new(depth: usize) -> Self {
        let depth = depth.max(1);
        let defaults = compute_default_nodes(depth);
        Self {
            depth,
            leaves: HashMap::new(),
            slots: HashMap::new(),
            commitments: HashSet::new(),
            defaults,
        }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn default_leaf_hex() -> String {
        encode_hex_leaf(&default_leaf())
    }

    pub fn root(&self) -> [u8; 32] {
        node_value(0, 0, self.depth, &self.leaves, &self.defaults)
    }

    pub fn root_hex(&self) -> String {
        encode_hex_leaf(&self.root())
    }

    pub fn contains_commitment(&self, commitment: &str) -> bool {
        self.commitments.contains(commitment)
    }

    pub fn leaf_hex(&self, wallet_addr: &str) -> String {
        let index = derive_index(wallet_addr);
        let leaf = self
            .leaves
            .get(&index)
            .copied()
            .unwrap_or(self.defaults[self.depth]);
        encode_hex_leaf(&leaf)
    }

    pub fn is_vacant(&self, wallet_addr: &str) -> bool {
        let index = derive_index(wallet_addr);
        !self.slots.contains_key(&index)
    }

    pub fn proof_for(&self, wallet_addr: &str) -> IdentityCommitmentProof {
        let index = derive_index(wallet_addr);
        let mut idx = index;
        let mut siblings = Vec::with_capacity(self.depth);
        for level in (0..self.depth).rev() {
            let sibling_index = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling_value = node_value(
                level + 1,
                sibling_index,
                self.depth,
                &self.leaves,
                &self.defaults,
            );
            siblings.push(encode_hex_leaf(&sibling_value));
            idx /= 2;
        }
        IdentityCommitmentProof {
            leaf: self.leaf_hex(wallet_addr),
            siblings,
        }
    }

    pub fn replace_commitment(
        &mut self,
        wallet_addr: &str,
        previous: Option<&str>,
        new_commitment: &str,
    ) -> IdentityTreeResult<()> {
        let index = derive_index(wallet_addr);
        let existing = self.slots.get(&index).cloned();
        if let Some(ref stored) = existing {
            if Some(stored.as_str()) != previous {
                return Err(IdentityTreeError::CommitmentMismatch);
            }
        }
        if self.commitments.contains(new_commitment) && existing.as_deref() != Some(new_commitment)
        {
            return Err(IdentityTreeError::CommitmentAlreadyRegistered);
        }

        let commitment_bytes = decode_hex_leaf(new_commitment, "identity commitment")?;
        if let Some(prev_hex) = previous {
            self.commitments.remove(prev_hex);
        }
        self.leaves.insert(index, commitment_bytes);
        self.slots.insert(index, new_commitment.to_string());
        self.commitments.insert(new_commitment.to_string());
        Ok(())
    }

    pub fn force_insert(&mut self, wallet_addr: &str, commitment: &str) -> IdentityTreeResult<()> {
        let index = derive_index(wallet_addr);
        let commitment_bytes = decode_hex_leaf(commitment, "identity commitment")?;
        if let Some(previous) = self.slots.insert(index, commitment.to_string()) {
            self.commitments.remove(&previous);
        }
        self.leaves.insert(index, commitment_bytes);
        self.commitments.insert(commitment.to_string());
        Ok(())
    }

    pub fn clear(&mut self) {
        self.leaves.clear();
        self.slots.clear();
        self.commitments.clear();
    }
}

/// Commitment proof exposing the Merkle path for a wallet slot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityCommitmentProof {
    pub leaf: String,
    pub siblings: Vec<String>,
}

impl IdentityCommitmentProof {
    pub fn compute_root(&self, wallet_addr: &str) -> IdentityTreeResult<String> {
        if self.siblings.len() != IDENTITY_TREE_DEPTH {
            return Err(IdentityTreeError::InvalidProofLength {
                expected: IDENTITY_TREE_DEPTH,
                actual: self.siblings.len(),
            });
        }
        let mut value = decode_hex_leaf(&self.leaf, "identity commitment leaf")?;
        let mut index = derive_index(wallet_addr);
        for sibling_hex in &self.siblings {
            let sibling = decode_hex_leaf(sibling_hex, "identity commitment sibling")?;
            let (left, right) = if index % 2 == 0 {
                (value, sibling)
            } else {
                (sibling, value)
            };
            value = hash_children(&left, &right);
            index /= 2;
        }
        Ok(encode_hex_leaf(&value))
    }

    pub fn is_vacant(&self) -> IdentityTreeResult<bool> {
        let leaf = decode_hex_leaf(&self.leaf, "identity commitment leaf")?;
        Ok(leaf == default_leaf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_roundtrip() {
        let mut tree = IdentityCommitmentTree::new(IDENTITY_TREE_DEPTH);
        let wallet = "deadbeef";
        let commitment = "11".repeat(32);
        tree.force_insert(wallet, &commitment).unwrap();

        let proof = tree.proof_for(wallet);
        assert_eq!(proof.leaf, commitment);
        assert_eq!(proof.siblings.len(), IDENTITY_TREE_DEPTH);
        assert_eq!(proof.compute_root(wallet).unwrap(), tree.root_hex());
    }
}
