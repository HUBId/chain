use std::collections::VecDeque;

use crate::kv::Hash;
use serde::{Deserialize, Serialize};

const LEAF_PREFIX: &[u8] = b"fw-pruning-leaf";
const NODE_PREFIX: &[u8] = b"fw-pruning-node";

#[derive(Debug, Clone)]
struct Snapshot {
    commitment: Hash,
}

impl Snapshot {
    fn new(block_id: u64, root: Hash) -> Self {
        let commitment = leaf_commitment(block_id, &root);
        Snapshot { commitment }
    }
}

fn leaf_commitment(block_id: u64, root: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_PREFIX);
    hasher.update(&block_id.to_be_bytes());
    hasher.update(root);
    hasher.finalize().into()
}

fn hash_pair(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_PREFIX);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn merkle_root_and_path(leaves: &[Hash], index: usize) -> (Hash, Vec<Hash>) {
    if leaves.is_empty() {
        return ([0u8; 32], Vec::new());
    }

    let mut layer = leaves.to_vec();
    let mut path = Vec::new();
    let mut position = index;

    while layer.len() > 1 {
        let pair_index = if position % 2 == 0 {
            position + 1
        } else {
            position.saturating_sub(1)
        };

        let sibling = if pair_index < layer.len() {
            layer[pair_index]
        } else {
            layer[position]
        };
        path.push(sibling);

        let mut next_layer = Vec::with_capacity((layer.len() + 1) / 2);
        for chunk in layer.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
            next_layer.push(hash_pair(&left, &right));
        }

        position /= 2;
        layer = next_layer;
    }

    (layer[0], path)
}

/// Proof artifact returned after pruning a block. The proof records the
/// resulting root and a Merkle proof that can be used to validate the compacted
/// state within recursive systems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningProof {
    pub block_id: u64,
    pub root: Hash,
    pub commitment_root: Hash,
    pub leaf_index: u32,
    pub merkle_path: Vec<Hash>,
}

/// Lightweight pruning manager that tracks block snapshots and evicts cold
/// state after recursive proofs have sealed prior roots.
#[derive(Debug)]
pub struct FirewoodPruner {
    snapshots: VecDeque<Snapshot>,
    retain: usize,
}

impl FirewoodPruner {
    pub fn new(retain: usize) -> Self {
        FirewoodPruner {
            snapshots: VecDeque::new(),
            retain: retain.max(1),
        }
    }

    pub fn prune_block(&mut self, block_id: u64, root: Hash) -> (Hash, PruningProof) {
        let snapshot = Snapshot::new(block_id, root);
        self.snapshots.push_back(snapshot);
        while self.snapshots.len() > self.retain {
            self.snapshots.pop_front();
        }

        let leaves: Vec<Hash> = self
            .snapshots
            .iter()
            .map(|snapshot| snapshot.commitment)
            .collect();

        let index = leaves
            .len()
            .checked_sub(1)
            .expect("at least one snapshot retained");

        let (commitment_root, merkle_path) = merkle_root_and_path(&leaves, index);

        let proof = PruningProof {
            block_id,
            root,
            commitment_root,
            leaf_index: index as u32,
            merkle_path,
        };

        (commitment_root, proof)
    }

    pub fn verify_pruned_state(root: Hash, proof: &PruningProof) -> bool {
        if root != proof.commitment_root {
            return false;
        }

        let mut computed = leaf_commitment(proof.block_id, &proof.root);
        let mut position = proof.leaf_index as usize;

        for sibling in &proof.merkle_path {
            if position % 2 == 0 {
                computed = hash_pair(&computed, sibling);
            } else {
                computed = hash_pair(sibling, &computed);
            }
            position /= 2;
        }

        position == 0 && computed == proof.commitment_root
    }
}

#[cfg(test)]
mod tests_prop;
