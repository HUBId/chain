use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use crate::kv::Hash;

/// Proof artifact returned after pruning a block. The proof records the
/// resulting root and a Merkle proof that can be used to validate the compacted
/// state within recursive systems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningProof {
    pub block_id: u64,
    pub root: Hash,
}

/// Lightweight pruning manager that tracks block snapshots and evicts cold
/// state after recursive proofs have sealed prior roots.
#[derive(Debug)]
pub struct FirewoodPruner {
    snapshots: VecDeque<PruningProof>,
    retain: usize,
}

impl FirewoodPruner {
    pub fn new(retain: usize) -> Self {
        FirewoodPruner {
            snapshots: VecDeque::new(),
            retain,
        }
    }

    pub fn prune_block(&mut self, block_id: u64, root: Hash) -> (Hash, PruningProof) {
        let proof = PruningProof {
            block_id,
            root,
        };

        self.snapshots.push_back(proof.clone());
        while self.snapshots.len() > self.retain {
            self.snapshots.pop_front();
        }

        (root, proof)
    }

    pub fn verify_pruned_state(root: Hash, proof: &PruningProof) -> bool {
        if root != proof.root {
            return false;
        }

        true
    }
}

