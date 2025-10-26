use std::sync::Arc;

use parking_lot::{Mutex, RwLock};
use thiserror::Error;

use crate::{
    kv::{FirewoodKv, Hash, KvError},
    pruning::{FirewoodPruner, PruningProof},
    tree::{FirewoodTree, MerkleProof},
};

pub type StateRoot = Hash;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("kv error: {0}")]
    Kv(#[from] KvError),
}

pub struct FirewoodState {
    kv: Mutex<FirewoodKv>,
    tree: RwLock<FirewoodTree>,
    pruner: Mutex<FirewoodPruner>,
}

impl FirewoodState {
    pub fn open(path: &str) -> Result<Arc<Self>, StateError> {
        let kv = FirewoodKv::open(path)?;
        let mut tree = FirewoodTree::new();
        for (key, value) in kv.scan_prefix(b"") {
            tree.update(&key, value);
        }
        let pruner = FirewoodPruner::new(3);
        Ok(Arc::new(FirewoodState {
            kv: Mutex::new(kv),
            tree: RwLock::new(tree),
            pruner: Mutex::new(pruner),
        }))
    }

    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.kv.lock().get(key)
    }

    pub fn put(&self, key: Vec<u8>, value: Vec<u8>) {
        self.kv.lock().put(key.clone(), value.clone());
        let mut tree = self.tree.write();
        tree.update(&key, value);
    }

    pub fn delete(&self, key: &[u8]) {
        self.kv.lock().delete(key);
        let mut tree = self.tree.write();
        tree.delete(key);
    }

    pub fn commit_block(&self, block_id: u64) -> Result<(StateRoot, PruningProof), StateError> {
        let mut kv = self.kv.lock();
        let root = kv.commit()?;
        let mut pruner = self.pruner.lock();
        let proof = pruner.prune_block(block_id, root);
        Ok((root, proof))
    }

    pub fn prove(&self, key: &[u8]) -> MerkleProof {
        let tree = self.tree.read();
        tree.get_proof(key)
    }
}
