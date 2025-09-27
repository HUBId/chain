pub mod api;
pub mod kv;
pub mod pruning;
pub mod schema;
pub mod state;
pub mod tree;
pub mod wal;

#[cfg(test)]
mod tests {
    use std::env;

    use super::{kv::FirewoodKv, pruning::FirewoodPruner, tree::FirewoodTree};

    fn temp_dir(name: &str) -> String {
        let mut dir = env::temp_dir();
        dir.push(format!("firewood-{}", name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn kv_roundtrip_and_commit() {
        let dir = temp_dir("kv");
        let mut kv = FirewoodKv::open(&dir).expect("open kv");
        kv.put(b"alpha".to_vec(), b"one".to_vec());
        kv.put(b"beta".to_vec(), b"two".to_vec());
        let root = kv.commit().expect("commit");
        assert_eq!(kv.get(b"alpha"), Some(b"one".to_vec()));
        assert_eq!(kv.get(b"beta"), Some(b"two".to_vec()));
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn tree_proof_verifies() {
        let mut tree = FirewoodTree::new();
        let root = tree.update(b"key", b"value".to_vec());
        let proof = tree.get_proof(b"key");
        assert!(super::tree::FirewoodTree::verify_proof(&root, &proof));
    }

    #[test]
    fn pruner_retains_recent_snapshots() {
        let mut pruner = FirewoodPruner::new(2);
        pruner.prune_block(1, [0u8; 32]);
        pruner.prune_block(2, [1u8; 32]);
        pruner.prune_block(3, [2u8; 32]);
        let (commitment_root, proof) = pruner.prune_block(4, [2u8; 32]);
        assert!(FirewoodPruner::verify_pruned_state(commitment_root, &proof));
    }

    #[test]
    fn pruning_proof_rejects_tampering() {
        let mut pruner = FirewoodPruner::new(4);
        let (commitment_root, mut proof) = pruner.prune_block(1, [1u8; 32]);
        assert!(FirewoodPruner::verify_pruned_state(commitment_root, &proof));
        assert!(!FirewoodPruner::verify_pruned_state([0u8; 32], &proof));

        // Corrupt the stored merkle path and expect verification to fail.
        if let Some(first) = proof.merkle_path.first_mut() {
            first[0] ^= 0xFF;
        } else {
            proof.commitment_root[0] ^= 0xFF;
        }
        assert!(!FirewoodPruner::verify_pruned_state(
            commitment_root,
            &proof
        ));
    }

    #[test]
    fn state_commit_flow() {
        let dir = temp_dir("state");
        let state = super::state::FirewoodState::open(&dir).expect("open state");
        state.put(b"account".to_vec(), vec![1, 2, 3]);
        let (root, proof) = state.commit_block(1).expect("commit block");
        assert_eq!(root.len(), 32);
        assert!(FirewoodPruner::verify_pruned_state(
            proof.commitment_root,
            &proof
        ));
    }
}
