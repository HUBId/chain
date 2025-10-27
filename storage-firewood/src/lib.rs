pub mod api;
pub mod kv;
pub mod pruning;
pub mod schema;
pub mod state;
pub mod tree;
pub mod wal;

pub use crate::state::FirewoodState as Storage;

#[cfg(test)]
mod tests {
    use std::env;

    use super::{kv::FirewoodKv, pruning::FirewoodPruner, tree::FirewoodTree};
    use rpp_pruning::{TaggedDigest, ENVELOPE_TAG, SNAPSHOT_STATE_TAG};

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
        let proof = pruner.prune_block(4, [2u8; 32]);
        assert!(pruner.verify_with_config([2u8; 32], &proof));
    }

    #[test]
    fn pruning_proof_rejects_tampering() {
        let mut pruner = FirewoodPruner::new(4);
        let root = [1u8; 32];
        let proof = pruner.prune_block(1, root);
        assert!(pruner.verify_with_config(root, &proof));
        assert!(!pruner.verify_with_config([0u8; 32], &proof));

        let mut digest = *proof.snapshot().state_commitment().digest();
        digest[0] ^= 0xFF;
        let corrupted_snapshot = rpp_pruning::Snapshot::new(
            proof.snapshot().schema_version(),
            proof.snapshot().parameter_version(),
            proof.snapshot().block_height(),
            TaggedDigest::new(SNAPSHOT_STATE_TAG, digest),
        )
        .expect("tag preserved");
        let segments = proof.segments().to_vec();
        let commitment = proof.commitment().clone();
        let mut binding_bytes = *proof.binding_digest().digest();
        binding_bytes[0] ^= 0xFF;
        let corrupted = rpp_pruning::Envelope::new(
            proof.schema_version(),
            proof.parameter_version(),
            corrupted_snapshot,
            segments,
            commitment,
            TaggedDigest::new(ENVELOPE_TAG, binding_bytes),
        )
        .expect("tag preserved");

        assert!(!pruner.verify_with_config(root, &corrupted));
    }

    #[test]
    fn state_commit_flow() {
        let dir = temp_dir("state");
        let state = super::state::FirewoodState::open(&dir).expect("open state");
        state.put(b"account".to_vec(), vec![1, 2, 3]);
        let (root, proof) = state.commit_block(1).expect("commit block");
        assert_eq!(root.len(), 32);
        assert!(FirewoodPruner::verify_pruned_state(root, proof.as_ref()));
    }
}
