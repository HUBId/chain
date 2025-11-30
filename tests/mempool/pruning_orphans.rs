use rpp_chain::config::DEFAULT_PRUNING_RETENTION_DEPTH;
use rpp_chain::node::Node;
use rpp_chain::runtime::RuntimeMetrics;
use tempfile::tempdir;

#[path = "helpers.rs"]
mod helpers;
use helpers::{
    backend_for_index, enabled_backends, sample_node_config, sample_transaction_bundle,
    ProofBackend,
};

#[test]
fn pruning_cycle_reconciles_mempool_metadata_and_orphans() {
    let backends = enabled_backends();
    for (index, backend) in backends.iter().enumerate() {
        let temp = tempdir().expect("tempdir");
        let mut config = sample_node_config(temp.path(), 8);
        config.rollout.feature_gates.pruning = true;
        config.rollout.feature_gates.reconstruction = true;
        if matches!(backend, ProofBackend::RppStark) {
            config.rollout.feature_gates.recursive_proofs = true;
        }
        #[cfg(feature = "backend-plonky3")]
        if matches!(backend, ProofBackend::Plonky3) {
            config.rollout.feature_gates.recursive_proofs = true;
        }

        let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
        let handle = node.handle();
        let recipient = handle.address().to_string();

        let bundle =
            sample_transaction_bundle(&recipient, 1 + index as u64, 25 + index as u64, *backend);
        let hash = handle
            .submit_transaction(bundle.clone())
            .expect("enqueue wallet transaction");

        handle.drop_pending_transaction_metadata(&hash);
        let orphan_bundle =
            sample_transaction_bundle("orphan-target", 99 + index as u64, 5, *backend);
        let orphan_hash = orphan_bundle.hash();
        handle.seed_orphaned_transaction_metadata(orphan_bundle);

        let summary = handle
            .run_pruning_cycle(2, DEFAULT_PRUNING_RETENTION_DEPTH)
            .expect("pruning cycle");
        assert!(!summary.cancelled, "pruning should complete");

        let status = handle
            .mempool_status()
            .expect("mempool status after pruning");
        let recovered = status
            .transactions
            .iter()
            .find(|tx| tx.hash == hash)
            .expect("queued transaction should remain after pruning");
        assert!(
            recovered.witness.is_some(),
            "pruning should rehydrate missing wallet metadata"
        );
        assert!(
            recovered.proof_payload.is_some(),
            "pruning should retain proof payload for wallet transactions"
        );
        assert!(
            recovered.proof.is_some(),
            "pruning should retain zk proof for wallet transactions"
        );

        let metadata_hashes = handle.pending_transaction_metadata_hashes();
        assert!(
            metadata_hashes.contains(&hash),
            "queued transaction metadata should be present after pruning",
        );
        assert!(
            !metadata_hashes.contains(&orphan_hash),
            "orphaned metadata should be cleared during pruning",
        );
    }

    assert!(!backends.is_empty());
    let observed = backend_for_index(&backends, backends.len() - 1);
    assert!(backends.contains(&observed));
}
