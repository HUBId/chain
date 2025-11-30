use std::thread;
use std::time::Duration;

use rpp_chain::config::DEFAULT_PRUNING_RETENTION_DEPTH;
use rpp_chain::node::Node;
use rpp_chain::runtime::RuntimeMetrics;
use tempfile::tempdir;

#[path = "helpers.rs"]
mod helpers;
use helpers::{
    backend_for_index, enabled_backends, sample_node_config, sample_transaction_bundle, ProofBackend,
};

#[test]
fn pruning_cycles_observe_mempool_backlog_across_backends() {
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

        let bundle = sample_transaction_bundle("recipient", 1 + index as u64, 10, *backend);
        handle
            .submit_transaction(bundle)
            .expect("submit transaction to mempool");

        thread::sleep(Duration::from_millis(10));

        let status_before = handle.mempool_status().expect("mempool status before");
        let latency_before = handle
            .mempool_latency_ms()
            .expect("latency before")
            .expect("latency sample before");

        let summary = handle
            .run_pruning_cycle(2, DEFAULT_PRUNING_RETENTION_DEPTH)
            .expect("pruning cycle");
        assert!(!summary.cancelled, "pruning should complete");

        let status_after = handle.mempool_status().expect("mempool status after");
        let latency_after = handle
            .mempool_latency_ms()
            .expect("latency after")
            .expect("latency sample after");

        assert_eq!(
            status_before.transactions.len(),
            status_after.transactions.len(),
            "pruning must not drop transactions in mempool",
        );
        assert!(
            latency_after >= latency_before,
            "oldest transaction age should be monotonic"
        );
    }

    // ensure helper stays in sync with enabled backends
    assert!(!backends.is_empty());
    let observed = backend_for_index(&backends, backends.len() - 1);
    assert!(backends.contains(&observed));
}
