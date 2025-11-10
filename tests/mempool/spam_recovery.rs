use anyhow::Result;
use tempfile::tempdir;

use rpp_chain::errors::ChainError;
use rpp_chain::node::Node;
use rpp_chain::runtime::RuntimeMetrics;

use super::helpers::{
    drain_witness_channel, recv_witness_transaction, sample_node_config, sample_transaction_bundle,
    witness_topic,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn high_volume_spam_triggers_rate_limits_and_recovers() -> Result<()> {
    let tempdir = tempdir()?;
    let mempool_limit = 6usize;
    let overflow = 3usize;

    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = node.handle();
    let mut witness_rx = handle.subscribe_witness_gossip(witness_topic());

    let recipient = handle.address().to_string();
    let mut accepted_hashes = Vec::new();

    for index in 0..mempool_limit {
        let fee = 10 + index as u64;
        let bundle = sample_transaction_bundle(&recipient, index as u64, fee);
        let hash = handle
            .submit_transaction(bundle)
            .expect("initial transaction accepted before reaching mempool capacity");
        accepted_hashes.push((hash.clone(), fee));

        let event = recv_witness_transaction(&mut witness_rx)
            .await
            .expect("witness gossip event for accepted transaction");
        assert_eq!(
            event.hash, hash,
            "gossip event should include submitted hash"
        );
        assert_eq!(event.fee, fee, "gossip event should report transaction fee");

        let status = handle
            .node_status()
            .expect("poll node status after acceptance");
        assert_eq!(
            status.pending_transactions,
            accepted_hashes.len(),
            "node metrics should reflect pending transaction count"
        );
    }

    let mut rejected = 0usize;
    for index in 0..overflow {
        let fee = 100 + index as u64;
        let bundle = sample_transaction_bundle(&recipient, (mempool_limit + index) as u64, fee);
        match handle.submit_transaction(bundle) {
            Err(ChainError::Transaction(message)) => {
                rejected += 1;
                assert_eq!(message, "mempool full", "overflow should be rate limited");
            }
            Err(other) => panic!("unexpected submission error: {other:?}"),
            Ok(hash) => panic!("overflow transaction unexpectedly accepted: {hash}"),
        }
    }
    assert_eq!(
        rejected, overflow,
        "all overflow submissions should be rejected"
    );

    drain_witness_channel(&mut witness_rx);

    let snapshot = handle
        .mempool_status()
        .expect("fetch mempool status after rate limiting");
    assert_eq!(
        snapshot.transactions.len(),
        mempool_limit,
        "mempool should hold at most the configured limit",
    );
    let observed_max_fee = snapshot
        .transactions
        .iter()
        .map(|tx| tx.fee)
        .max()
        .expect("max fee should be computed from pending transactions");
    assert_eq!(
        observed_max_fee,
        accepted_hashes
            .iter()
            .map(|(_, fee)| *fee)
            .max()
            .expect("accepted transactions should track max fee"),
        "fee prioritisation metrics should be observable via mempool status",
    );
    assert!(
        (snapshot.queue_weights.priority - 0.55).abs() < f64::EPSILON
            && (snapshot.queue_weights.fee - 0.45).abs() < f64::EPSILON,
        "queue weight telemetry should reflect configured priority and fee weights",
    );

    handle
        .update_mempool_limit(mempool_limit + overflow)
        .expect("expand mempool limit for recovery");

    for index in 0..overflow {
        let fee = 200 + index as u64;
        let bundle = sample_transaction_bundle(&recipient, (mempool_limit * 2 + index) as u64, fee);
        let hash = handle
            .submit_transaction(bundle)
            .expect("transaction should be accepted after expanding mempool limit");
        let event = recv_witness_transaction(&mut witness_rx)
            .await
            .expect("witness event after mempool recovery");
        assert_eq!(
            event.hash, hash,
            "recovery gossip should include transaction hash"
        );
        assert_eq!(
            event.fee, fee,
            "recovery gossip should report transaction fee"
        );
    }

    let recovered_status = handle
        .node_status()
        .expect("fetch node metrics after recovery");
    assert_eq!(
        recovered_status.pending_transactions,
        mempool_limit + overflow,
        "node metrics should capture recovered pending transaction count",
    );

    let recovered_snapshot = handle
        .mempool_status()
        .expect("mempool status after recovery");
    assert_eq!(
        recovered_snapshot.transactions.len(),
        mempool_limit + overflow,
        "mempool should accommodate expanded limit after recovery",
    );
    let recovery_fees: Vec<_> = recovered_snapshot
        .transactions
        .iter()
        .map(|tx| tx.fee)
        .collect();
    assert!(
        recovery_fees.iter().any(|fee| *fee >= 200),
        "recovered mempool should capture new high-fee submissions",
    );

    drop(witness_rx);
    drop(handle);
    drop(node);

    Ok(())
}
