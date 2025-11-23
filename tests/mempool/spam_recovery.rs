use std::{env, fs, path::PathBuf};

use anyhow::Result;
use serde_json::json;
use tempfile::tempdir;

use rpp_chain::errors::ChainError;
use rpp_chain::node::Node;
use rpp_chain::runtime::node::MempoolStatusExt;
use rpp_chain::runtime::RuntimeMetrics;

use super::helpers::{
    drain_witness_channel, recv_witness_transaction, sample_node_config, sample_transaction_bundle,
    sample_vote, sort_bundles_by_fee_desc, witness_topic,
};
use super::status_probe::{AlertSeverity, MempoolStatusProbe};

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multi_queue_spam_respects_eviction_fairness() -> Result<()> {
    let tempdir = tempdir()?;
    let mempool_limit = 4usize;
    let overflow = 2usize;

    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = node.handle();
    let mut witness_rx = handle.subscribe_witness_gossip(witness_topic());

    let recipient = handle.address().to_string();
    let mut accepted_transactions = Vec::new();
    for index in 0..mempool_limit {
        let fee = 5 + index as u64;
        let bundle = sample_transaction_bundle(&recipient, index as u64, fee);
        let hash = handle
            .submit_transaction(bundle)
            .expect("transaction should be accepted before saturation");
        accepted_transactions.push(hash.clone());

        let event = recv_witness_transaction(&mut witness_rx)
            .await
            .expect("witness gossip event for accepted transaction");
        assert_eq!(
            event.hash, hash,
            "witness payload should report submitted hash"
        );
    }

    let mut transaction_evictions = 0usize;
    for offset in 0..overflow {
        let bundle = sample_transaction_bundle(
            &recipient,
            (mempool_limit + offset) as u64,
            1 + offset as u64,
        );
        match handle.submit_transaction(bundle) {
            Err(ChainError::Transaction(message)) => {
                transaction_evictions += 1;
                assert_eq!(
                    message, "mempool full",
                    "overflow should reject transactions"
                );
            }
            Err(other) => panic!("unexpected submission error: {other:?}"),
            Ok(hash) => panic!("overflow transaction unexpectedly accepted: {hash}"),
        }
    }

    let mut accepted_votes = Vec::new();
    for round in 0..mempool_limit {
        let vote = sample_vote(1, round as u64);
        let hash = handle
            .submit_vote(vote)
            .expect("vote should be accepted before reaching the limit");
        accepted_votes.push(hash);
    }

    let mut vote_evictions = 0usize;
    for round in mempool_limit..(mempool_limit + overflow) {
        let vote = sample_vote(1, round as u64);
        match handle.submit_vote(vote) {
            Err(ChainError::Transaction(message)) => {
                vote_evictions += 1;
                assert_eq!(
                    message, "vote mempool full",
                    "vote overflow should be rejected"
                );
            }
            Err(other) => panic!("unexpected vote submission error: {other:?}"),
            Ok(hash) => panic!("overflow vote unexpectedly accepted: {hash}"),
        }
    }

    drain_witness_channel(&mut witness_rx);

    let snapshot = handle
        .mempool_status()
        .expect("fetch mempool status after mixed spam");
    assert_eq!(
        snapshot.transactions.len(),
        mempool_limit,
        "transaction spam should not evict prior accepted transactions",
    );
    assert_eq!(
        snapshot.votes.len(),
        mempool_limit,
        "vote spam should be confined to the vote queue",
    );
    assert!(
        snapshot.identities.is_empty(),
        "identity queue should remain empty"
    );
    assert!(
        snapshot.uptime_proofs.is_empty(),
        "uptime queue should remain empty during spam probe",
    );

    let decoded_transactions = snapshot
        .decode_transactions()
        .expect("decode transaction mempool entries");
    let decoded_transaction_hashes: Vec<_> = decoded_transactions
        .iter()
        .map(|tx| tx.hash.clone())
        .collect();
    assert_eq!(
        decoded_transaction_hashes, accepted_transactions,
        "overflow must not evict accepted transactions"
    );

    let decoded_votes = snapshot
        .decode_votes()
        .expect("decode vote mempool entries");
    let decoded_vote_hashes: Vec<_> = decoded_votes.iter().map(|vote| vote.hash.clone()).collect();
    assert_eq!(
        decoded_vote_hashes, accepted_votes,
        "vote ordering should remain stable across overflow attempts"
    );

    let node_status = handle
        .node_status()
        .expect("fetch node status after mixed spam");
    assert_eq!(
        node_status.pending_transactions, mempool_limit,
        "node metrics should report saturated transaction queue"
    );
    assert_eq!(
        node_status.pending_votes, mempool_limit,
        "node metrics should report saturated vote queue"
    );

    let eviction_artifact_dir = env::var("MEMPOOL_EVICTION_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target/artifacts/mempool-eviction-probe")
        });
    fs::create_dir_all(&eviction_artifact_dir).expect("create mempool eviction artifact directory");
    fs::write(
        eviction_artifact_dir.join("evictions.json"),
        serde_json::to_vec_pretty(&json!({
            "accepted": {
                "transactions": accepted_transactions,
                "votes": accepted_votes,
            },
            "pending": {
                "transactions": snapshot.transactions.len(),
                "votes": snapshot.votes.len(),
            },
            "evictions": {
                "transactions": transaction_evictions,
                "votes": vote_evictions,
            },
            "queue_weights": snapshot.queue_weights,
        }))
        .expect("persist mempool eviction artifact"),
    )
    .expect("write mempool eviction payload");

    drop(witness_rx);
    drop(handle);
    drop(node);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mempool_restarts_preserve_fee_priority_ordering() -> Result<()> {
    let tempdir = tempdir()?;
    let mempool_limit = 6usize;
    let overflow = 3usize;
    let expanded_limit = mempool_limit + overflow;

    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = node.handle();
    let mut witness_rx = handle.subscribe_witness_gossip(witness_topic());

    let recipient = handle.address().to_string();
    let mut restoration_bundles = Vec::new();

    for index in 0..mempool_limit {
        let fee = 10 + index as u64;
        let bundle = sample_transaction_bundle(&recipient, index as u64, fee);
        restoration_bundles.push(bundle.clone());
        let hash = handle
            .submit_transaction(bundle)
            .expect("initial transaction accepted before reaching mempool capacity");

        let event = recv_witness_transaction(&mut witness_rx)
            .await
            .expect("witness gossip event for accepted transaction");
        assert_eq!(
            event.hash, hash,
            "gossip event should include submitted hash"
        );
        assert_eq!(event.fee, fee, "gossip event should report transaction fee");
    }

    let mut rejected_bundles = Vec::new();
    for index in 0..overflow {
        let fee = 100 + index as u64;
        let bundle = sample_transaction_bundle(&recipient, (mempool_limit + index) as u64, fee);
        rejected_bundles.push(bundle.clone());
        match handle.submit_transaction(bundle) {
            Err(ChainError::Transaction(message)) => {
                assert_eq!(message, "mempool full", "overflow should be rate limited");
            }
            Err(other) => panic!("unexpected submission error: {other:?}"),
            Ok(hash) => panic!("overflow transaction unexpectedly accepted: {hash}"),
        }
    }

    drain_witness_channel(&mut witness_rx);

    handle
        .update_mempool_limit(expanded_limit)
        .expect("expand mempool limit for recovery");

    for bundle in &rejected_bundles {
        let hash = handle
            .submit_transaction(bundle.clone())
            .expect("transaction should be accepted after expanding mempool limit");
        restoration_bundles.push(bundle.clone());
        let event = recv_witness_transaction(&mut witness_rx)
            .await
            .expect("witness event after mempool recovery");
        assert_eq!(
            event.hash, hash,
            "recovery gossip should include transaction hash"
        );
    }

    let recovered_snapshot = handle
        .mempool_status()
        .expect("mempool status after recovery");
    assert_eq!(
        recovered_snapshot.transactions.len(),
        expanded_limit,
        "recovery should leave a full mempool before restart",
    );

    drop(witness_rx);
    drop(handle);
    drop(node);

    let restart_config = sample_node_config(tempdir.path(), expanded_limit);
    let restarted_node = tokio::task::spawn_blocking({
        let restart_config = restart_config.clone();
        move || Node::new(restart_config, RuntimeMetrics::noop())
    })
    .await??;
    let restarted_handle = restarted_node.handle();

    let ordered_bundles = sort_bundles_by_fee_desc(restoration_bundles.clone());
    for bundle in ordered_bundles.clone() {
        restarted_handle
            .submit_transaction(bundle)
            .expect("restoration bundle should be accepted after restart");
    }

    let restored_snapshot = restarted_handle
        .mempool_status()
        .expect("mempool status after restart");
    let observed_order: Vec<_> = restored_snapshot
        .transactions
        .iter()
        .map(|tx| (tx.hash.clone(), tx.fee))
        .collect();
    let expected_order: Vec<_> = ordered_bundles
        .iter()
        .map(|bundle| (bundle.hash(), bundle.transaction.payload.fee))
        .collect();

    let ordering_artifact_dir = env::var("MEMPOOL_ORDERING_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target/artifacts/mempool-ordering-probe")
        });
    fs::create_dir_all(&ordering_artifact_dir).expect("create mempool ordering artifact directory");

    let probe = MempoolStatusProbe::new(0.8, 1.0);
    let probe_alerts = probe.evaluate(&restored_snapshot, expanded_limit);

    let ordering_log = json!({
        "expected_fee_order": expected_order,
        "observed_fee_order": observed_order,
        "pending_after_restart": restored_snapshot.transactions.len(),
        "mempool_limit": expanded_limit,
        "alerts": probe_alerts
            .iter()
            .map(|alert| json!({
                "queue": alert.queue,
                "severity": match alert.severity {
                    AlertSeverity::Warning => "warning",
                    AlertSeverity::Critical => "critical",
                },
                "summary": alert.summary(),
            }))
            .collect::<Vec<_>>()
    });
    fs::write(
        ordering_artifact_dir.join("ordering.json"),
        serde_json::to_vec_pretty(&ordering_log).expect("serialize ordering log"),
    )
    .expect("persist mempool ordering artifact");

    assert_eq!(
        observed_order, expected_order,
        "restored mempool should preserve fee-priority ordering",
    );
    assert!(
        probe_alerts
            .iter()
            .any(|alert| alert.queue == "transactions" && alert.severity == AlertSeverity::Critical),
        "full restored mempool should trigger critical transaction alerts",
    );

    drop(restarted_handle);
    drop(restarted_node);

    Ok(())
}
