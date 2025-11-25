use std::env;
use std::fs;
use std::path::PathBuf;
use std::thread;

use anyhow::Result;
use serde_json::json;
use tempfile::tempdir;

use rpp_chain::errors::ChainError;
use rpp_chain::node::Node;
use rpp_chain::runtime::node::MempoolStatusExt;
use rpp_chain::runtime::RuntimeMetrics;
use tokio::sync::broadcast;

use super::helpers::{
    backend_for_index, drain_witness_channel, enabled_backends, observed_backends,
    recv_witness_transaction, sample_node_config, sample_transaction_bundle, witness_topic,
};
use super::status_probe::{AlertSeverity, MempoolStatusProbe};

#[derive(Debug)]
struct ChurnArtifact {
    path: PathBuf,
    payload: Option<serde_json::Value>,
}

impl ChurnArtifact {
    fn new(path: PathBuf) -> Self {
        println!(
            "[mempool] peer churn artifacts will be written to: {} (on failure)",
            path.display()
        );
        Self {
            path,
            payload: None,
        }
    }

    fn set_payload(&mut self, payload: serde_json::Value) {
        self.payload = Some(payload);
    }
}

impl Drop for ChurnArtifact {
    fn drop(&mut self) {
        if !thread::panicking() {
            return;
        }
        let Some(payload) = self.payload.as_ref() else {
            return;
        };

        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        match serde_json::to_vec_pretty(payload) {
            Ok(serialized) => {
                if let Err(error) = fs::write(&self.path, serialized) {
                    eprintln!(
                        "[mempool] failed to persist peer churn artifact to {}: {error:?}",
                        self.path.display()
                    );
                } else {
                    eprintln!(
                        "[mempool] persisted peer churn artifact to {} after failure",
                        self.path.display()
                    );
                }
            }
            Err(error) => eprintln!(
                "[mempool] failed to serialize peer churn artifact for {}: {error:?}",
                self.path.display()
            ),
        }
    }
}

async fn recv_churn_events(
    primary: &mut broadcast::Receiver<Vec<u8>>,
    peers: &mut [broadcast::Receiver<Vec<u8>>],
    expected_hash: &str,
) -> usize {
    let mut deliveries = 0usize;

    if let Some(event) = recv_witness_transaction(primary).await {
        if event.hash == expected_hash {
            deliveries += 1;
        }
    }

    for receiver in peers.iter_mut() {
        if let Some(event) = recv_witness_transaction(receiver).await {
            if event.hash == expected_hash {
                deliveries += 1;
            }
        }
    }

    deliveries
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_churn_respects_rate_limits_and_preserves_queue_ordering() -> Result<()> {
    let tempdir = tempdir()?;
    let mempool_limit = 5usize;
    let overflow = 3usize;
    let backends = enabled_backends();

    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = node.handle();

    let mut primary_rx = handle.subscribe_witness_gossip(witness_topic());
    let mut churned_peers: Vec<_> = (0..3)
        .map(|_| handle.subscribe_witness_gossip(witness_topic()))
        .collect();

    let recipient = handle.address().to_string();
    let mut accepted = Vec::new();
    let mut rejected = 0usize;
    let mut witness_deliveries = Vec::new();

    for index in 0..(mempool_limit + overflow) {
        if index % 2 == 0 {
            if let Some(mut receiver) = churned_peers.pop() {
                drain_witness_channel(&mut receiver);
            }
            churned_peers.push(handle.subscribe_witness_gossip(witness_topic()));
        }

        let fee = 25 + index as u64;
        let backend = backend_for_index(&backends, index);
        let bundle = sample_transaction_bundle(&recipient, index as u64, fee, backend);

        match handle.submit_transaction(bundle) {
            Ok(hash) => {
                accepted.push((hash.clone(), fee));
                let deliveries =
                    recv_churn_events(&mut primary_rx, &mut churned_peers, &hash).await;
                witness_deliveries.push((hash.clone(), deliveries));
            }
            Err(ChainError::MempoolFull(_)) => {
                rejected += 1;
            }
            Err(other) => return Err(other.into()),
        }
    }

    let pending_snapshot = handle
        .mempool_status()
        .expect("fetch mempool status after churn");
    let expected_backends: std::collections::BTreeSet<_> = backends.iter().copied().collect();
    let observed = observed_backends(&pending_snapshot.transactions);

    assert!(
        observed.is_superset(&expected_backends),
        "all enabled proof backends should survive peer churn: observed={observed:?} expected={expected_backends:?}",
    );
    assert_eq!(
        pending_snapshot.transactions.len(),
        mempool_limit,
        "mempool should cap accepted transactions at configured limit",
    );
    assert_eq!(
        rejected, overflow,
        "overflow submissions should be rejected"
    );

    let mut fees: Vec<_> = pending_snapshot
        .transactions
        .iter()
        .map(|tx| tx.fee)
        .collect();
    let mut expected_fees: Vec<_> = accepted
        .iter()
        .rev()
        .take(mempool_limit)
        .map(|(_, fee)| *fee)
        .collect();
    fees.sort_unstable_by(|lhs, rhs| rhs.cmp(lhs));
    expected_fees.sort_unstable_by(|lhs, rhs| rhs.cmp(lhs));
    assert_eq!(
        fees, expected_fees,
        "queue should preserve highest-fee ordering after churn",
    );

    let probe = MempoolStatusProbe::new(0.6, 0.9);
    let alerts = probe.evaluate(&pending_snapshot, mempool_limit);
    assert!(
        alerts
            .iter()
            .any(|alert| alert.severity == AlertSeverity::Warning),
        "probe should emit at least a warning when occupancy nears capacity",
    );
    assert!(
        alerts
            .iter()
            .any(|alert| alert.severity == AlertSeverity::Critical),
        "probe should flag a critical alert once the mempool is saturated",
    );

    let status = handle
        .node_status()
        .expect("read node metrics after peer churn");
    assert_eq!(
        status.pending_transactions, mempool_limit,
        "node metrics should reflect capped pending transaction count",
    );

    let artifact_dir = env::var("MEMPOOL_PEER_CHURN_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/artifacts/mempool-peer-churn")
        });
    let mut artifact = ChurnArtifact::new(artifact_dir.join("peer-churn.json"));
    artifact.set_payload(json!({
        "mempool_limit": mempool_limit,
        "accepted": accepted,
        "rejected": rejected,
        "alerts": alerts
            .iter()
            .map(|alert| json!({
                "name": alert.name,
                "severity": format!("{:?}", alert.severity),
                "queue": alert.queue,
                "occupancy": alert.occupancy,
                "capacity": alert.capacity,
            }))
            .collect::<Vec<_>>(),
        "witness_deliveries": witness_deliveries,
        "observed_backends": observed
            .into_iter()
            .map(|backend| format!("{backend:?}"))
            .collect::<Vec<_>>(),
    }));

    Ok(())
}
