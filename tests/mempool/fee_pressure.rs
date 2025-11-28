use std::collections::BTreeSet;
use std::env;
use std::path::PathBuf;
use std::{fs, thread};

use anyhow::Result;
use serde_json::json;
use tempfile::tempdir;

use rpp_chain::node::Node;
use rpp_chain::runtime::config::QueueWeightsConfig;
use rpp_chain::runtime::node::MempoolStatusExt;
use rpp_chain::runtime::RuntimeMetrics;

use super::helpers::{
    backend_for_index, drain_witness_channel, enabled_backends, observed_backends,
    recv_witness_transaction, sample_node_config, sample_transaction_bundle,
    sort_bundles_by_fee_desc, witness_topic, ProofBackend,
};
use super::status_probe::{AlertSeverity, MempoolStatusProbe, ProbeAlert};

struct FeeArtifact {
    path: PathBuf,
    payload: Option<serde_json::Value>,
}

impl FeeArtifact {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            payload: None,
        }
    }

    fn set_payload(&mut self, payload: serde_json::Value) {
        self.payload = Some(payload);
    }
}

impl Drop for FeeArtifact {
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

        if let Ok(serialized) = serde_json::to_vec_pretty(payload) {
            let _ = fs::write(&self.path, serialized);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fee_ordering_survives_proof_and_fee_pressure() -> Result<()> {
    let tempdir = tempdir()?;
    let mempool_limit = 8usize;
    let burst = 4usize;
    let backends = enabled_backends();
    let expected_backends: BTreeSet<ProofBackend> = backends.iter().copied().collect();

    let mut config = sample_node_config(tempdir.path(), mempool_limit);
    config.queue_weights = QueueWeightsConfig {
        priority: 0.35,
        fee: 0.65,
    };

    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = node.handle();
    let mut witness_rx = handle.subscribe_witness_gossip(witness_topic());
    let recipient = handle.address().to_string();

    let mut accepted_bundles = Vec::new();
    for index in 0..mempool_limit {
        let backend = backend_for_index(&backends, index);
        let fee = 10 + (index as u64 % 3);
        let bundle = sample_transaction_bundle(&recipient, index as u64, fee, backend);
        let hash = handle
            .submit_transaction(bundle.clone())
            .expect("initial transaction accepted while filling mempool");
        accepted_bundles.push(bundle);

        let event = recv_witness_transaction(&mut witness_rx)
            .await
            .expect("witness gossip event for accepted transaction");
        assert_eq!(
            event.hash, hash,
            "gossip event should include submitted hash"
        );
        assert_eq!(event.fee, fee, "gossip event should report transaction fee");
    }

    let pressure_probe = MempoolStatusProbe::new(0.75, 1.0);
    let saturated_snapshot = handle
        .mempool_status()
        .expect("snapshot after saturating mempool");
    let saturated_alerts = pressure_probe.evaluate(&saturated_snapshot, mempool_limit);
    assert!(
        saturated_alerts
            .iter()
            .any(|alert| alert.queue == "transactions"),
        "fee pressure should surface transaction queue alerts",
    );

    handle.update_mempool_limit(mempool_limit + burst);

    for index in 0..burst {
        let backend = backend_for_index(&backends, mempool_limit + index);
        let fee = 200 + index as u64;
        let bundle =
            sample_transaction_bundle(&recipient, (mempool_limit + index) as u64, fee, backend);
        let hash = handle
            .submit_transaction(bundle.clone())
            .expect("fee-heavy bundle accepted after expanding mempool");
        accepted_bundles.push(bundle);

        let event = recv_witness_transaction(&mut witness_rx)
            .await
            .expect("witness gossip for fee-heavy bundle");
        assert_eq!(event.hash, hash, "gossip includes fee-heavy hash");
        assert_eq!(event.fee, fee, "gossip includes fee-heavy fee");
    }

    drain_witness_channel(&mut witness_rx);

    let ordering_artifact_dir = env::var("MEMPOOL_ORDERING_ARTIFACT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("target/artifacts/mempool-ordering-probe")
        });
    let mut artifact = FeeArtifact::new(ordering_artifact_dir.join("fee-pressure.json"));

    let expanded_snapshot = handle
        .mempool_status()
        .expect("mempool snapshot after fee-heavy submissions");
    let decoded = expanded_snapshot
        .decode_transactions()
        .expect("decode pending transactions");
    let observed_backends = observed_backends(&decoded);
    let observed_order: Vec<_> = decoded.iter().map(|tx| (tx.hash.clone(), tx.fee)).collect();

    let expected_order: Vec<_> = sort_bundles_by_fee_desc(accepted_bundles.clone())
        .into_iter()
        .map(|bundle| (bundle.hash(), bundle.transaction.payload.fee))
        .collect();

    let recovered_alerts = pressure_probe.evaluate(&expanded_snapshot, mempool_limit + burst);

    artifact.set_payload(json!({
        "expected_backends": expected_backends
            .iter()
            .map(|backend| format!("{backend:?}"))
            .collect::<Vec<_>>(),
        "observed_backends": observed_backends
            .iter()
            .map(|backend| format!("{backend:?}"))
            .collect::<Vec<_>>(),
        "queue_weights": expanded_snapshot.queue_weights,
        "saturated_alerts": encode_alerts(&saturated_alerts),
        "recovered_alerts": encode_alerts(&recovered_alerts),
        "expected_order": expected_order,
        "observed_order": observed_order,
    }));

    assert_eq!(
        observed_backends, expected_backends,
        "mixed proof submissions should cover every enabled backend",
    );
    assert_eq!(
        observed_order, expected_order,
        "fee-priority ordering should remain intact under proof load",
    );
    assert!(
        recovered_alerts
            .iter()
            .all(|alert| alert.queue != "transactions" || alert.severity != AlertSeverity::Critical),
        "expanded capacity should clear transaction saturation alerts",
    );

    drop(witness_rx);
    drop(handle);
    drop(node);

    Ok(())
}

fn encode_alerts(alerts: &[ProbeAlert]) -> Vec<serde_json::Value> {
    alerts
        .iter()
        .map(|alert| {
            json!({
                "queue": alert.queue,
                "severity": match alert.severity {
                    AlertSeverity::Warning => "warning",
                    AlertSeverity::Critical => "critical",
                },
                "summary": alert.summary(),
            })
        })
        .collect()
}
