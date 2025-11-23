use std::{env, fs, path::PathBuf, thread, time::Duration};

use anyhow::{Context, Result};
use tempfile::tempdir;

use rpp_chain::consensus::BftVoteKind;
use rpp_chain::node::Node;
use rpp_chain::runtime::config::QueueWeightsConfig;
use rpp_chain::runtime::node::{
    MempoolStatus, PendingIdentitySummary, PendingUptimeSummary, PendingVoteSummary,
};
use rpp_chain::runtime::RuntimeMetrics;
use serde::Serialize;
use serde_json::{json, Value};

use super::helpers::{
    drain_witness_channel, recv_witness_transaction, sample_node_config, sample_transaction_bundle,
    witness_topic,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AlertSeverity {
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProbeAlert {
    name: String,
    queue: &'static str,
    severity: AlertSeverity,
    occupancy: usize,
    capacity: usize,
}

impl ProbeAlert {
    fn warning(queue: &'static str, occupancy: usize, capacity: usize) -> Self {
        Self {
            name: format!("{}QueueWarning", capitalize(queue)),
            queue,
            severity: AlertSeverity::Warning,
            occupancy,
            capacity,
        }
    }

    fn critical(queue: &'static str, occupancy: usize, capacity: usize) -> Self {
        Self {
            name: format!("{}QueueSaturated", capitalize(queue)),
            queue,
            severity: AlertSeverity::Critical,
            occupancy,
            capacity,
        }
    }

    fn summary(&self) -> String {
        format!(
            "{} occupancy {}/{} ({:.1}%)",
            self.queue,
            self.occupancy,
            self.capacity,
            100.0 * self.occupancy as f64 / self.capacity as f64
        )
    }
}

pub(super) struct MempoolStatusProbe {
    warning_threshold: f64,
    critical_threshold: f64,
}

impl MempoolStatusProbe {
    fn new(warning_threshold: f64, critical_threshold: f64) -> Self {
        Self {
            warning_threshold,
            critical_threshold,
        }
    }

    fn evaluate(&self, snapshot: &MempoolStatus, capacity: usize) -> Vec<ProbeAlert> {
        assert!(capacity > 0, "mempool capacity must be greater than zero");

        let mut alerts = Vec::new();
        for (queue, occupancy) in [
            ("transactions", snapshot.transactions.len()),
            ("identities", snapshot.identities.len()),
            ("votes", snapshot.votes.len()),
            ("uptime", snapshot.uptime_proofs.len()),
        ] {
            let ratio = occupancy as f64 / capacity as f64;
            if ratio >= self.critical_threshold {
                alerts.push(ProbeAlert::critical(queue, occupancy, capacity));
            } else if ratio >= self.warning_threshold {
                alerts.push(ProbeAlert::warning(queue, occupancy, capacity));
            }
        }
        alerts
    }
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

fn sample_identity(tag: usize) -> PendingIdentitySummary {
    PendingIdentitySummary {
        wallet_addr: format!("wallet-{tag:02x}"),
        commitment: format!("commitment-{tag:02x}"),
        epoch_nonce: format!("nonce-{tag:02x}"),
        state_root: format!("state-{tag:02x}"),
        identity_root: format!("identity-{tag:02x}"),
        vrf_tag: format!("vrf-{tag:02x}"),
        attested_votes: tag,
        gossip_confirmations: tag + 1,
    }
}

fn sample_vote(tag: usize) -> PendingVoteSummary {
    PendingVoteSummary {
        hash: format!("vote-hash-{tag:02x}"),
        voter: format!("voter-{tag:02x}"),
        height: tag as u64,
        round: tag as u64 + 1,
        block_hash: format!("block-{tag:02x}"),
        kind: if tag % 2 == 0 {
            BftVoteKind::PreVote
        } else {
            BftVoteKind::PreCommit
        },
    }
}

fn sample_uptime(tag: usize) -> PendingUptimeSummary {
    PendingUptimeSummary {
        identity: format!("uptime-{tag:02x}"),
        window_start: tag as u64 * 10,
        window_end: tag as u64 * 10 + 5,
        credited_hours: tag as u64,
    }
}

fn encode_summary<T: Serialize>(summary: T) -> Value {
    serde_json::to_value(summary).expect("serialize pending summary")
}

fn encode_alert_payload(alerts: &[ProbeAlert]) -> Value {
    json!({
        "alerts": alerts
            .iter()
            .map(|alert| {
                json!({
                    "status": "firing",
                    "labels": {
                        "alertname": alert.name,
                        "queue": alert.queue,
                        "severity": match alert.severity {
                            AlertSeverity::Warning => "warning",
                            AlertSeverity::Critical => "critical",
                        },
                    },
                    "annotations": {
                        "summary": alert.summary(),
                    },
                })
            })
            .collect::<Vec<_>>(),
    })
}

#[derive(Default)]
struct MempoolAlertArtifacts {
    dir: PathBuf,
    payloads: Vec<(String, Value)>,
    armed: bool,
}

impl MempoolAlertArtifacts {
    fn new() -> Self {
        let dir = env::var(ALERT_ARTIFACT_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_ALERT_ARTIFACT_DIR)
            });

        Self {
            dir,
            payloads: Vec::new(),
            armed: true,
        }
    }

    fn record_payload(&mut self, name: impl Into<String>, payload: Value) {
        self.payloads.push((name.into(), payload));
    }

    fn persist(&self) -> anyhow::Result<()> {
        if self.payloads.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(&self.dir).with_context(|| {
            format!(
                "create mempool alert artifact directory at {}",
                self.dir.display()
            )
        })?;

        for (name, payload) in &self.payloads {
            let body =
                serde_json::to_vec_pretty(payload).context("encode mempool alert payload")?;
            fs::write(self.dir.join(format!("{name}.json")), body)
                .with_context(|| format!("write mempool alert payload artifact {name}"))?;
        }

        Ok(())
    }
}

impl Drop for MempoolAlertArtifacts {
    fn drop(&mut self) {
        if self.armed && thread::panicking() {
            let _ = self.persist();
        }
    }
}

const ALERT_ARTIFACT_ENV: &str = "MEMPOOL_ALERT_ARTIFACT_DIR";
const DEFAULT_ALERT_ARTIFACT_DIR: &str = "target/artifacts/mempool-alert-probe";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mempool_status_probe_flags_queue_saturation_alerts() -> Result<()> {
    let mut artifacts = MempoolAlertArtifacts::new();
    let result = mempool_status_probe_flags_queue_saturation_alerts_inner(&mut artifacts).await;

    if result.is_err() {
        artifacts
            .persist()
            .context("write mempool alert artifacts after probe failure")?;
    }

    result
}

async fn mempool_status_probe_flags_queue_saturation_alerts_inner(
    artifacts: &mut MempoolAlertArtifacts,
) -> Result<()> {
    let tempdir = tempdir()?;
    let mempool_limit = 6usize;

    let config = sample_node_config(tempdir.path(), mempool_limit);
    let node = tokio::task::spawn_blocking({
        let config = config.clone();
        move || Node::new(config, RuntimeMetrics::noop())
    })
    .await??;
    let handle = node.handle();

    let mut witness_rx = handle.subscribe_witness_gossip(witness_topic());
    let recipient = handle.address().to_string();
    for index in 0..mempool_limit as u64 {
        let bundle = sample_transaction_bundle(&recipient, index, 10 + index);
        handle
            .submit_transaction(bundle)
            .expect("transaction should be accepted until saturation");
        // ensure gossip has time to propagate to avoid lag affecting later drain
        let _ = tokio::time::timeout(
            Duration::from_secs(1),
            recv_witness_transaction(&mut witness_rx),
        )
        .await
        .expect("witness gossip event for accepted transaction");
    }

    drain_witness_channel(&mut witness_rx);

    let snapshot = handle
        .mempool_status()
        .expect("fetch mempool status after saturation");
    assert_eq!(
        snapshot.transactions.len(),
        mempool_limit,
        "saturated mempool should report full transaction queue",
    );

    let probe = MempoolStatusProbe::new(0.8, 1.0);

    let critical_alerts = probe.evaluate(&snapshot, mempool_limit);
    let critical_payload = encode_alert_payload(&critical_alerts);
    artifacts.record_payload("critical", critical_payload.clone());
    assert!(
        critical_alerts
            .iter()
            .any(|alert| alert.queue == "transactions" && alert.severity == AlertSeverity::Critical),
        "transaction queue saturation should raise a critical alert: {critical_alerts:?}"
    );
    let critical_entries = critical_payload
        .get("alerts")
        .and_then(|alerts| alerts.as_array())
        .context("critical alert payload should include alert entries")?;
    assert!(
        critical_entries.iter().any(|alert| {
            alert
                .get("labels")
                .and_then(|labels| labels.get("alertname"))
                == Some(&Value::String("TransactionsQueueSaturated".to_string()))
                && alert
                    .get("labels")
                    .and_then(|labels| labels.get("severity"))
                    == Some(&Value::String("critical".to_string()))
        }),
        "critical payload should emit the transactions saturation alert: {critical_entries:?}"
    );

    let mut warning_snapshot = snapshot.clone();
    let warning_count = ((mempool_limit as f64 * probe.warning_threshold).ceil() as usize)
        .clamp(1, mempool_limit - 1);
    warning_snapshot.transactions.truncate(warning_count);

    let warning_alerts = probe.evaluate(&warning_snapshot, mempool_limit);
    let warning_payload = encode_alert_payload(&warning_alerts);
    artifacts.record_payload("warning", warning_payload.clone());
    assert!(
        warning_alerts
            .iter()
            .any(|alert| alert.queue == "transactions" && alert.severity == AlertSeverity::Warning),
        "transaction queue warning should fire once occupancy crosses the warning threshold"
    );
    assert!(
        !warning_alerts
            .iter()
            .any(|alert| alert.queue == "transactions" && alert.severity == AlertSeverity::Critical),
        "warning-level occupancy must not escalate to a critical alert"
    );
    let warning_entries = warning_payload
        .get("alerts")
        .and_then(|alerts| alerts.as_array())
        .context("warning alert payload should include alert entries")?;
    assert!(
        warning_entries.iter().any(|alert| {
            alert
                .get("annotations")
                .and_then(|annotations| annotations.get("summary"))
                == Some(&Value::String(
                    ProbeAlert::warning("transactions", warning_count, mempool_limit).summary(),
                ))
        }),
        "warning payload should report transaction queue occupancy"
    );

    let mut multi_queue_snapshot = warning_snapshot.clone();
    multi_queue_snapshot.identities = (0..mempool_limit)
        .map(|tag| encode_summary(sample_identity(tag)))
        .collect();
    multi_queue_snapshot.votes = (0..(mempool_limit - 1))
        .map(|tag| encode_summary(sample_vote(tag)))
        .collect();
    multi_queue_snapshot.uptime_proofs = (0..(mempool_limit / 2 + 1))
        .map(|tag| encode_summary(sample_uptime(tag)))
        .collect();

    let multi_alerts = probe.evaluate(&multi_queue_snapshot, mempool_limit);
    let multi_payload = encode_alert_payload(&multi_alerts);
    artifacts.record_payload("multi-queue", multi_payload.clone());
    let identity_critical = multi_alerts
        .iter()
        .find(|alert| alert.queue == "identities" && alert.severity == AlertSeverity::Critical);
    assert!(
        identity_critical.is_some(),
        "identity queue saturation should raise a critical alert: {multi_alerts:?}"
    );
    let transaction_warning = multi_alerts
        .iter()
        .find(|alert| alert.queue == "transactions" && alert.severity == AlertSeverity::Warning);
    assert!(
        transaction_warning.is_some(),
        "transaction warning alert should coexist with identity saturation"
    );
    let multi_entries = multi_payload
        .get("alerts")
        .and_then(|alerts| alerts.as_array())
        .context("multi-queue payload should include alert entries")?;
    assert!(
        multi_entries.iter().any(|alert| {
            alert.get("labels").and_then(|labels| labels.get("queue"))
                == Some(&Value::String("identities".to_string()))
                && alert
                    .get("labels")
                    .and_then(|labels| labels.get("alertname"))
                    == Some(&Value::String("IdentitiesQueueSaturated".to_string()))
        }),
        "multi-queue payload should emit identity saturation entries"
    );

    let recovered_limit = mempool_limit * 2;
    let recovered_weights = QueueWeightsConfig {
        priority: 0.6,
        fee: 0.4,
    };
    handle
        .update_queue_weights(recovered_weights.clone())
        .expect("adjust queue weights for recovery");
    handle
        .update_mempool_limit(recovered_limit)
        .expect("expand mempool limit during recovery");

    let recovered_snapshot = handle
        .mempool_status()
        .expect("mempool status after recovery tuning");
    assert_eq!(
        recovered_snapshot.transactions.len(),
        mempool_limit,
        "recovery tuning should retain the existing backlog while creating headroom",
    );
    assert_eq!(
        recovered_snapshot.queue_weights, recovered_weights,
        "queue weight telemetry should reflect the recovery tuning",
    );
    let recovered_alerts = probe.evaluate(&recovered_snapshot, recovered_limit);
    artifacts.record_payload("recovered", encode_alert_payload(&recovered_alerts));
    assert!(
        recovered_alerts.is_empty(),
        "raising limits and rebalancing fees should clear mempool saturation alerts",
    );

    let recovered_metrics = handle
        .node_status()
        .expect("node metrics after recovery tuning");
    assert_eq!(
        recovered_metrics.pending_transactions,
        recovered_snapshot.transactions.len(),
        "node status pending_transactions should align with mempool status after recovery",
    );
    assert_eq!(
        recovered_metrics.pending_identities,
        recovered_snapshot.identities.len(),
        "node status pending_identities should align with mempool status after recovery",
    );
    assert_eq!(
        recovered_metrics.pending_votes,
        recovered_snapshot.votes.len(),
        "node status pending_votes should align with mempool status after recovery",
    );
    assert_eq!(
        recovered_metrics.pending_uptime_proofs,
        recovered_snapshot.uptime_proofs.len(),
        "node status pending_uptime_proofs should align with mempool status after recovery",
    );

    drop(witness_rx);
    drop(handle);
    drop(node);

    let mut restart_config = config.clone();
    restart_config.mempool_limit = recovered_limit;
    restart_config.queue_weights = recovered_weights;
    let restarted_node = tokio::task::spawn_blocking({
        let restart_config = restart_config.clone();
        move || Node::new(restart_config, RuntimeMetrics::noop())
    })
    .await??;
    let restarted_handle = restarted_node.handle();

    let restarted_snapshot = restarted_handle
        .mempool_status()
        .expect("mempool status after restart with recovery tuning");
    let restarted_alerts = probe.evaluate(&restarted_snapshot, recovered_limit);
    assert!(
        restarted_alerts.is_empty(),
        "restart with recovered configuration should not trigger mempool alerts",
    );
    assert_eq!(
        restarted_snapshot.queue_weights, recovered_weights,
        "restart should preserve queue weight configuration",
    );

    let restarted_metrics = restarted_handle
        .node_status()
        .expect("node metrics after restart");
    assert_eq!(
        restarted_metrics.pending_transactions,
        restarted_snapshot.transactions.len(),
        "node status should report empty transaction backlog after restart",
    );
    assert_eq!(
        restarted_metrics.pending_identities,
        restarted_snapshot.identities.len(),
        "node status should report empty identity backlog after restart",
    );

    drop(restarted_handle);
    drop(restarted_node);

    Ok(())
}
