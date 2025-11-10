use std::time::Duration;

use anyhow::Result;
use tempfile::tempdir;

use rpp_chain::consensus::BftVoteKind;
use rpp_chain::node::Node;
use rpp_chain::runtime::node::{
    MempoolStatus, PendingIdentitySummary, PendingUptimeSummary, PendingVoteSummary,
};
use rpp_chain::runtime::RuntimeMetrics;

use super::helpers::{
    sample_node_config, sample_transaction_bundle, drain_witness_channel, recv_witness_transaction,
    witness_topic,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AlertSeverity {
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeAlert {
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

struct MempoolStatusProbe {
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mempool_status_probe_flags_queue_saturation_alerts() -> Result<()> {
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
        let _ = tokio::time::timeout(Duration::from_secs(1), recv_witness_transaction(&mut witness_rx))
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
    assert!(
        critical_alerts
            .iter()
            .any(|alert| alert.queue == "transactions" && alert.severity == AlertSeverity::Critical),
        "transaction queue saturation should raise a critical alert: {critical_alerts:?}"
    );

    let mut warning_snapshot = snapshot.clone();
    let warning_count = ((mempool_limit as f64 * probe.warning_threshold).ceil() as usize)
        .clamp(1, mempool_limit - 1);
    warning_snapshot.transactions.truncate(warning_count);

    let warning_alerts = probe.evaluate(&warning_snapshot, mempool_limit);
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

    let mut multi_queue_snapshot = warning_snapshot.clone();
    multi_queue_snapshot.identities = (0..mempool_limit)
        .map(sample_identity)
        .collect();
    multi_queue_snapshot.votes = (0..(mempool_limit - 1)).map(sample_vote).collect();
    multi_queue_snapshot.uptime_proofs = (0..(mempool_limit / 2 + 1))
        .map(sample_uptime)
        .collect();

    let multi_alerts = probe.evaluate(&multi_queue_snapshot, mempool_limit);
    let identity_critical = multi_alerts.iter().find(|alert| {
        alert.queue == "identities" && alert.severity == AlertSeverity::Critical
    });
    assert!(
        identity_critical.is_some(),
        "identity queue saturation should raise a critical alert: {multi_alerts:?}"
    );
    let transaction_warning = multi_alerts.iter().find(|alert| {
        alert.queue == "transactions" && alert.severity == AlertSeverity::Warning
    });
    assert!(
        transaction_warning.is_some(),
        "transaction warning alert should coexist with identity saturation"
    );

    drop(witness_rx);
    drop(handle);
    drop(node);

    Ok(())
}
