use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use thiserror::Error;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, info, warn};

use rpp_chain::config::NodeConfig;
use rpp_chain::node::{NodeError, NodeHandle};
use rpp_chain::p2p::vendor::core::PeerId;
use rpp_chain::p2p::{
    AdmissionPolicies, AdmissionPolicyChange, AdmissionPolicyLogEntry, AllowlistedPeer, TierLevel,
};

use crate::telemetry::admission::{AdmissionReconcilerMetrics, DriftKind};

#[derive(Clone, Debug)]
pub struct AdmissionReconcilerSettings {
    pub cadence: Duration,
    pub drift_alert_threshold: u64,
    pub max_audit_lag: Duration,
}

impl AdmissionReconcilerSettings {
    pub fn from_config(config: &NodeConfig) -> Self {
        let cadence = Duration::from_secs(config.admission_reconciler.cadence_secs.max(1));
        let threshold = config.admission_reconciler.drift_alert_threshold.max(1);
        let max_audit_lag =
            Duration::from_secs(config.admission_reconciler.max_audit_lag_secs.max(1));
        Self {
            cadence,
            drift_alert_threshold: threshold,
            max_audit_lag,
        }
    }
}

pub struct AdmissionReconciler {
    shutdown: watch::Sender<bool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl AdmissionReconciler {
    pub fn start(
        node: NodeHandle,
        policy_path: PathBuf,
        settings: AdmissionReconcilerSettings,
    ) -> Self {
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let metrics = AdmissionReconcilerMetrics::global().clone();
        let cadence = settings.cadence;
        let alert_threshold = settings.drift_alert_threshold;
        let max_audit_lag = settings.max_audit_lag;
        let policy_path = Arc::new(policy_path);
        let mut state = ReconcilerState::new(alert_threshold);

        info!(
            target = "telemetry.admission",
            cadence_secs = cadence.as_secs(),
            drift_alert_threshold = alert_threshold,
            max_audit_lag_secs = max_audit_lag.as_secs(),
            "admission reconciler started"
        );

        let worker = tokio::spawn(async move {
            let mut ticker = time::interval(cadence);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let started = Instant::now();
                        match reconcile_once(&node, &policy_path, max_audit_lag).await {
                            Ok(report) => {
                                let drift_present = report.has_drift();
                                metrics.record_cycle(started.elapsed(), drift_present);
                                let should_alert = state.observe(drift_present);
                                if drift_present {
                                    debug!(
                                        target = "telemetry.admission",
                                        disk_mismatches = report.disk_diff.total(),
                                        audit_mismatches = report.audit_diff.as_ref().map(|diff| diff.total()).unwrap_or(0),
                                        disk_snapshot_missing = report.disk_missing,
                                        audit_lagged = report.audit_lagged,
                                        "admission policy reconciliation detected drift"
                                    );
                                }

                                if should_alert {
                                    emit_alert(&metrics, &report);
                                }
                            }
                            Err(err) => {
                                warn!(
                                    target = "telemetry.admission",
                                    error = %err,
                                    "admission policy reconciliation failed"
                                );
                            }
                        }
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        Self {
            shutdown: shutdown_tx,
            worker: Mutex::new(Some(worker)),
        }
    }

    pub async fn shutdown(&self) {
        if self.shutdown.send(true).is_err() {
            return;
        }
        if let Some(handle) = self.worker.lock().await.take() {
            if let Err(err) = handle.await {
                debug!(?err, "admission reconciler worker exited with error");
            }
        }
    }
}

fn emit_alert(metrics: &AdmissionReconcilerMetrics, report: &ReconcileReport) {
    if report.disk_missing || !report.disk_diff.is_clean() {
        metrics.record_drift(DriftKind::Disk, report.disk_diff.total().max(1));
    }
    if let Some(diff) = &report.audit_diff {
        if !diff.is_clean() {
            metrics.record_drift(DriftKind::Audit, diff.total().max(1));
        }
    }
    if report.audit_lagged {
        metrics.record_drift(DriftKind::AuditLag, 1);
    }

    warn!(
        target = "telemetry.admission",
        disk_mismatches = report.disk_diff.total(),
        audit_mismatches = report
            .audit_diff
            .as_ref()
            .map(|diff| diff.total())
            .unwrap_or(0),
        disk_snapshot_missing = report.disk_missing,
        audit_lagged = report.audit_lagged,
        "admission policy drift detected"
    );
}

struct ReconcilerState {
    consecutive_drift: u64,
    threshold: u64,
}

impl ReconcilerState {
    fn new(threshold: u64) -> Self {
        Self {
            consecutive_drift: 0,
            threshold: threshold.max(1),
        }
    }

    fn observe(&mut self, drift: bool) -> bool {
        if drift {
            self.consecutive_drift = self.consecutive_drift.saturating_add(1);
            self.consecutive_drift >= self.threshold
        } else {
            self.consecutive_drift = 0;
            false
        }
    }
}

#[derive(Debug, Default, Clone)]
struct PolicySnapshot {
    allowlist: BTreeMap<PeerId, TierLevel>,
    blocklist: BTreeSet<PeerId>,
}

impl PolicySnapshot {
    fn from_policies(policies: AdmissionPolicies) -> Self {
        Self::from_parts(policies.allowlist, policies.blocklist)
    }

    fn from_parts(allowlist: Vec<AllowlistedPeer>, blocklist: Vec<PeerId>) -> Self {
        let map = allowlist
            .into_iter()
            .map(|entry| (entry.peer, entry.tier))
            .collect();
        let blocked = blocklist.into_iter().collect();
        Self {
            allowlist: map,
            blocklist: blocked,
        }
    }

    fn diff(&self, other: &PolicySnapshot) -> SnapshotDiff {
        let mut keys: BTreeSet<PeerId> = BTreeSet::new();
        for peer in self.allowlist.keys() {
            keys.insert(peer.clone());
        }
        for peer in other.allowlist.keys() {
            keys.insert(peer.clone());
        }

        let mut allowlist_mismatches = 0u64;
        for peer in keys {
            if self.allowlist.get(&peer) != other.allowlist.get(&peer) {
                allowlist_mismatches += 1;
            }
        }

        let blocklist_diff = self
            .blocklist
            .symmetric_difference(&other.blocklist)
            .count() as u64;

        SnapshotDiff {
            allowlist: allowlist_mismatches,
            blocklist: blocklist_diff,
        }
    }
}

#[derive(Debug, Default, Clone)]
struct SnapshotDiff {
    allowlist: u64,
    blocklist: u64,
}

impl SnapshotDiff {
    fn total(&self) -> u64 {
        self.allowlist + self.blocklist
    }

    fn is_clean(&self) -> bool {
        self.allowlist == 0 && self.blocklist == 0
    }
}

#[derive(Debug, Default)]
struct ReconcileReport {
    disk_diff: SnapshotDiff,
    audit_diff: Option<SnapshotDiff>,
    disk_missing: bool,
    audit_lagged: bool,
}

impl ReconcileReport {
    fn has_drift(&self) -> bool {
        self.disk_missing
            || !self.disk_diff.is_clean()
            || self
                .audit_diff
                .as_ref()
                .map(|diff| !diff.is_clean())
                .unwrap_or(false)
            || self.audit_lagged
    }
}

#[derive(Debug, thiserror::Error)]
enum AdmissionReconcilerError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("invalid peer id: {0}")]
    PeerId(String),
    #[error("node error: {0}")]
    Node(#[from] NodeError),
}

async fn reconcile_once(
    node: &NodeHandle,
    policy_path: &Path,
    max_audit_lag: Duration,
) -> Result<ReconcileReport, AdmissionReconcilerError> {
    let policies = node.admission_policies();
    let runtime_snapshot = PolicySnapshot::from_policies(policies);

    let disk_snapshot = load_disk_snapshot(policy_path).await?;
    let disk_diff = runtime_snapshot.diff(&disk_snapshot.snapshot);

    let audit_data = load_audit_snapshot(node)?;
    let audit_diff = audit_data
        .snapshot
        .map(|snapshot| runtime_snapshot.diff(&snapshot));

    let audit_lagged = if let (Some(last_ts), Some(modified)) =
        (audit_data.last_timestamp, disk_snapshot.modified)
    {
        if let Ok(modified_ms) = modified.duration_since(UNIX_EPOCH) {
            let modified_millis = modified_ms.as_millis() as u128;
            let last_millis = last_ts as u128;
            let lag_threshold = max_audit_lag.as_millis() as u128;
            modified_millis > last_millis.saturating_add(lag_threshold)
        } else {
            false
        }
    } else {
        false
    };

    Ok(ReconcileReport {
        disk_diff,
        audit_diff,
        disk_missing: disk_snapshot.missing,
        audit_lagged,
    })
}

struct DiskSnapshot {
    snapshot: PolicySnapshot,
    missing: bool,
    modified: Option<SystemTime>,
}

async fn load_disk_snapshot(path: &Path) -> Result<DiskSnapshot, AdmissionReconcilerError> {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => {
            let modified = metadata.modified().ok();
            let bytes = tokio::fs::read(path).await?;
            if bytes.is_empty() {
                return Ok(DiskSnapshot {
                    snapshot: PolicySnapshot::default(),
                    missing: false,
                    modified,
                });
            }
            let stored: StoredAccessLists = serde_json::from_slice(&bytes)
                .map_err(|err| AdmissionReconcilerError::Serialization(err.to_string()))?;
            let snapshot = stored.try_into()?;
            Ok(DiskSnapshot {
                snapshot,
                missing: false,
                modified,
            })
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(DiskSnapshot {
            snapshot: PolicySnapshot::default(),
            missing: true,
            modified: None,
        }),
        Err(err) => Err(err.into()),
    }
}

struct AuditSnapshot {
    snapshot: Option<PolicySnapshot>,
    last_timestamp: Option<u64>,
}

fn load_audit_snapshot(node: &NodeHandle) -> Result<AuditSnapshot, AdmissionReconcilerError> {
    let (_, total) = node.admission_audit_log(0, 0)?;
    if total == 0 {
        return Ok(AuditSnapshot {
            snapshot: None,
            last_timestamp: None,
        });
    }

    let (entries, _) = node.admission_audit_log(0, total)?;
    let last_timestamp = entries.last().map(|entry| entry.timestamp_ms);
    let snapshot = audit_entries_to_snapshot(&entries)?;
    Ok(AuditSnapshot {
        snapshot: Some(snapshot),
        last_timestamp,
    })
}

fn audit_entries_to_snapshot(
    entries: &[AdmissionPolicyLogEntry],
) -> Result<PolicySnapshot, AdmissionReconcilerError> {
    let mut allowlist: BTreeMap<PeerId, TierLevel> = BTreeMap::new();
    let mut blocklist: BTreeSet<PeerId> = BTreeSet::new();

    for entry in entries {
        match &entry.change {
            AdmissionPolicyChange::Allowlist { previous, current } => {
                if let Some(current) = current {
                    let peer = parse_peer_id(&current.peer_id)?;
                    allowlist.insert(peer, current.tier);
                } else if let Some(previous) = previous {
                    let peer = parse_peer_id(&previous.peer_id)?;
                    allowlist.remove(&peer);
                }
            }
            AdmissionPolicyChange::Blocklist {
                peer_id, current, ..
            } => {
                let peer = parse_peer_id(peer_id)?;
                if *current {
                    blocklist.insert(peer);
                } else {
                    blocklist.remove(&peer);
                }
            }
            AdmissionPolicyChange::Noop => {}
        }
    }

    Ok(PolicySnapshot {
        allowlist,
        blocklist,
    })
}

fn parse_peer_id(value: &str) -> Result<PeerId, AdmissionReconcilerError> {
    PeerId::from_str(value).map_err(|err| AdmissionReconcilerError::PeerId(err.to_string()))
}

#[derive(Debug, Deserialize)]
struct StoredAccessLists {
    #[serde(default)]
    allowlist: Vec<StoredAllowlistEntry>,
    #[serde(default)]
    blocklist: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StoredAllowlistEntry {
    peer_id: String,
    tier: TierLevel,
}

impl TryFrom<StoredAccessLists> for PolicySnapshot {
    type Error = AdmissionReconcilerError;

    fn try_from(value: StoredAccessLists) -> Result<Self, Self::Error> {
        let allowlist = value
            .allowlist
            .into_iter()
            .map(|entry| {
                let peer = parse_peer_id(&entry.peer_id)?;
                Ok(AllowlistedPeer {
                    peer,
                    tier: entry.tier,
                })
            })
            .collect::<Result<Vec<_>, AdmissionReconcilerError>>()?;
        let blocklist = value
            .blocklist
            .into_iter()
            .map(|peer| parse_peer_id(&peer))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(PolicySnapshot::from_parts(allowlist, blocklist))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpp_chain::p2p::vendor::identity::Keypair;

    fn sample_peer() -> PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    #[test]
    fn reconciler_state_alerts_on_first_drift() {
        let mut state = ReconcilerState::new(1);
        assert!(state.observe(true));
        assert!(!state.observe(false));
    }

    #[test]
    fn reconciler_state_resets_after_recovery() {
        let mut state = ReconcilerState::new(2);
        assert!(!state.observe(true));
        assert!(state.observe(true));
        assert!(!state.observe(false));
    }

    #[test]
    fn snapshot_diff_detects_mismatches() {
        let peer = sample_peer();
        let runtime = PolicySnapshot::from_parts(
            vec![AllowlistedPeer {
                peer: peer.clone(),
                tier: TierLevel::Tl3,
            }],
            vec![peer.clone()],
        );
        let disk = PolicySnapshot::default();
        let diff = runtime.diff(&disk);
        assert_eq!(diff.allowlist, 1);
        assert_eq!(diff.blocklist, 1);
        assert!(diff.total() > 0);
    }

    #[test]
    fn report_marks_drift_before_reload() {
        let report = ReconcileReport {
            disk_diff: SnapshotDiff {
                allowlist: 1,
                blocklist: 0,
            },
            audit_diff: None,
            disk_missing: false,
            audit_lagged: false,
        };
        assert!(report.has_drift());
    }

    #[tokio::test]
    async fn disk_snapshot_handles_missing_file() {
        let temp = tempfile::tempdir().expect("temp dir");
        let path = temp.path().join("policies.json");
        let snapshot = load_disk_snapshot(&path).await.expect("load snapshot");
        assert!(snapshot.missing);
        assert!(snapshot.snapshot.allowlist.is_empty());
    }

    #[test]
    fn audit_snapshot_builds_state() {
        let peer = sample_peer();
        let entry = AdmissionPolicyLogEntry {
            id: 1,
            timestamp_ms: 10,
            actor: "system".into(),
            reason: None,
            change: AdmissionPolicyChange::Allowlist {
                previous: None,
                current: Some(rpp_chain::p2p::PolicyAllowlistState::new(
                    peer.clone(),
                    TierLevel::Tl2,
                )),
            },
        };
        let snapshot = audit_entries_to_snapshot(&[entry]).expect("snapshot");
        assert_eq!(snapshot.allowlist.len(), 1);
        assert!(snapshot.blocklist.is_empty());
        assert_eq!(snapshot.allowlist.get(&peer), Some(&TierLevel::Tl2));
    }
}
