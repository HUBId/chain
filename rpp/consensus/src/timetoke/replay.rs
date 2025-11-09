use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hex;
use metrics::{counter, gauge, histogram};
use rpp_p2p::{
    NetworkPruningCommitment, NetworkPruningEnvelope, NetworkPruningSegment,
    NetworkPruningSnapshot, NetworkTaggedDigestHex,
};
use rpp_pruning::{
    DomainTag, COMMITMENT_TAG, DIGEST_LENGTH, DOMAIN_TAG_LENGTH, ENVELOPE_TAG, PROOF_SEGMENT_TAG,
    SNAPSHOT_STATE_TAG,
};

use serde::Serialize;

use super::snapshots::TimetokeSnapshot;

const METRIC_REPLAY_DURATION: &str = "timetoke_replay_duration_ms";
const METRIC_REPLAY_SUCCESS: &str = "timetoke_replay_success_total";
const METRIC_REPLAY_FAILURE: &str = "timetoke_replay_failure_total";
const METRIC_REPLAY_LAST_ATTEMPT: &str = "timetoke_replay_last_attempt_timestamp";
const METRIC_REPLAY_LAST_SUCCESS: &str = "timetoke_replay_last_success_timestamp";
const METRIC_REPLAY_SECONDS_SINCE_SUCCESS: &str = "timetoke_replay_seconds_since_success";
const METRIC_REPLAY_STALLED: &str = "timetoke_replay_stalled";

const STALLED_WARNING_THRESHOLD_SECS: u64 = 60;
const STALLED_CRITICAL_THRESHOLD_SECS: u64 = 120;
const MAX_LATENCY_SAMPLES: usize = 1024;

static TELEMETRY: OnceLock<TimetokeReplayMetrics> = OnceLock::new();
static METRIC_DESCRIPTORS: OnceLock<()> = OnceLock::new();

/// Validates incoming snapshots against pruning receipts and locally trusted
/// ledger commitments to defend against replay attempts.
#[derive(Debug, Default)]
pub struct TimetokeReplayValidator;

impl TimetokeReplayValidator {
    /// Verifies that the snapshot and pruning envelope are consistent with the
    /// locally stored commitments. Errors indicate a potential replay or data
    /// integrity issue.
    pub fn validate(
        snapshot: &TimetokeSnapshot,
        pruning: &NetworkPruningEnvelope,
        ledger_timetoke_root: [u8; 32],
        ledger_global_state_root: [u8; 32],
    ) -> Result<(), TimetokeReplayError> {
        init_metric_descriptors();
        let start = Instant::now();
        let result = Self::validate_inner(
            snapshot,
            pruning,
            ledger_timetoke_root,
            ledger_global_state_root,
        );
        let latency = start.elapsed();
        record_telemetry(latency, result.as_ref().err());
        result
    }

    fn validate_inner(
        snapshot: &TimetokeSnapshot,
        pruning: &NetworkPruningEnvelope,
        ledger_timetoke_root: [u8; 32],
        ledger_global_state_root: [u8; 32],
    ) -> Result<(), TimetokeReplayError> {
        let snapshot_root = decode_hex32("snapshot.timetoke_root", &snapshot.timetoke_root)?;
        if snapshot_root != ledger_timetoke_root {
            return Err(TimetokeReplayError::SnapshotRootMismatch {
                expected: hex::encode(ledger_timetoke_root),
                found: snapshot.timetoke_root.clone(),
            });
        }

        let snapshot_state = decode_tagged_digest(
            "pruning.snapshot.state_commitment",
            &pruning.snapshot.state_commitment,
        )?;
        ensure_tag(
            "pruning.snapshot.state_commitment",
            snapshot_state.tag,
            SNAPSHOT_STATE_TAG,
        )?;
        if snapshot_state.digest != ledger_global_state_root {
            return Err(TimetokeReplayError::PruningDigestMismatch {
                field: "pruning.snapshot.state_commitment",
                expected: hex::encode(ledger_global_state_root),
                found: hex::encode(snapshot_state.digest),
            });
        }

        for (index, segment) in pruning.segments.iter().enumerate() {
            let commitment =
                decode_tagged_digest("pruning.segment.commitment", &segment.segment_commitment)?;
            ensure_tag_segment(index, commitment.tag, PROOF_SEGMENT_TAG)?;
        }

        let aggregate = decode_tagged_digest(
            "pruning.commitment.aggregate_commitment",
            &pruning.commitment.aggregate_commitment,
        )?;
        ensure_tag(
            "pruning.commitment.aggregate_commitment",
            aggregate.tag,
            COMMITMENT_TAG,
        )?;

        let binding = decode_tagged_digest("pruning.binding_digest", &pruning.binding_digest)?;
        ensure_tag("pruning.binding_digest", binding.tag, ENVELOPE_TAG)?;

        Ok(())
    }
}

struct TaggedDigestParts {
    tag: DomainTag,
    digest: [u8; DIGEST_LENGTH],
}

fn decode_hex32(field: &'static str, value: &str) -> Result<[u8; 32], TimetokeReplayError> {
    let bytes = hex::decode(value).map_err(|err| TimetokeReplayError::InvalidHex {
        field,
        error: err.to_string(),
    })?;
    if bytes.len() != 32 {
        return Err(TimetokeReplayError::InvalidLength {
            field,
            expected: 32,
            found: bytes.len(),
        });
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    Ok(output)
}

fn decode_tagged_digest(
    field: &'static str,
    value: &NetworkTaggedDigestHex,
) -> Result<TaggedDigestParts, TimetokeReplayError> {
    let bytes = hex::decode(value.as_str()).map_err(|err| TimetokeReplayError::InvalidHex {
        field,
        error: err.to_string(),
    })?;
    if bytes.len() != DOMAIN_TAG_LENGTH + DIGEST_LENGTH {
        return Err(TimetokeReplayError::InvalidLength {
            field,
            expected: DOMAIN_TAG_LENGTH + DIGEST_LENGTH,
            found: bytes.len(),
        });
    }
    let mut tag_bytes = [0u8; DOMAIN_TAG_LENGTH];
    tag_bytes.copy_from_slice(&bytes[..DOMAIN_TAG_LENGTH]);
    let mut digest = [0u8; DIGEST_LENGTH];
    digest.copy_from_slice(&bytes[DOMAIN_TAG_LENGTH..]);
    Ok(TaggedDigestParts {
        tag: DomainTag::new(tag_bytes),
        digest,
    })
}

fn ensure_tag(
    field: &'static str,
    actual: DomainTag,
    expected: DomainTag,
) -> Result<(), TimetokeReplayError> {
    if actual.as_bytes() != expected.as_bytes() {
        return Err(TimetokeReplayError::DomainTagMismatch {
            field,
            expected: expected.as_bytes(),
            found: actual.as_bytes(),
        });
    }
    Ok(())
}

fn ensure_tag_segment(
    index: usize,
    actual: DomainTag,
    expected: DomainTag,
) -> Result<(), TimetokeReplayError> {
    if actual.as_bytes() != expected.as_bytes() {
        return Err(TimetokeReplayError::SegmentDomainTagMismatch {
            index,
            expected: expected.as_bytes(),
            found: actual.as_bytes(),
        });
    }
    Ok(())
}

/// Errors reported during snapshot replay validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimetokeReplayError {
    /// Hex decoding failed for the referenced field.
    InvalidHex { field: &'static str, error: String },
    /// The decoded field length did not match the expected size.
    InvalidLength {
        field: &'static str,
        expected: usize,
        found: usize,
    },
    /// A domain tag differed from the expected pruning schema.
    DomainTagMismatch {
        field: &'static str,
        expected: [u8; DOMAIN_TAG_LENGTH],
        found: [u8; DOMAIN_TAG_LENGTH],
    },
    /// A pruning segment carried an unexpected domain tag.
    SegmentDomainTagMismatch {
        index: usize,
        expected: [u8; DOMAIN_TAG_LENGTH],
        found: [u8; DOMAIN_TAG_LENGTH],
    },
    /// The pruning digest did not match the locally trusted ledger root.
    PruningDigestMismatch {
        field: &'static str,
        expected: String,
        found: String,
    },
    /// The snapshot announced a Timetoke commitment different from the local ledger.
    SnapshotRootMismatch { expected: String, found: String },
}

impl fmt::Display for TimetokeReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimetokeReplayError::InvalidHex { field, error } => {
                write!(f, "invalid hex for {field}: {error}")
            }
            TimetokeReplayError::InvalidLength {
                field,
                expected,
                found,
            } => {
                write!(
                    f,
                    "invalid length for {field}: expected {expected} bytes, found {found}"
                )
            }
            TimetokeReplayError::DomainTagMismatch {
                field,
                expected,
                found,
            } => {
                write!(
                    f,
                    "domain tag mismatch for {field}: expected {:x?}, found {:x?}",
                    expected, found
                )
            }
            TimetokeReplayError::SegmentDomainTagMismatch {
                index,
                expected,
                found,
            } => {
                write!(
                    f,
                    "segment {index} tag mismatch: expected {:x?}, found {:x?}",
                    expected, found
                )
            }
            TimetokeReplayError::PruningDigestMismatch {
                field,
                expected,
                found,
            } => {
                write!(
                    f,
                    "pruning digest mismatch for {field}: expected {expected}, found {found}"
                )
            }
            TimetokeReplayError::SnapshotRootMismatch { expected, found } => {
                write!(
                    f,
                    "snapshot timetoke root mismatch: expected {expected}, found {found}"
                )
            }
        }
    }
}

impl std::error::Error for TimetokeReplayError {}

impl TimetokeReplayError {
    fn telemetry_reason(&self) -> &'static str {
        match self {
            TimetokeReplayError::InvalidHex { .. } => "invalid_hex",
            TimetokeReplayError::InvalidLength { .. } => "invalid_length",
            TimetokeReplayError::DomainTagMismatch { .. } => "domain_tag_mismatch",
            TimetokeReplayError::SegmentDomainTagMismatch { .. } => "segment_domain_tag_mismatch",
            TimetokeReplayError::PruningDigestMismatch { .. } => "pruning_digest_mismatch",
            TimetokeReplayError::SnapshotRootMismatch { .. } => "snapshot_root_mismatch",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TimetokeReplayFailureBreakdown {
    pub reason: String,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimetokeReplayTelemetrySnapshot {
    pub success_total: u64,
    pub failure_total: u64,
    pub success_rate: Option<f64>,
    pub latency_p50_ms: Option<u64>,
    pub latency_p95_ms: Option<u64>,
    pub latency_p99_ms: Option<u64>,
    pub last_attempt_epoch: Option<u64>,
    pub last_success_epoch: Option<u64>,
    pub seconds_since_attempt: Option<u64>,
    pub seconds_since_success: Option<u64>,
    pub stall_warning: bool,
    pub stall_critical: bool,
    pub failure_breakdown: Vec<TimetokeReplayFailureBreakdown>,
}

pub fn timetoke_replay_telemetry() -> TimetokeReplayTelemetrySnapshot {
    telemetry().snapshot()
}

struct TimetokeReplayMetrics {
    success_total: AtomicU64,
    failure_total: AtomicU64,
    last_attempt_epoch: AtomicU64,
    last_success_epoch: AtomicU64,
    latency_samples: Mutex<VecDeque<u64>>,
    failure_breakdown: Mutex<Vec<(String, u64)>>,
}

impl TimetokeReplayMetrics {
    const fn new() -> Self {
        Self {
            success_total: AtomicU64::new(0),
            failure_total: AtomicU64::new(0),
            last_attempt_epoch: AtomicU64::new(0),
            last_success_epoch: AtomicU64::new(0),
            latency_samples: Mutex::new(VecDeque::new()),
            failure_breakdown: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, latency: Duration, failure: Option<&TimetokeReplayError>) {
        let latency_ms = latency.as_millis().min(u128::from(u64::MAX)) as u64;
        histogram!(METRIC_REPLAY_DURATION, latency_ms as f64);
        self.push_latency(latency_ms);

        let now = unix_timestamp_seconds();
        self.last_attempt_epoch.store(now, Ordering::Relaxed);
        gauge!(METRIC_REPLAY_LAST_ATTEMPT).set(now as f64);

        match failure {
            Some(error) => {
                self.failure_total.fetch_add(1, Ordering::Relaxed);
                let reason = error.telemetry_reason().to_string();
                counter!(METRIC_REPLAY_FAILURE, "reason" => error.telemetry_reason()).increment(1);
                let mut breakdown = self
                    .failure_breakdown
                    .lock()
                    .expect("failure breakdown lock");
                if let Some((_, total)) = breakdown.iter_mut().find(|(label, _)| label == &reason) {
                    *total += 1;
                } else {
                    breakdown.push((reason, 1));
                }
            }
            None => {
                self.success_total.fetch_add(1, Ordering::Relaxed);
                self.last_success_epoch.store(now, Ordering::Relaxed);
                counter!(METRIC_REPLAY_SUCCESS).increment(1);
                gauge!(METRIC_REPLAY_LAST_SUCCESS).set(now as f64);
            }
        }

        let last_success = self.last_success_epoch.load(Ordering::Relaxed);
        if last_success != 0 {
            let since_success = now.saturating_sub(last_success);
            gauge!(METRIC_REPLAY_SECONDS_SINCE_SUCCESS).set(since_success as f64);
            gauge!(METRIC_REPLAY_STALLED, "threshold" => "warning").set(
                if since_success >= STALLED_WARNING_THRESHOLD_SECS {
                    1.0
                } else {
                    0.0
                },
            );
            gauge!(METRIC_REPLAY_STALLED, "threshold" => "critical").set(
                if since_success >= STALLED_CRITICAL_THRESHOLD_SECS {
                    1.0
                } else {
                    0.0
                },
            );
        }
    }

    fn push_latency(&self, latency_ms: u64) {
        let mut samples = self.latency_samples.lock().expect("latency samples lock");
        samples.push_back(latency_ms);
        if samples.len() > MAX_LATENCY_SAMPLES {
            samples.pop_front();
        }
    }

    fn snapshot(&self) -> TimetokeReplayTelemetrySnapshot {
        let now = unix_timestamp_seconds();
        let success_total = self.success_total.load(Ordering::Relaxed);
        let failure_total = self.failure_total.load(Ordering::Relaxed);
        let total = success_total + failure_total;
        let success_rate = if total == 0 {
            None
        } else {
            Some(success_total as f64 / total as f64)
        };

        let last_attempt_epoch = opt_epoch(self.last_attempt_epoch.load(Ordering::Relaxed));
        let last_success_epoch = opt_epoch(self.last_success_epoch.load(Ordering::Relaxed));
        let seconds_since_attempt = last_attempt_epoch.map(|epoch| now.saturating_sub(epoch));
        let seconds_since_success = last_success_epoch.map(|epoch| now.saturating_sub(epoch));

        let latency_values = {
            let samples = self.latency_samples.lock().expect("latency samples lock");
            samples.iter().copied().collect::<Vec<_>>()
        };
        let (p50, p95, p99) = percentiles(&latency_values);

        let failure_breakdown = {
            let entries = self
                .failure_breakdown
                .lock()
                .expect("failure breakdown lock");
            let mut items = entries.clone();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            items
                .into_iter()
                .map(|(reason, total)| TimetokeReplayFailureBreakdown { reason, total })
                .collect()
        };

        let stall_warning = seconds_since_success
            .map(|value| value >= STALLED_WARNING_THRESHOLD_SECS)
            .unwrap_or(false);
        let stall_critical = seconds_since_success
            .map(|value| value >= STALLED_CRITICAL_THRESHOLD_SECS)
            .unwrap_or(false);

        TimetokeReplayTelemetrySnapshot {
            success_total,
            failure_total,
            success_rate,
            latency_p50_ms: p50,
            latency_p95_ms: p95,
            latency_p99_ms: p99,
            last_attempt_epoch,
            last_success_epoch,
            seconds_since_attempt,
            seconds_since_success,
            stall_warning,
            stall_critical,
            failure_breakdown,
        }
    }
}

fn telemetry() -> &'static TimetokeReplayMetrics {
    TELEMETRY.get_or_init(TimetokeReplayMetrics::new)
}

fn record_telemetry(latency: Duration, failure: Option<&TimetokeReplayError>) {
    telemetry().record(latency, failure);
}

fn percentiles(values: &[u64]) -> (Option<u64>, Option<u64>, Option<u64>) {
    if values.is_empty() {
        return (None, None, None);
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    (
        Some(select_percentile(&sorted, 0.50)),
        Some(select_percentile(&sorted, 0.95)),
        Some(select_percentile(&sorted, 0.99)),
    )
}

fn select_percentile(sorted: &[u64], quantile: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let clamped = quantile.clamp(0.0, 1.0);
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (sorted.len() - 1) as f64 * clamped;
    let index = rank.ceil() as usize;
    sorted[index.min(sorted.len() - 1)]
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn opt_epoch(epoch: u64) -> Option<u64> {
    if epoch == 0 {
        None
    } else {
        Some(epoch)
    }
}

fn init_metric_descriptors() {
    METRIC_DESCRIPTORS.get_or_init(|| {
        metrics::describe_histogram!(
            METRIC_REPLAY_DURATION,
            "Timetoke replay duration in milliseconds"
        );
        metrics::describe_counter!(
            METRIC_REPLAY_SUCCESS,
            "Total number of successful Timetoke replays"
        );
        metrics::describe_counter!(
            METRIC_REPLAY_FAILURE,
            "Total number of failed Timetoke replay validations grouped by reason"
        );
        metrics::describe_gauge!(
            METRIC_REPLAY_LAST_ATTEMPT,
            "Unix epoch timestamp of the last Timetoke replay attempt"
        );
        metrics::describe_gauge!(
            METRIC_REPLAY_LAST_SUCCESS,
            "Unix epoch timestamp of the last successful Timetoke replay"
        );
        metrics::describe_gauge!(
            METRIC_REPLAY_SECONDS_SINCE_SUCCESS,
            "Seconds elapsed since the last successful Timetoke replay"
        );
        metrics::describe_gauge!(
            METRIC_REPLAY_STALLED,
            "Stalled Timetoke replay indicator grouped by warning/critical threshold"
        );
    });
}

// Ensure the unused imports from helper functions remain justified.
#[allow(dead_code)]
fn _assert_pruning_types(
    _snapshot: &NetworkPruningSnapshot,
    _segment: &NetworkPruningSegment,
    _commitment: &NetworkPruningCommitment,
    _digest: &NetworkTaggedDigestHex,
) {
}
