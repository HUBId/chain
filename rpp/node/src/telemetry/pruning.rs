use std::env;
use std::sync::OnceLock;
use std::time::Duration;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::KeyValue;
use rpp_chain::node::PruningJobStatus;

static METRICS: OnceLock<PruningMetrics> = OnceLock::new();

#[derive(Clone)]
pub struct PruningMetrics {
    cycle_duration_ms: Histogram<f64>,
    cycle_total: Counter<u64>,
    keys_processed: Histogram<u64>,
    time_remaining_ms: Histogram<f64>,
    failures_total: Counter<u64>,
    persisted_plan: Counter<u64>,
    missing_heights: Histogram<u64>,
    stored_proofs: Histogram<u64>,
    retention_depth: Histogram<u64>,
    pause_transitions: Counter<u64>,
    pacing_decisions: Counter<u64>,
    pacing_delay_ms: Histogram<f64>,
    shard_label: KeyValue,
    partition_label: KeyValue,
}

impl PruningMetrics {
    const METER_NAME: &'static str = "rpp-node.pruning";
    const SHARD_ENV: &'static str = "RPP_PRUNING_SHARD";
    const PARTITION_ENV: &'static str = "RPP_PRUNING_PARTITION";

    fn new(meter: Meter) -> Self {
        let cycle_duration_ms = meter
            .f64_histogram("rpp.node.pruning.cycle_duration_ms")
            .with_description("Duration of pruning cycles in milliseconds")
            .with_unit("ms")
            .build();
        let cycle_total = meter
            .u64_counter("rpp.node.pruning.cycle_total")
            .with_description("Total pruning cycle executions grouped by trigger reason and result")
            .with_unit("1")
            .build();
        let keys_processed = meter
            .u64_histogram("rpp.node.pruning.keys_processed")
            .with_description("Number of pruning keys processed in a cycle")
            .with_unit("1")
            .build();
        let time_remaining_ms = meter
            .f64_histogram("rpp.node.pruning.time_remaining_ms")
            .with_description(
                "Estimated time remaining in milliseconds to clear the current pruning backlog",
            )
            .with_unit("ms")
            .build();
        let failures_total = meter
            .u64_counter("rpp.node.pruning.failures_total")
            .with_description(
                "Total pruning cycle failures grouped by trigger reason and error class",
            )
            .with_unit("1")
            .build();
        let persisted_plan = meter
            .u64_counter("rpp.node.pruning.persisted_plan_total")
            .with_description("Count of pruning cycles that persisted a reconstruction plan")
            .with_unit("1")
            .build();
        let missing_heights = meter
            .u64_histogram("rpp.node.pruning.missing_heights")
            .with_description("Number of missing heights discovered in a pruning cycle")
            .with_unit("1")
            .build();
        let stored_proofs = meter
            .u64_histogram("rpp.node.pruning.stored_proofs")
            .with_description("Number of pruning proofs persisted during a cycle")
            .with_unit("1")
            .build();
        let retention_depth = meter
            .u64_histogram("rpp.node.pruning.retention_depth")
            .with_description("Retention depth (in blocks) applied to pruning cycles")
            .with_unit("1")
            .build();
        let pause_transitions = meter
            .u64_counter("rpp.node.pruning.pause_transitions")
            .with_description("Transitions of the pruning service pause state")
            .with_unit("1")
            .build();
        let pacing_decisions = meter
            .u64_counter("rpp.node.pruning.pacing_total")
            .with_description("Count of pruning pacing decisions grouped by reason and action")
            .with_unit("1")
            .build();
        let pacing_delay_ms = meter
            .f64_histogram("rpp.node.pruning.pacing_delay_ms")
            .with_description("Backoff applied by pruning pacing in milliseconds")
            .with_unit("ms")
            .build();

        let shard_label = KeyValue::new(
            "shard",
            env::var(Self::SHARD_ENV).unwrap_or_else(|_| "primary".to_string()),
        );
        let partition_label = KeyValue::new(
            "partition",
            env::var(Self::PARTITION_ENV).unwrap_or_else(|_| "0".to_string()),
        );

        Self {
            cycle_duration_ms,
            cycle_total,
            keys_processed,
            time_remaining_ms,
            failures_total,
            persisted_plan,
            missing_heights,
            stored_proofs,
            retention_depth,
            pause_transitions,
            pacing_decisions,
            pacing_delay_ms,
            shard_label,
            partition_label,
        }
    }

    pub fn global() -> &'static Self {
        METRICS.get_or_init(|| Self::new(global::meter(Self::METER_NAME)))
    }

    pub fn record_cycle(
        &self,
        reason: CycleReason,
        outcome: CycleOutcome,
        duration: Duration,
        status: Option<&PruningJobStatus>,
    ) {
        let reason_attr = reason.as_str();
        let outcome_attr = outcome.as_str();
        let attrs = self.with_base_labels([
            KeyValue::new("reason", reason_attr),
            KeyValue::new("result", outcome_attr),
        ]);
        self.cycle_duration_ms
            .record(duration.as_secs_f64() * 1_000.0, &attrs);
        self.cycle_total.add(1, &attrs);

        let persisted = status.and_then(|s| s.persisted_path.as_ref()).is_some();
        let persisted_attrs = self.with_base_labels([
            KeyValue::new("reason", reason_attr),
            KeyValue::new("persisted", if persisted { "true" } else { "false" }),
        ]);
        self.persisted_plan.add(1, &persisted_attrs);

        if let Some(status) = status {
            let processed = status.stored_proofs.len() as u64;
            let backlog_labels = self.base_labels();
            self.missing_heights
                .record(status.missing_heights.len() as u64, &backlog_labels);
            self.stored_proofs
                .record(status.stored_proofs.len() as u64, &backlog_labels);
            let processed_attrs = self.with_base_labels([KeyValue::new("reason", reason_attr)]);
            self.keys_processed.record(processed, &processed_attrs);

            let estimate_ms = status
                .estimated_time_remaining_ms
                .map(|ms| ms as f64)
                .or_else(|| {
                    compute_time_remaining_ms(processed, status.missing_heights.len(), duration)
                });

            if let Some(estimate_ms) = estimate_ms {
                let estimate_attrs = self.with_base_labels([KeyValue::new("reason", reason_attr)]);
                self.time_remaining_ms.record(estimate_ms, &estimate_attrs);
            }
        }
    }

    pub fn record_failure(&self, reason: CycleReason, error: &'static str) {
        let attrs = self.with_base_labels([
            KeyValue::new("reason", reason.as_str()),
            KeyValue::new("error", error),
        ]);
        self.failures_total.add(1, &attrs);
    }

    pub fn record_retention_depth(&self, depth: u64) {
        self.retention_depth.record(depth, &self.base_labels());
    }

    pub fn record_pause_state(&self, paused: bool) {
        let state = if paused { "paused" } else { "resumed" };
        let attrs = self.with_base_labels([KeyValue::new("state", state)]);
        self.pause_transitions.add(1, &attrs);
    }

    pub fn record_pacing(
        &self,
        reason: PacingReason,
        action: PacingAction,
        observed: Option<f64>,
        limit: Option<f64>,
        delay: Option<Duration>,
    ) {
        let mut attrs = self.with_base_labels([
            KeyValue::new("reason", reason.as_str()),
            KeyValue::new("action", action.as_str()),
        ]);
        if let Some(observed) = observed {
            attrs.push(KeyValue::new("observed", observed.to_string()));
        }
        if let Some(limit) = limit {
            attrs.push(KeyValue::new("limit", limit.to_string()));
        }

        if let Some(delay) = delay {
            self.pacing_delay_ms
                .record(delay.as_secs_f64() * 1_000.0, &attrs);
        }

        self.pacing_decisions.add(1, &attrs);
    }

    fn base_labels(&self) -> Vec<KeyValue> {
        vec![self.shard_label.clone(), self.partition_label.clone()]
    }

    fn with_base_labels(&self, extra: impl IntoIterator<Item = KeyValue>) -> Vec<KeyValue> {
        let mut labels = self.base_labels();
        labels.extend(extra);
        labels
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CycleReason {
    Manual,
    Scheduled,
}

impl CycleReason {
    fn as_str(self) -> &'static str {
        match self {
            CycleReason::Manual => "manual",
            CycleReason::Scheduled => "scheduled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacingReason {
    Cpu,
    Io,
    Mempool,
    Timetoke,
}

impl PacingReason {
    pub fn as_str(self) -> &'static str {
        match self {
            PacingReason::Cpu => "cpu",
            PacingReason::Io => "io",
            PacingReason::Mempool => "mempool",
            PacingReason::Timetoke => "timetoke",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacingAction {
    Yield,
    Resume,
}

impl PacingAction {
    pub fn as_str(self) -> &'static str {
        match self {
            PacingAction::Yield => "yield",
            PacingAction::Resume => "resume",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CycleOutcome {
    Success,
    Failure,
}

impl CycleOutcome {
    fn as_str(self) -> &'static str {
        match self {
            CycleOutcome::Success => "success",
            CycleOutcome::Failure => "failure",
        }
    }
}

fn compute_time_remaining_ms(processed: u64, backlog: usize, duration: Duration) -> Option<f64> {
    if processed == 0 || backlog <= processed as usize {
        return None;
    }

    let per_key_ms = duration.as_secs_f64() * 1_000.0 / processed as f64;
    let estimate = per_key_ms * backlog.saturating_sub(processed as usize) as f64;
    if estimate.is_finite() && estimate.is_sign_positive() {
        Some(estimate)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::{global, Value};
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use rpp_chain::node::PruningJobStatus;
    use rpp_chain::rpp::GlobalStateCommitments;
    use rpp_chain::runtime::sync::{BlockMetadata, SnapshotSummary, StateSyncPlan};
    use std::env;

    fn setup_meter() -> (PruningMetrics, InMemoryMetricExporter, SdkMeterProvider) {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        global::set_meter_provider(provider.clone());
        let meter = provider.meter(PruningMetrics::METER_NAME);
        (PruningMetrics::new(meter), exporter, provider)
    }

    fn histogram_has_value(
        exported: &[ResourceMetrics],
        name: &str,
        expectation: impl Fn(f64) -> bool,
    ) -> bool {
        exported
            .iter()
            .flat_map(|resource| resource.scope_metrics())
            .flat_map(|scope| scope.metrics())
            .filter(|metric| metric.name() == name)
            .any(|metric| match metric.data() {
                AggregatedMetrics::F64(MetricData::Histogram(data)) => data
                    .data_points()
                    .iter()
                    .any(|point| point.sum().map_or(false, &expectation)),
                AggregatedMetrics::U64(MetricData::Histogram(data)) => data
                    .data_points()
                    .iter()
                    .any(|point| expectation(point.sum() as f64)),
                _ => false,
            })
    }

    fn metric_has_labels(
        exported: &[ResourceMetrics],
        name: &str,
        expected: &[(&str, &str)],
    ) -> bool {
        exported
            .iter()
            .flat_map(|resource| resource.scope_metrics())
            .flat_map(|scope| scope.metrics())
            .filter(|metric| metric.name() == name)
            .any(|metric| match metric.data() {
                AggregatedMetrics::F64(MetricData::Histogram(data)) => data
                    .data_points()
                    .iter()
                    .any(|point| attrs_match(point.attributes(), expected)),
                AggregatedMetrics::U64(MetricData::Histogram(data)) => data
                    .data_points()
                    .iter()
                    .any(|point| attrs_match(point.attributes(), expected)),
                AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                    .data_points()
                    .iter()
                    .any(|point| attrs_match(point.attributes(), expected)),
                _ => false,
            })
    }

    fn attrs_match(attrs: &[KeyValue], expected: &[(&str, &str)]) -> bool {
        expected.iter().all(|(key, value)| {
            attrs.iter().any(|kv| {
                kv.key.as_str() == *key
                    && matches!(&kv.value, Value::String(v) if v.as_str() == *value)
            })
        })
    }

    fn counter_has_attrs(
        exported: &[ResourceMetrics],
        name: &str,
        reason: &str,
        error: &str,
    ) -> bool {
        exported
            .iter()
            .flat_map(|resource| resource.scope_metrics())
            .flat_map(|scope| scope.metrics())
            .filter(|metric| metric.name() == name)
            .any(|metric| match metric.data() {
                AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                    sum.data_points().iter().any(|dp| {
                        dp.value() > 0
                            && dp.attributes().iter().any(|kv| {
                                kv.key.as_str() == "reason"
                                    && matches!(&kv.value, Value::String(v) if v.as_str() == reason)
                            })
                            && dp.attributes().iter().any(|kv| {
                                kv.key.as_str() == "error"
                                    && matches!(&kv.value, Value::String(v) if v.as_str() == error)
                            })
                    })
                }
                _ => false,
            })
    }

    fn cycle_counter_has_result(
        exported: &[ResourceMetrics],
        name: &str,
        reason: &str,
        result: &str,
    ) -> bool {
        exported
            .iter()
            .flat_map(|resource| resource.scope_metrics())
            .flat_map(|scope| scope.metrics())
            .filter(|metric| metric.name() == name)
            .any(|metric| match metric.data() {
                AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                    sum.data_points().iter().any(|dp| {
                        dp.value() > 0
                            && dp.attributes().iter().any(|kv| {
                                kv.key.as_str() == "reason"
                                    && matches!(&kv.value, Value::String(v) if v.as_str() == reason)
                            })
                            && dp.attributes().iter().any(|kv| {
                                kv.key.as_str() == "result"
                                    && matches!(&kv.value, Value::String(v) if v.as_str() == result)
                            })
                    })
                }
                _ => false,
            })
    }

    fn sample_status(missing: usize, stored: usize) -> PruningJobStatus {
        PruningJobStatus {
            plan: StateSyncPlan {
                snapshot: SnapshotSummary {
                    height: 0,
                    block_hash: String::new(),
                    commitments: GlobalStateCommitments::default(),
                    chain_commitment: String::new(),
                },
                tip: BlockMetadata {
                    height: 0,
                    hash: String::new(),
                    timestamp: 0,
                    previous_state_root: String::new(),
                    new_state_root: String::new(),
                    proof_hash: String::new(),
                    pruning: None,
                    pruning_binding_digest: [0u8; 36],
                    pruning_segment_commitments: Vec::new(),
                    recursive_commitment: String::new(),
                    recursive_previous_commitment: None,
                },
                chunks: Vec::new(),
                light_client_updates: Vec::new(),
                max_concurrent_requests: None,
            },
            missing_heights: (0..missing as u64).collect(),
            persisted_path: None,
            stored_proofs: (0..stored as u64).collect(),
            last_updated: 0,
            estimated_time_remaining_ms: None,
        }
    }

    #[test]
    fn records_progress_and_estimates_remaining_time() {
        let (metrics, exporter, provider) = setup_meter();
        let status = sample_status(4, 2);

        metrics.record_cycle(
            CycleReason::Manual,
            CycleOutcome::Success,
            Duration::from_secs(4),
            Some(&status),
        );

        provider.force_flush().unwrap();
        let exported = exporter.get_finished_metrics().unwrap();

        assert!(histogram_has_value(
            &exported,
            "rpp.node.pruning.keys_processed",
            |v| v >= 2.0
        ));
        assert!(histogram_has_value(
            &exported,
            "rpp.node.pruning.time_remaining_ms",
            |v| v >= 3_900.0
        ));
    }

    #[test]
    fn calculates_eta_from_cycle_duration() {
        let status = sample_status(5, 2);

        let eta = status.estimate_time_remaining_ms(Duration::from_secs(4));

        assert_eq!(eta, Some(6_000));
    }

    #[test]
    fn metrics_prefer_reported_eta() {
        let (metrics, exporter, provider) = setup_meter();
        let mut status = sample_status(4, 2);
        status.estimated_time_remaining_ms = Some(2_500);

        metrics.record_cycle(
            CycleReason::Manual,
            CycleOutcome::Success,
            Duration::from_secs(2),
            Some(&status),
        );

        provider.force_flush().unwrap();
        let exported = exporter.get_finished_metrics().unwrap();

        assert!(histogram_has_value(
            &exported,
            "rpp.node.pruning.time_remaining_ms",
            |v| (v - 2_500.0).abs() < f64::EPSILON
        ));
    }

    #[test]
    fn eta_tracks_throughput_changes() {
        let fast = sample_status(10, 4);
        let slow = sample_status(10, 1);

        let fast_eta = fast.estimate_time_remaining_ms(Duration::from_secs(2));
        let slow_eta = slow.estimate_time_remaining_ms(Duration::from_secs(2));

        assert_eq!(fast_eta, Some(3_000));
        assert!(slow_eta.is_some());
        assert!(slow_eta > fast_eta);
    }

    #[test]
    fn records_failure_reason_for_alerting() {
        let (metrics, exporter, provider) = setup_meter();

        metrics.record_failure(CycleReason::Scheduled, "storage");

        provider.force_flush().unwrap();
        let exported = exporter.get_finished_metrics().unwrap();

        assert!(counter_has_attrs(
            &exported,
            "rpp.node.pruning.failures_total",
            "scheduled",
            "storage"
        ));
    }

    #[test]
    fn aborted_cycle_surfaces_failure_metrics() {
        let (metrics, exporter, provider) = setup_meter();

        metrics.record_cycle(
            CycleReason::Manual,
            CycleOutcome::Failure,
            Duration::from_millis(500),
            None,
        );

        provider.force_flush().unwrap();
        let exported = exporter.get_finished_metrics().unwrap();

        assert!(cycle_counter_has_result(
            &exported,
            "rpp.node.pruning.cycle_total",
            "manual",
            "failure",
        ));
    }

    #[test]
    fn metrics_include_shard_and_partition_labels() {
        let shard = "shard-a";
        let partition = "partition-1";
        let prior_shard = env::var(PruningMetrics::SHARD_ENV).ok();
        let prior_partition = env::var(PruningMetrics::PARTITION_ENV).ok();
        env::set_var(PruningMetrics::SHARD_ENV, shard);
        env::set_var(PruningMetrics::PARTITION_ENV, partition);

        let (metrics, exporter, provider) = setup_meter();
        let status = sample_status(3, 1);

        metrics.record_cycle(
            CycleReason::Manual,
            CycleOutcome::Success,
            Duration::from_secs(2),
            Some(&status),
        );
        metrics.record_failure(CycleReason::Manual, "storage");

        provider.force_flush().unwrap();
        let exported = exporter.get_finished_metrics().unwrap();

        assert!(metric_has_labels(
            &exported,
            "rpp.node.pruning.cycle_total",
            &["shard", "partition", "reason", "result"]
                .into_iter()
                .zip([shard, partition, "manual", "success"])
                .collect::<Vec<_>>()
        ));

        assert!(metric_has_labels(
            &exported,
            "rpp.node.pruning.missing_heights",
            &[("shard", shard), ("partition", partition)]
        ));

        assert!(metric_has_labels(
            &exported,
            "rpp.node.pruning.failures_total",
            &["shard", "partition", "reason", "error"]
                .into_iter()
                .zip([shard, partition, "manual", "storage"])
                .collect::<Vec<_>>()
        ));

        if let Some(value) = prior_shard {
            env::set_var(PruningMetrics::SHARD_ENV, value);
        } else {
            env::remove_var(PruningMetrics::SHARD_ENV);
        }

        if let Some(value) = prior_partition {
            env::set_var(PruningMetrics::PARTITION_ENV, value);
        } else {
            env::remove_var(PruningMetrics::PARTITION_ENV);
        }
    }
}
