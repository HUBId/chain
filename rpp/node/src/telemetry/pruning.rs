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
}

impl PruningMetrics {
    const METER_NAME: &'static str = "rpp-node.pruning";

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
        let attrs = [
            KeyValue::new("reason", reason_attr),
            KeyValue::new("result", outcome_attr),
        ];
        self.cycle_duration_ms
            .record(duration.as_secs_f64() * 1_000.0, &attrs);
        self.cycle_total.add(1, &attrs);

        let persisted = status.and_then(|s| s.persisted_path.as_ref()).is_some();
        let persisted_attrs = [
            KeyValue::new("reason", reason_attr),
            KeyValue::new("persisted", if persisted { "true" } else { "false" }),
        ];
        self.persisted_plan.add(1, &persisted_attrs);

        if let Some(status) = status {
            let processed = status.stored_proofs.len() as u64;
            self.missing_heights
                .record(status.missing_heights.len() as u64, &[]);
            self.stored_proofs
                .record(status.stored_proofs.len() as u64, &[]);
            self.keys_processed
                .record(processed, &[KeyValue::new("reason", reason_attr)]);

            if processed > 0 {
                let remaining = status
                    .missing_heights
                    .len()
                    .saturating_sub(status.stored_proofs.len());
                let per_key_ms = duration.as_secs_f64() * 1_000.0 / processed as f64;
                let estimate_ms = per_key_ms * remaining as f64;
                self.time_remaining_ms
                    .record(estimate_ms, &[KeyValue::new("reason", reason_attr)]);
            }
        }
    }

    pub fn record_failure(&self, reason: CycleReason, error: &'static str) {
        self.failures_total.add(
            1,
            &[
                KeyValue::new("reason", reason.as_str()),
                KeyValue::new("error", error),
            ],
        );
    }

    pub fn record_retention_depth(&self, depth: u64) {
        self.retention_depth.record(depth, &[]);
    }

    pub fn record_pause_state(&self, paused: bool) {
        let state = if paused { "paused" } else { "resumed" };
        self.pause_transitions
            .add(1, &[KeyValue::new("state", state)]);
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

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::{global, Value};
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use rpp_chain::node::PruningJobStatus;
    use rpp_chain::rpp::GlobalStateCommitments;
    use rpp_chain::runtime::sync::{BlockMetadata, SnapshotSummary, StateSyncPlan};

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
                AggregatedMetrics::U64(MetricData::Sum(sum)) => sum.data_points().iter().any(|dp| {
                    dp.value() > 0
                        && dp.attributes().iter().any(|kv| {
                            kv.key.as_str() == "reason"
                                && matches!(&kv.value, Value::String(v) if v.as_str() == reason)
                        })
                        && dp.attributes().iter().any(|kv| {
                            kv.key.as_str() == "result"
                                && matches!(&kv.value, Value::String(v) if v.as_str() == result)
                        })
                }),
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
}
