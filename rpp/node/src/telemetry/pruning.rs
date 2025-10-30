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
            self.missing_heights
                .record(status.missing_heights.len() as u64, &[]);
            self.stored_proofs
                .record(status.stored_proofs.len() as u64, &[]);
        }
    }

    pub fn record_retention_depth(&self, depth: u64) {
        self.retention_depth.record(depth, &[]);
    }

    pub fn record_pause_state(&self, paused: bool) {
        let state = if paused { "paused" } else { "resumed" };
        self.pause_transitions.add(1, &[KeyValue::new("state", state)]);
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
