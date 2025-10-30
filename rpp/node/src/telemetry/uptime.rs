use std::sync::OnceLock;
use std::time::Duration;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::KeyValue;

static METRICS: OnceLock<UptimeMetrics> = OnceLock::new();

#[derive(Clone)]
pub struct UptimeMetrics {
    cycle_duration_ms: Histogram<f64>,
    cycle_total: Counter<u64>,
    credited_hours: Histogram<u64>,
    pending_queue: Histogram<u64>,
    failures_total: Counter<u64>,
}

impl UptimeMetrics {
    const METER_NAME: &'static str = "rpp-node.uptime";

    fn new(meter: Meter) -> Self {
        let cycle_duration_ms = meter
            .f64_histogram("rpp.node.uptime.cycle_duration_ms")
            .with_description("Duration of uptime scheduler cycles in milliseconds")
            .with_unit("ms")
            .build();
        let cycle_total = meter
            .u64_counter("rpp.node.uptime.cycle_total")
            .with_description("Total number of uptime scheduler cycles grouped by outcome")
            .with_unit("1")
            .build();
        let credited_hours = meter
            .u64_histogram("rpp.node.uptime.credited_hours")
            .with_description("Number of uptime hours credited per successful cycle")
            .with_unit("h")
            .build();
        let pending_queue = meter
            .u64_histogram("rpp.node.uptime.pending_queue")
            .with_description("Snapshot of pending uptime proofs queued in the node mempool")
            .with_unit("1")
            .build();
        let failures_total = meter
            .u64_counter("rpp.node.uptime.failures_total")
            .with_description("Total number of uptime scheduler failures grouped by stage")
            .with_unit("1")
            .build();

        Self {
            cycle_duration_ms,
            cycle_total,
            credited_hours,
            pending_queue,
            failures_total,
        }
    }

    pub fn global() -> &'static Self {
        METRICS.get_or_init(|| Self::new(global::meter(Self::METER_NAME)))
    }

    pub fn record_cycle(&self, outcome: CycleOutcome, duration: Duration, credited: Option<u64>) {
        let attrs = [KeyValue::new("outcome", outcome.as_str())];
        self.cycle_duration_ms
            .record(duration.as_secs_f64() * 1_000.0, &attrs);
        self.cycle_total.add(1, &attrs);
        if let Some(hours) = credited {
            self.credited_hours.record(hours, &[]);
        }
    }

    pub fn record_pending_queue(&self, size: usize) {
        self.pending_queue.record(size as u64, &[]);
    }

    pub fn record_failure(&self, phase: CyclePhase) {
        self.failures_total
            .add(1, &[KeyValue::new("stage", phase.as_str())]);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CycleOutcome {
    Success,
    Skipped,
    Error,
}

impl CycleOutcome {
    fn as_str(self) -> &'static str {
        match self {
            CycleOutcome::Success => "success",
            CycleOutcome::Skipped => "skipped",
            CycleOutcome::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CyclePhase {
    NodeStatus,
    Wallet,
    Submission,
    Gossip,
}

impl CyclePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            CyclePhase::NodeStatus => "node_status",
            CyclePhase::Wallet => "wallet",
            CyclePhase::Submission => "submission",
            CyclePhase::Gossip => "gossip",
        }
    }
}
