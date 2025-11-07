use std::sync::OnceLock;
use std::time::Duration;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::KeyValue;

static METRICS: OnceLock<AdmissionReconcilerMetrics> = OnceLock::new();

#[derive(Clone)]
pub struct AdmissionReconcilerMetrics {
    cycle_duration_ms: Histogram<f64>,
    cycle_total: Counter<u64>,
    drift_detected: Counter<u64>,
}

impl AdmissionReconcilerMetrics {
    const METER_NAME: &'static str = "rpp-node.admission";

    fn new(meter: Meter) -> Self {
        let cycle_duration_ms = meter
            .f64_histogram("rpp.node.admission.reconcile_duration_ms")
            .with_description("Duration of admission policy reconciliation cycles")
            .with_unit("ms")
            .build();
        let cycle_total = meter
            .u64_counter("rpp.node.admission.reconcile_total")
            .with_description(
                "Total admission policy reconciliation checks grouped by drift outcome",
            )
            .with_unit("1")
            .build();
        let drift_detected = meter
            .u64_counter("rpp.node.admission.policy_drift_detected_total")
            .with_description("Count of admission policy drift detections grouped by source")
            .with_unit("1")
            .build();

        Self {
            cycle_duration_ms,
            cycle_total,
            drift_detected,
        }
    }

    pub fn global() -> &'static Self {
        METRICS.get_or_init(|| Self::new(global::meter(Self::METER_NAME)))
    }

    pub fn record_cycle(&self, duration: Duration, drift: bool) {
        let duration_ms = duration.as_secs_f64() * 1_000.0;
        self.cycle_duration_ms.record(duration_ms, &[]);
        let attrs = [KeyValue::new("drift", if drift { "true" } else { "false" })];
        self.cycle_total.add(1, &attrs);
    }

    pub fn record_drift(&self, kind: DriftKind, count: u64) {
        let attrs = [KeyValue::new("kind", kind.as_str())];
        self.drift_detected.add(count, &attrs);
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DriftKind {
    Disk,
    Audit,
    AuditLag,
}

impl DriftKind {
    fn as_str(self) -> &'static str {
        match self {
            DriftKind::Disk => "disk",
            DriftKind::Audit => "audit",
            DriftKind::AuditLag => "audit_lag",
        }
    }
}
