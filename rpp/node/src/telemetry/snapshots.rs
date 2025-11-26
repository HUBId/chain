use std::sync::OnceLock;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::KeyValue;
use std::time::Duration;

static METRICS: OnceLock<SnapshotValidatorMetrics> = OnceLock::new();

#[derive(Clone)]
pub struct SnapshotValidatorMetrics {
    checksum_failures: Counter<u64>,
    scan_events: Counter<u64>,
    scan_duration_ms: Histogram<f64>,
}

impl SnapshotValidatorMetrics {
    const METER_NAME: &'static str = "rpp-node.snapshot-validator";

    fn new(meter: Meter) -> Self {
        let checksum_failures = meter
            .u64_counter("snapshot_chunk_checksum_failures_total")
            .with_description(
                "Total number of snapshot chunks whose checksum did not match the manifest entry",
            )
            .with_unit("1")
            .build();

        let scan_events = meter
            .u64_counter("rpp.node.snapshot_validator.scan_events_total")
            .with_description("Snapshot validator scan start/end events grouped by result")
            .with_unit("1")
            .build();

        let scan_duration_ms = meter
            .f64_histogram("rpp.node.snapshot_validator.scan_duration_ms")
            .with_description("Duration of snapshot validator scans grouped by result")
            .with_unit("ms")
            .build();

        Self {
            checksum_failures,
            scan_events,
            scan_duration_ms,
        }
    }

    pub fn global() -> &'static Self {
        METRICS.get_or_init(|| Self::new(global::meter(Self::METER_NAME)))
    }

    pub fn record_failure(&self, kind: &str) {
        self.checksum_failures
            .add(1, &[KeyValue::new("kind", kind.to_owned())]);
    }

    pub fn record_scan_start(&self) {
        self.scan_events.add(
            1,
            &[
                KeyValue::new("phase", "start"),
                KeyValue::new("result", "pending"),
            ],
        );
    }

    pub fn record_scan_end(&self, result: ScanResult, duration: Duration) {
        let attrs = [
            KeyValue::new("phase", "end"),
            KeyValue::new("result", result.as_str()),
        ];
        self.scan_events.add(1, &attrs);
        self.scan_duration_ms
            .record(duration.as_secs_f64() * 1_000.0, &attrs);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanResult {
    Success,
    Skipped,
    Failure,
}

impl ScanResult {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanResult::Success => "success",
            ScanResult::Skipped => "skipped",
            ScanResult::Failure => "failure",
        }
    }
}
