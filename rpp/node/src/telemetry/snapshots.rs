use std::sync::OnceLock;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Meter};
use opentelemetry::KeyValue;

static METRICS: OnceLock<SnapshotValidatorMetrics> = OnceLock::new();

#[derive(Clone)]
pub struct SnapshotValidatorMetrics {
    checksum_failures: Counter<u64>,
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

        Self { checksum_failures }
    }

    pub fn global() -> &'static Self {
        METRICS.get_or_init(|| Self::new(global::meter(Self::METER_NAME)))
    }

    pub fn record_failure(&self, kind: &str) {
        self.checksum_failures
            .add(1, &[KeyValue::new("kind", kind.to_owned())]);
    }
}
