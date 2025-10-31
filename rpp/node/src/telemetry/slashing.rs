use std::sync::OnceLock;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::KeyValue;
use rpp_consensus::evidence::{EvidenceKind, EvidencePipeline};
use rpp_consensus::reputation::{SlashingEvent, SlashingKind, SlashingSnapshot};

static METRICS: OnceLock<SlashingMetrics> = OnceLock::new();

#[derive(Clone)]
pub struct SlashingMetrics {
    events_total: Counter<u64>,
    queue_depth: Histogram<u64>,
    queue_segments: Histogram<u64>,
    snapshot_totals: Histogram<u64>,
}

impl SlashingMetrics {
    const METER_NAME: &'static str = "rpp-node.slashing";

    fn new(meter: Meter) -> Self {
        let events_total = meter
            .u64_counter("rpp.node.slashing.events_total")
            .with_description("Total number of slashing events grouped by kind")
            .with_unit("1")
            .build();
        let queue_depth = meter
            .u64_histogram("rpp.node.slashing.queue_depth")
            .with_description("Size of the slashing evidence pipeline")
            .with_unit("1")
            .build();
        let queue_segments = meter
            .u64_histogram("rpp.node.slashing.queue_segments")
            .with_description("Number of queued evidence records per slashing category")
            .with_unit("1")
            .build();
        let snapshot_totals = meter
            .u64_histogram("rpp.node.slashing.snapshot_total")
            .with_description("Cumulative slashing counters grouped by category")
            .with_unit("1")
            .build();

        Self {
            events_total,
            queue_depth,
            queue_segments,
            snapshot_totals,
        }
    }

    pub fn global() -> &'static Self {
        METRICS.get_or_init(|| Self::new(global::meter(Self::METER_NAME)))
    }

    pub fn record_event(&self, event: &SlashingEvent) {
        let attrs = [KeyValue::new("kind", event.kind().as_str())];
        self.events_total.add(1, &attrs);
    }

    pub fn record_pipeline(&self, pipeline: &EvidencePipeline) {
        let total = pipeline.len() as u64;
        let counts = pipeline.counts();
        self.queue_depth.record(total, &[]);
        self.queue_segments.record(
            counts.double_signs as u64,
            &[KeyValue::new("kind", EvidenceKind::DoubleSign.as_str())],
        );
        self.queue_segments.record(
            counts.availability as u64,
            &[KeyValue::new("kind", EvidenceKind::Availability.as_str())],
        );
        self.queue_segments.record(
            counts.witness as u64,
            &[KeyValue::new("kind", EvidenceKind::Witness.as_str())],
        );
        self.queue_segments.record(
            counts.censorship as u64,
            &[KeyValue::new("kind", EvidenceKind::Censorship.as_str())],
        );
        self.queue_segments.record(
            counts.inactivity as u64,
            &[KeyValue::new("kind", EvidenceKind::Inactivity.as_str())],
        );
    }

    pub fn record_snapshot(&self, snapshot: &SlashingSnapshot) {
        self.snapshot_totals.record(
            snapshot.double_signs,
            &[KeyValue::new("kind", SlashingKind::DoubleSign.as_str())],
        );
        self.snapshot_totals.record(
            snapshot.availability_failures,
            &[KeyValue::new("kind", SlashingKind::Availability.as_str())],
        );
        self.snapshot_totals.record(
            snapshot.witness_reports,
            &[KeyValue::new("kind", SlashingKind::Witness.as_str())],
        );
        self.snapshot_totals.record(
            snapshot.censorship_events,
            &[KeyValue::new("kind", SlashingKind::Censorship.as_str())],
        );
        self.snapshot_totals.record(
            snapshot.inactivity_events,
            &[KeyValue::new("kind", SlashingKind::Inactivity.as_str())],
        );
    }
}
