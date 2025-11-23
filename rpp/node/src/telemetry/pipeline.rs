use std::sync::OnceLock;

use opentelemetry::global;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::KeyValue;
use rpp_runtime::orchestration::PipelineStage;

static METRICS: OnceLock<PipelineMetrics> = OnceLock::new();

#[derive(Clone)]
pub struct PipelineMetrics {
    stage_latency_ms: Histogram<f64>,
    stage_total: Counter<u64>,
    commit_height: Histogram<u64>,
    root_io_errors_total: Counter<u64>,
    state_sync_tamper_total: Counter<u64>,
}

impl PipelineMetrics {
    const METER_NAME: &'static str = "rpp-node.pipeline";

    fn new(meter: Meter) -> Self {
        let stage_latency_ms = meter
            .f64_histogram("rpp.node.pipeline.stage_latency_ms")
            .with_description("Latency in milliseconds from wallet submission until a pipeline stage is observed, grouped by phase")
            .with_unit("ms")
            .build();
        let stage_total = meter
            .u64_counter("rpp.node.pipeline.stage_total")
            .with_description("Total number of pipeline stage observations grouped by phase")
            .with_unit("1")
            .build();
        let commit_height = meter
            .u64_histogram("rpp.node.pipeline.commit_height")
            .with_description("Firewood commit height recorded when the storage stage completes")
            .with_unit("1")
            .build();
        let root_io_errors_total = meter
            .u64_counter("rpp_node_pipeline_root_io_errors_total")
            .with_description(
                "Total number of Firewood snapshot root IO errors encountered during state sync verification",
            )
            .with_unit("1")
            .build();
        let state_sync_tamper_total = meter
            .u64_counter("rpp_node_pipeline_state_sync_tamper_total")
            .with_description(
                "Total number of tamper events detected while verifying state-sync manifests or chunks",
            )
            .with_unit("1")
            .build();

        Self {
            stage_latency_ms,
            stage_total,
            commit_height,
            root_io_errors_total,
            state_sync_tamper_total,
        }
    }

    pub fn global() -> &'static Self {
        METRICS.get_or_init(|| Self::new(global::meter(Self::METER_NAME)))
    }

    pub fn record_stage(
        &self,
        stage: PipelineStage,
        observed_ms: u128,
        commit_height: Option<u64>,
    ) {
        if let Some(phase) = PipelinePhase::from_stage(stage) {
            let attrs = [KeyValue::new("phase", phase.as_str())];

            self.stage_latency_ms.record(observed_ms as f64, &attrs);
            self.stage_total.add(1, &attrs);

            if let Some(height) = commit_height {
                self.commit_height.record(height, &attrs);
            }
        }
    }

    pub fn record_root_io_error(&self, request_id: Option<&str>) {
        let attrs = request_id
            .map(|id| vec![KeyValue::new("request_id", id.to_string())])
            .unwrap_or_default();
        self.root_io_errors_total.add(1, &attrs);
    }

    pub fn record_state_sync_tamper(&self, reason: &'static str, request_id: Option<&str>) {
        let mut attrs = vec![KeyValue::new("reason", reason)];
        if let Some(id) = request_id {
            attrs.push(KeyValue::new("request_id", id.to_string()));
        }
        self.state_sync_tamper_total.add(1, &attrs);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PipelinePhase {
    Wallet,
    Proof,
    Consensus,
    Storage,
}

impl PipelinePhase {
    fn as_str(self) -> &'static str {
        match self {
            PipelinePhase::Wallet => "wallet",
            PipelinePhase::Proof => "proof",
            PipelinePhase::Consensus => "consensus",
            PipelinePhase::Storage => "storage",
        }
    }

    fn from_stage(stage: PipelineStage) -> Option<Self> {
        match stage {
            PipelineStage::GossipReceived => Some(PipelinePhase::Wallet),
            PipelineStage::MempoolAccepted => Some(PipelinePhase::Proof),
            PipelineStage::BftFinalised => Some(PipelinePhase::Consensus),
            PipelineStage::FirewoodCommitted => Some(PipelinePhase::Storage),
            _ => None,
        }
    }
}
