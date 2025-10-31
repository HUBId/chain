use std::collections::HashSet;

use opentelemetry::global;
use opentelemetry::metrics::noop::NoopMeterProvider;
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, MetricError, PeriodicReader, SdkMeterProvider};
use rpp_node::telemetry::pipeline::PipelineMetrics;
use rpp_runtime::orchestration::PipelineStage;

#[test]
fn pipeline_metrics_exporter_records_all_phases() -> Result<(), MetricError> {
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = SdkMeterProvider::builder().with_reader(reader).build();
    global::set_meter_provider(provider.clone());

    let metrics = PipelineMetrics::global();
    metrics.record_stage(PipelineStage::GossipReceived, 25, None);
    metrics.record_stage(PipelineStage::MempoolAccepted, 50, None);
    metrics.record_stage(PipelineStage::BftFinalised, 75, None);
    metrics.record_stage(PipelineStage::FirewoodCommitted, 100, Some(42));

    provider.force_flush()?;
    let exported = exporter.get_finished_metrics()?;

    let mut names = HashSet::new();
    for resource in &exported {
        for scope in &resource.scope_metrics {
            for metric in &scope.metrics {
                names.insert(metric.name.clone());
            }
        }
    }

    for expected in [
        "rpp.node.pipeline.stage_latency_ms",
        "rpp.node.pipeline.stage_total",
        "rpp.node.pipeline.commit_height",
    ] {
        assert!(names.contains(expected), "missing metric {expected}");
    }

    let debug_dump = format!("{:?}", exported);
    for phase in ["wallet", "proof", "consensus", "storage"] {
        assert!(
            debug_dump.contains(phase),
            "missing phase attribute {phase} in exported metrics"
        );
    }

    global::set_meter_provider(NoopMeterProvider::new());
    Ok(())
}
