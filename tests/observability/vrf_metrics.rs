use std::collections::HashSet;

use opentelemetry::global;
use opentelemetry::metrics::noop::NoopMeterProvider;
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, MetricError, PeriodicReader, SdkMeterProvider};
use rpp_crypto_vrf::telemetry::VrfTelemetry;
use rpp_crypto_vrf::VrfSelectionMetrics;

#[test]
fn vrf_metrics_exporter_records_selection_rounds() -> std::result::Result<(), MetricError> {
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = SdkMeterProvider::builder().with_reader(reader).build();
    global::set_meter_provider(provider.clone());

    let telemetry = VrfTelemetry::global();
    let mut metrics = VrfSelectionMetrics::default();
    metrics.pool_entries = 4;
    metrics.target_validator_count = 2;
    metrics.unique_addresses = 4;
    metrics.verified_submissions = 3;
    metrics.accepted_validators = 2;
    metrics.rejected_candidates = 1;
    metrics.fallback_selected = true;
    metrics.participation_rate = 0.5;
    metrics.latest_epoch = Some(42);
    metrics.latest_round = Some(7);
    metrics.active_epoch_threshold = Some("1337".into());

    telemetry.record_selection(&metrics);

    provider.force_flush()?;
    let exported = exporter.get_finished_metrics()?;

    let mut seen = HashSet::new();
    for resource in exported {
        for scope in resource.scope_metrics {
            for metric in scope.metrics {
                seen.insert(metric.name);
            }
        }
    }

    for expected in [
        "rpp.crypto_vrf.selection.pool_entries",
        "rpp.crypto_vrf.selection.target_validator_count",
        "rpp.crypto_vrf.selection.unique_addresses",
        "rpp.crypto_vrf.selection.participation_rate",
        "rpp.crypto_vrf.selection.verified_total",
        "rpp.crypto_vrf.selection.accepted_total",
        "rpp.crypto_vrf.selection.rejected_total",
        "rpp.crypto_vrf.selection.fallback_total",
        "rpp.crypto_vrf.selection.latest_epoch",
        "rpp.crypto_vrf.selection.latest_round",
        "rpp.crypto_vrf.selection.threshold_transitions",
    ] {
        assert!(seen.contains(expected), "missing metric {expected}");
    }

    global::set_meter_provider(NoopMeterProvider::new());
    Ok(())
}
