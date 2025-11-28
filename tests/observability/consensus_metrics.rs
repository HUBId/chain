use std::collections::HashMap;
use std::time::Duration;

use opentelemetry::global;
use opentelemetry::metrics::noop::NoopMeterProvider;
use opentelemetry_sdk::metrics::data::{Data, Histogram, Sum};
use opentelemetry_sdk::metrics::{
    InMemoryMetricExporter, MetricError, PeriodicReader, SdkMeterProvider,
};
use rpp_runtime::RuntimeMetrics;

#[test]
fn consensus_metrics_capture_vrf_and_quorum_outcomes() -> Result<(), MetricError> {
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = SdkMeterProvider::builder().with_reader(reader).build();
    global::set_meter_provider(provider.clone());

    let meter = provider.meter("rpp-runtime");
    let metrics = RuntimeMetrics::from_meter_for_testing(&meter);

    metrics.record_consensus_vrf_verification_success(Duration::from_millis(5));
    metrics
        .record_consensus_vrf_verification_failure(Duration::from_millis(7), "invalid_vrf_proof");
    metrics.record_consensus_quorum_verification_success();
    metrics.record_consensus_quorum_verification_failure("duplicate_precommit");

    provider.force_flush()?;
    let exported = exporter.get_finished_metrics()?;

    let mut sums: HashMap<String, HashMap<String, u64>> = HashMap::new();
    let mut histogram_counts: HashMap<String, HashMap<String, u64>> = HashMap::new();

    for resource in &exported {
        for scope in &resource.scope_metrics {
            for metric in &scope.metrics {
                match &metric.data {
                    Data::Histogram(histogram) => {
                        collect_histogram(&metric.name, histogram, &mut histogram_counts);
                    }
                    Data::Sum(sum) => {
                        collect_sum(&metric.name, sum, &mut sums);
                    }
                    _ => {}
                }
            }
        }
    }

    let vrf_hist = histogram_counts
        .get("consensus_vrf_verification_time_ms")
        .expect("vrf latency histogram not exported");
    assert_eq!(
        vrf_hist.get("result=success").copied(),
        Some(1),
        "successful VRF verification should record one histogram sample"
    );
    assert_eq!(
        vrf_hist
            .get("result=failure,reason=invalid_vrf_proof")
            .copied(),
        Some(1),
        "failed VRF verification should record one histogram sample with reason label"
    );

    let vrf_totals = sums
        .get("consensus_vrf_verifications_total")
        .expect("vrf verification counter not exported");
    assert_eq!(
        vrf_totals.get("result=success").copied(),
        Some(1),
        "successful VRF verification should increment the counter"
    );
    assert_eq!(
        vrf_totals
            .get("result=failure,reason=invalid_vrf_proof")
            .copied(),
        Some(1),
        "failed VRF verification should increment the counter with reason"
    );

    let quorum_totals = sums
        .get("consensus_quorum_verifications_total")
        .expect("quorum verification counter not exported");
    assert_eq!(
        quorum_totals.get("result=success").copied(),
        Some(1),
        "successful quorum verification should increment the counter"
    );
    assert_eq!(
        quorum_totals
            .get("result=failure,reason=duplicate_precommit")
            .copied(),
        Some(1),
        "failed quorum verification should increment the counter with reason"
    );

    global::set_meter_provider(NoopMeterProvider::new());
    Ok(())
}

#[test]
fn validator_change_and_timetoke_mismatch_metrics_export() -> Result<(), MetricError> {
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = SdkMeterProvider::builder().with_reader(reader).build();
    global::set_meter_provider(provider.clone());

    let meter = provider.meter("rpp-runtime");
    let metrics = RuntimeMetrics::from_meter_for_testing(&meter);

    metrics.record_validator_set_change(7, 42);
    metrics.record_validator_set_quorum_delay(7, 42, Duration::from_millis(1800));
    metrics.record_timetoke_root_mismatch("gossip_delta", Some("peer-1".into()));

    provider.force_flush()?;
    let exported = exporter.get_finished_metrics()?;

    let mut sums: HashMap<String, HashMap<String, u64>> = HashMap::new();
    let mut histogram_counts: HashMap<String, HashMap<String, u64>> = HashMap::new();

    for resource in &exported {
        for scope in &resource.scope_metrics {
            for metric in &scope.metrics {
                match &metric.data {
                    Data::Histogram(histogram) => {
                        collect_histogram(&metric.name, histogram, &mut histogram_counts);
                    }
                    Data::Sum(sum) => {
                        collect_sum(&metric.name, sum, &mut sums);
                    }
                    _ => {}
                }
            }
        }
    }

    let validator_changes = sums
        .get("validator_set_changes_total")
        .expect("validator change counter missing");
    assert_eq!(
        validator_changes.get("epoch=7").copied(),
        Some(1),
        "validator set transitions should be counted",
    );

    let height_samples = histogram_counts
        .get("validator_set_change_height")
        .expect("validator change height histogram missing");
    assert_eq!(
        height_samples.get("epoch=7").copied(),
        Some(1),
        "validator change height should record a sample",
    );

    let quorum_delay = histogram_counts
        .get("validator_set_change_quorum_delay_ms")
        .expect("validator change quorum delay histogram missing");
    assert_eq!(
        quorum_delay.get("epoch=7,height=42").copied(),
        Some(1),
        "quorum delay should capture epoch and height labels",
    );

    let timetoke_mismatches = sums
        .get("timetoke_root_mismatch_total")
        .expect("timetoke mismatch counter missing");
    assert_eq!(
        timetoke_mismatches
            .get("peer=peer-1,source=gossip_delta")
            .copied(),
        Some(1),
        "timetoke root mismatch counter should track source and peer",
    );

    global::set_meter_provider(NoopMeterProvider::new());
    Ok(())
}

fn collect_sum(name: &str, sum: &Sum<u64>, sink: &mut HashMap<String, HashMap<String, u64>>) {
    let entries = sink.entry(name.to_string()).or_default();
    for point in &sum.points {
        let key = format_attributes(&point.attributes);
        entries.insert(key, point.value);
    }
}

fn collect_histogram(
    name: &str,
    histogram: &Histogram<f64>,
    sink: &mut HashMap<String, HashMap<String, u64>>,
) {
    let entries = sink.entry(name.to_string()).or_default();
    for point in &histogram.points {
        let key = format_attributes(&point.attributes);
        entries.insert(key, point.count);
    }
}

fn format_attributes(attributes: &opentelemetry::Attributes) -> String {
    if attributes.is_empty() {
        return String::new();
    }

    let mut pairs: Vec<_> = attributes
        .iter()
        .map(|(key, value)| format!("{}={}", key.as_str(), value.to_string()))
        .collect();
    pairs.sort();
    pairs.join(",")
}
