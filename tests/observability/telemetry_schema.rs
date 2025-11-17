use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use opentelemetry::global;
use opentelemetry::metrics::noop::NoopMeterProvider;
use opentelemetry_sdk::metrics::data::{Data, Histogram, Sum};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
use rpp_runtime::runtime::telemetry::metrics::{
    ConsensusStage, ProofKind, ProofVerificationBackend, ProofVerificationKind,
    ProofVerificationOutcome, ProofVerificationStage, RpcMethod, RpcResult, WalFlushOutcome,
    WalletRpcMethod,
};
use rpp_runtime::RuntimeMetrics;
use rpp_wallet_interface::runtime_telemetry::{WalletAction, WalletActionResult};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TelemetrySchema {
    metrics: Vec<MetricEntry>,
}

#[derive(Debug, Deserialize)]
struct MetricEntry {
    name: String,
    #[serde(default)]
    labels: Vec<String>,
}

#[test]
fn telemetry_metrics_match_allowlist() -> Result<()> {
    let exporter = InMemoryMetricExporter::default();
    let reader = PeriodicReader::builder(exporter.clone()).build();
    let provider = SdkMeterProvider::builder().with_reader(reader).build();
    global::set_meter_provider(provider.clone());

    let meter = provider.meter("telemetry-schema-test");
    let metrics = RuntimeMetrics::from_meter_for_testing(&meter);

    metrics.record_consensus_stage_duration(ConsensusStage::Commitment, Duration::from_millis(7));
    metrics.record_wallet_rpc_latency(WalletRpcMethod::SubmitTransaction, Duration::from_millis(5));
    metrics.record_wallet_action(WalletAction::BackupExport, WalletActionResult::Success);
    metrics.record_rpc_request(
        RpcMethod::Wallet(WalletRpcMethod::RuntimeStatus),
        RpcResult::ClientError,
        Duration::from_millis(11),
    );
    metrics.record_wal_flush_duration(WalFlushOutcome::Retried, Duration::from_millis(13));
    metrics.record_wal_flush_bytes(WalFlushOutcome::Retried, 8192);
    metrics.increment_wal_flushes(WalFlushOutcome::Retried);
    metrics.record_header_flush_duration(Duration::from_millis(3));
    metrics.record_header_flush_bytes(2048);
    metrics.increment_header_flushes();
    metrics.record_proof_generation_duration(ProofKind::Stwo, Duration::from_millis(17));
    metrics.record_proof_generation_size(ProofKind::Stwo, 4096);
    metrics.increment_proof_generation(ProofKind::Mock);
    metrics.record_consensus_round_duration(9, 2, Duration::from_millis(23));
    metrics.record_consensus_quorum_latency(9, 2, Duration::from_millis(19));
    metrics.record_consensus_vrf_verification_success(Duration::from_millis(2));
    metrics
        .record_consensus_vrf_verification_failure(Duration::from_millis(4), "invalid_vrf_proof");
    metrics.record_consensus_quorum_verification_success();
    metrics.record_consensus_quorum_verification_failure("duplicate_precommit");
    metrics.record_consensus_leader_change(9, 2, "validator-A");
    metrics.record_consensus_witness_event("blocks");
    metrics.record_consensus_slashing_event("equivocation");
    metrics.record_consensus_failed_vote("timeout");
    metrics.record_block_height(128);
    metrics.record_peer_count(21);
    metrics.record_reputation_penalty("gossip_spam");

    let proofs = metrics.proofs();
    proofs.observe_verification(
        ProofVerificationBackend::RppStark,
        ProofVerificationKind::Transaction,
        Duration::from_millis(29),
    );
    proofs.observe_verification_total_bytes(
        ProofVerificationBackend::RppStark,
        ProofVerificationKind::Transaction,
        16384,
    );
    proofs.observe_verification_params_bytes(
        ProofVerificationBackend::RppStark,
        ProofVerificationKind::Transaction,
        512,
    );
    proofs.observe_verification_public_inputs_bytes(
        ProofVerificationBackend::RppStark,
        ProofVerificationKind::Transaction,
        2048,
    );
    proofs.observe_verification_payload_bytes(
        ProofVerificationBackend::RppStark,
        ProofVerificationKind::Transaction,
        8192,
    );
    proofs.observe_verification_stage(
        ProofVerificationBackend::RppStark,
        ProofVerificationKind::Transaction,
        ProofVerificationStage::Fri,
        ProofVerificationOutcome::Fail,
    );

    provider
        .force_flush()
        .context("flush runtime telemetry metrics")?;
    let exported = exporter
        .get_finished_metrics()
        .context("collect in-memory metric export")?;

    let mut actual: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for resource in &exported {
        for scope in &resource.scope_metrics {
            for metric in &scope.metrics {
                let labels = actual.entry(metric.name.clone()).or_default();
                match &metric.data {
                    Data::Histogram(histogram) => collect_histogram_labels(histogram, labels),
                    Data::Sum(sum) => collect_sum_labels(sum, labels),
                    _ => {}
                }
            }
        }
    }

    let schema_path = workspace_root().join("telemetry/schema.yaml");
    let schema_contents = fs::read_to_string(&schema_path)
        .with_context(|| format!("read telemetry schema from {}", schema_path.display()))?;
    let schema: TelemetrySchema = serde_yaml::from_str(&schema_contents)
        .with_context(|| format!("parse telemetry schema at {}", schema_path.display()))?;

    let mut expected: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in schema.metrics {
        expected.insert(entry.name, entry.labels.into_iter().collect());
    }

    let mut failures = Vec::new();

    for (name, labels) in &expected {
        match actual.get(name) {
            Some(actual_labels) => {
                if actual_labels != labels {
                    failures.push(format!(
                        "metric '{}' labels mismatch: expected {:?}, found {:?}",
                        name, labels, actual_labels
                    ));
                }
            }
            None => failures.push(format!(
                "metric '{}' defined in telemetry/schema.yaml was not exported",
                name
            )),
        }
    }

    for name in actual.keys() {
        if !expected.contains_key(name) {
            failures.push(format!(
                "metric '{}' exported by runtime is missing from telemetry/schema.yaml",
                name
            ));
        }
    }

    provider
        .shutdown()
        .context("shutdown runtime telemetry metrics provider")?;
    global::set_meter_provider(NoopMeterProvider::new());

    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(failures.join("\n")))
    }
}

fn collect_histogram_labels<T>(histogram: &Histogram<T>, sink: &mut BTreeSet<String>) {
    for point in &histogram.points {
        merge_attribute_keys(&point.attributes, sink);
    }
}

fn collect_sum_labels<T>(sum: &Sum<T>, sink: &mut BTreeSet<String>) {
    for point in &sum.points {
        merge_attribute_keys(&point.attributes, sink);
    }
}

fn merge_attribute_keys(
    attributes: &opentelemetry_sdk::attributes::AttributeSet,
    sink: &mut BTreeSet<String>,
) {
    for (key, _) in attributes.iter() {
        sink.insert(key.as_str().to_string());
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}
