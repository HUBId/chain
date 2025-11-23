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
    #[serde(default)]
    alternate_labels: Vec<Vec<String>>,
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
    metrics.record_wallet_prover_job_duration("mock", true, Duration::from_millis(33));
    metrics.record_wallet_prover_witness_bytes("mock", 2048);
    metrics.record_wallet_prover_backend("mock", true);
    metrics.record_wallet_prover_failure("mock", "PROVER_INTERNAL");
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
    proofs.observe_verification_total_bytes_by_result(
        ProofVerificationBackend::RppStark,
        ProofVerificationKind::Transaction,
        ProofVerificationOutcome::Fail,
        32768,
    );
    proofs.observe_verification_total_bytes(
        ProofVerificationBackend::Stwo,
        ProofVerificationKind::State,
        8192,
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
    proofs.observe_verification_stage_duration(
        ProofVerificationBackend::RppStark,
        ProofVerificationKind::Transaction,
        ProofVerificationStage::Merkle,
        Duration::from_millis(7),
    );
    proofs.observe_verification_stage_duration(
        ProofVerificationBackend::Stwo,
        ProofVerificationKind::Transaction,
        ProofVerificationStage::Parse,
        Duration::from_millis(4),
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

    let expected = load_schema()?;

    let mut failures = Vec::new();

    failures.extend(validate_label_sets(&actual, &expected));

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

#[test]
fn zk_metric_labels_allow_stage_variants() -> Result<()> {
    let expected = load_schema()?;
    let metric = "rpp_stark_verify_duration_seconds";

    let allowed_sets = expected
        .get(metric)
        .context("load zk verification metric from schema")?;
    assert!(
        allowed_sets.iter().any(|labels| labels.contains("stage")),
        "schema should list a stage-bearing variant for zk metrics"
    );

    let mut actual = BTreeMap::new();
    actual.insert(
        metric.to_string(),
        BTreeSet::from_iter([
            "proof_backend".to_string(),
            "proof_kind".to_string(),
            "stage".to_string(),
        ]),
    );

    let failures = validate_label_sets(&actual, &expected);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(failures.join("\n")))
    }
}

fn load_schema() -> Result<BTreeMap<String, Vec<BTreeSet<String>>>> {
    let schema_path = workspace_root().join("telemetry/schema.yaml");
    let schema_contents = fs::read_to_string(&schema_path)
        .with_context(|| format!("read telemetry schema from {}", schema_path.display()))?;
    let schema: TelemetrySchema = serde_yaml::from_str(&schema_contents)
        .with_context(|| format!("parse telemetry schema at {}", schema_path.display()))?;

    let mut expected: BTreeMap<String, Vec<BTreeSet<String>>> = BTreeMap::new();
    for entry in schema.metrics {
        let mut label_sets = Vec::new();
        label_sets.push(entry.labels.into_iter().collect());

        for alternate in entry.alternate_labels {
            label_sets.push(alternate.into_iter().collect());
        }

        expected.insert(entry.name, label_sets);
    }

    Ok(expected)
}

fn validate_label_sets(
    actual: &BTreeMap<String, BTreeSet<String>>,
    expected: &BTreeMap<String, Vec<BTreeSet<String>>>,
) -> Vec<String> {
    let mut failures = Vec::new();

    for (name, label_sets) in expected {
        if let Some(actual_labels) = actual.get(name) {
            let matches = label_sets.iter().any(|labels| labels == actual_labels);
            if !matches {
                failures.push(format!(
                    "metric '{}' labels mismatch: expected one of {:?}, found {:?}",
                    name, label_sets, actual_labels
                ));
            }
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

    failures
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

#[test]
fn zk_backend_labels_are_stable() {
    assert_eq!(ProofKind::Stwo.as_str(), "stwo");
    assert_eq!(ProofVerificationBackend::RppStark.as_str(), "rpp-stark");
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}
