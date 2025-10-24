use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use log::warn;
use opentelemetry::KeyValue;
use opentelemetry::global;
use opentelemetry::metrics::noop::NoopMeterProvider;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider, Temporality};

use crate::config::TelemetryConfig;

const METER_NAME: &str = "rpp-runtime";
const MILLIS_PER_SECOND: f64 = 1_000.0;

/// Initialise the runtime metrics provider using the OTLP exporter configured via `TelemetryConfig`.
///
/// When telemetry is disabled the returned provider still registers all instruments but no exporter
/// is attached which results in no data being sent.
pub fn init_runtime_metrics(
    config: &TelemetryConfig,
    resource: Resource,
) -> Result<(Arc<RuntimeMetrics>, RuntimeMetricsGuard)> {
    let mut provider_builder = SdkMeterProvider::builder().with_resource(resource);

    if config.enabled {
        let mut exporter_builder = opentelemetry_otlp::MetricExporter::builder().with_http();

        if let Some(endpoint) = config.endpoint.as_ref().filter(|value| !value.is_empty()) {
            exporter_builder = exporter_builder.with_endpoint(endpoint.clone());
        }

        let timeout = Duration::from_millis(config.timeout_ms.max(1));
        exporter_builder = exporter_builder.with_timeout(timeout);

        if let Some(token) = config.auth_token.as_ref().filter(|value| !value.is_empty()) {
            let mut headers = HashMap::new();
            headers.insert("Authorization".to_string(), format!("Bearer {token}"));
            exporter_builder = exporter_builder.with_headers(headers);
        }

        exporter_builder = exporter_builder.with_temporality(Temporality::Cumulative);

        let exporter = exporter_builder
            .build()
            .context("failed to build OTLP metrics exporter")?;

        let interval = Duration::from_secs(config.sample_interval_secs.max(1));
        let reader = PeriodicReader::builder(exporter)
            .with_interval(interval)
            .build();
        provider_builder = provider_builder.with_reader(reader);
    }

    let provider = provider_builder.build();
    global::set_meter_provider(provider.clone());

    let meter = provider.meter(METER_NAME);
    let metrics = Arc::new(RuntimeMetrics::from_meter(&meter));
    let guard = RuntimeMetricsGuard::new(provider);

    Ok((metrics, guard))
}

/// Wrapper that holds all runtime specific metric instruments.
#[derive(Clone)]
pub struct RuntimeMetrics {
    consensus_block_duration: EnumF64Histogram<ConsensusStage>,
    wallet_rpc_latency: EnumF64Histogram<WalletRpcMethod>,
    wal_flush_duration: EnumF64Histogram<WalFlushOutcome>,
    wal_flush_bytes: EnumU64Histogram<WalFlushOutcome>,
    proof_generation_duration: EnumF64Histogram<ProofKind>,
    proof_generation_size: EnumU64Histogram<ProofKind>,
    proof_generation_total: EnumCounter<ProofKind>,
}

impl RuntimeMetrics {
    fn from_meter(meter: &Meter) -> Self {
        let consensus_block_duration = EnumF64Histogram::new(
            meter
                .f64_histogram("rpp.runtime.consensus.block_duration")
                .with_description("Duration of consensus block pipeline phases in milliseconds")
                .with_unit("ms")
                .build(),
        );

        let wallet_rpc_latency = EnumF64Histogram::new(
            meter
                .f64_histogram("rpp.runtime.wallet.rpc_latency")
                .with_description("Latency of wallet RPC requests in milliseconds")
                .with_unit("ms")
                .build(),
        );

        let wal_flush_duration = EnumF64Histogram::new(
            meter
                .f64_histogram("rpp.runtime.storage.wal_flush.duration")
                .with_description("Duration of WAL flush operations in milliseconds")
                .with_unit("ms")
                .build(),
        );

        let wal_flush_bytes = EnumU64Histogram::new(
            meter
                .u64_histogram("rpp.runtime.storage.wal_flush.bytes")
                .with_description("Size of flushed WAL batches in bytes")
                .with_unit("By")
                .build(),
        );

        let proof_generation_duration = EnumF64Histogram::new(
            meter
                .f64_histogram("rpp.runtime.proof.generation.duration")
                .with_description("Time spent generating proving artefacts in milliseconds")
                .with_unit("ms")
                .build(),
        );

        let proof_generation_size = EnumU64Histogram::new(
            meter
                .u64_histogram("rpp.runtime.proof.generation.size")
                .with_description("Size of generated proofs in bytes")
                .with_unit("By")
                .build(),
        );

        let proof_generation_total = EnumCounter::new(
            meter
                .u64_counter("rpp.runtime.proof.generation.count")
                .with_description("Total number of proofs generated by the runtime")
                .with_unit("1")
                .build(),
        );

        Self {
            consensus_block_duration,
            wallet_rpc_latency,
            wal_flush_duration,
            wal_flush_bytes,
            proof_generation_duration,
            proof_generation_size,
            proof_generation_total,
        }
    }

    /// Returns a no-op metrics handle backed by a [`NoopMeterProvider`].
    pub fn noop() -> Arc<Self> {
        let meter = NoopMeterProvider::new().meter(METER_NAME);
        Arc::new(Self::from_meter(&meter))
    }

    /// Record the duration of a consensus stage.
    pub fn record_consensus_stage_duration(&self, stage: ConsensusStage, duration: Duration) {
        self.consensus_block_duration
            .record_duration(stage, duration);
    }

    /// Record the latency of a wallet RPC invocation.
    pub fn record_wallet_rpc_latency(&self, method: WalletRpcMethod, duration: Duration) {
        self.wallet_rpc_latency.record_duration(method, duration);
    }

    /// Record the duration of a WAL flush attempt.
    pub fn record_wal_flush_duration(&self, outcome: WalFlushOutcome, duration: Duration) {
        self.wal_flush_duration.record_duration(outcome, duration);
    }

    /// Record the number of bytes flushed to the WAL for the provided outcome.
    pub fn record_wal_flush_bytes(&self, outcome: WalFlushOutcome, bytes: u64) {
        self.wal_flush_bytes.record(outcome, bytes);
    }

    /// Record the time it took to generate a proof for the given kind.
    pub fn record_proof_generation_duration(&self, kind: ProofKind, duration: Duration) {
        self.proof_generation_duration
            .record_duration(kind, duration);
        self.proof_generation_total.add(kind, 1);
    }

    /// Record the resulting proof size for the provided proving backend.
    pub fn record_proof_generation_size(&self, kind: ProofKind, bytes: u64) {
        self.proof_generation_size.record(kind, bytes);
    }

    /// Increment the proof generation counter without emitting duration/size data.
    pub fn increment_proof_generation(&self, kind: ProofKind) {
        self.proof_generation_total.add(kind, 1);
    }
}

/// Guard that shuts down the underlying meter provider when dropped.
pub struct RuntimeMetricsGuard {
    provider: Option<SdkMeterProvider>,
}

impl RuntimeMetricsGuard {
    fn new(provider: SdkMeterProvider) -> Self {
        Self {
            provider: Some(provider),
        }
    }
}

impl Drop for RuntimeMetricsGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            if let Err(err) = provider.shutdown() {
                warn!(
                    target: "telemetry",
                    "failed to shutdown OTLP metrics provider: {err}"
                );
            }
            global::set_meter_provider(NoopMeterProvider::new());
        }
    }
}

/// Enumeration capturing the distinct phases of the consensus pipeline.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ConsensusStage {
    /// Stage responsible for proposing a block.
    Proposal,
    /// Stage executing the block contents.
    Execution,
    /// Stage verifying and voting on proposals.
    Validation,
    /// Stage finalising committed blocks.
    Commitment,
}

impl MetricLabel for ConsensusStage {
    const KEY: &'static str = "stage";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Proposal => "proposal",
            Self::Execution => "execution",
            Self::Validation => "validation",
            Self::Commitment => "commitment",
        }
    }
}

/// Wallet RPC surface area that is traced via metrics.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum WalletRpcMethod {
    /// Fetches account or balance data.
    GetBalance,
    /// Retrieves historical ledger state.
    GetHistory,
    /// Submits a signed transaction for inclusion.
    SubmitTransaction,
    /// Builds or validates proof bundles.
    BuildProof,
    /// Performs health checking style operations.
    Status,
}

impl MetricLabel for WalletRpcMethod {
    const KEY: &'static str = "method";

    fn as_str(&self) -> &'static str {
        match self {
            Self::GetBalance => "get_balance",
            Self::GetHistory => "get_history",
            Self::SubmitTransaction => "submit_transaction",
            Self::BuildProof => "build_proof",
            Self::Status => "status",
        }
    }
}

/// Outcomes emitted when flushing the write-ahead log.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum WalFlushOutcome {
    /// Flush completed successfully on the first attempt.
    Success,
    /// Flush required a retry but eventually succeeded.
    Retried,
    /// Flush failed permanently.
    Failed,
}

impl MetricLabel for WalFlushOutcome {
    const KEY: &'static str = "outcome";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Retried => "retried",
            Self::Failed => "failed",
        }
    }
}

/// Supported proving backends used by the runtime.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofKind {
    /// Production STWO proving backend.
    Stwo,
    /// Experimental Plonky3 proving backend.
    Plonky3,
    /// Deterministic mock backend for tests.
    Mock,
}

impl MetricLabel for ProofKind {
    const KEY: &'static str = "backend";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Stwo => "stwo",
            Self::Plonky3 => "plonky3",
            Self::Mock => "mock",
        }
    }
}

trait MetricLabel {
    const KEY: &'static str;

    fn as_str(&self) -> &'static str;
}

#[derive(Clone)]
struct EnumF64Histogram<L: MetricLabel> {
    histogram: Histogram<f64>,
    _marker: PhantomData<L>,
}

impl<L: MetricLabel> EnumF64Histogram<L> {
    fn new(histogram: Histogram<f64>) -> Self {
        Self {
            histogram,
            _marker: PhantomData,
        }
    }

    fn record_duration(&self, label: L, duration: Duration) {
        self.record(label, duration.as_secs_f64() * MILLIS_PER_SECOND);
    }

    fn record(&self, label: L, value: f64) {
        let attributes = [KeyValue::new(L::KEY, label.as_str())];
        self.histogram.record(value, &attributes);
    }
}

#[derive(Clone)]
struct EnumU64Histogram<L: MetricLabel> {
    histogram: Histogram<u64>,
    _marker: PhantomData<L>,
}

impl<L: MetricLabel> EnumU64Histogram<L> {
    fn new(histogram: Histogram<u64>) -> Self {
        Self {
            histogram,
            _marker: PhantomData,
        }
    }

    fn record(&self, label: L, value: u64) {
        let attributes = [KeyValue::new(L::KEY, label.as_str())];
        self.histogram.record(value, &attributes);
    }
}

#[derive(Clone)]
struct EnumCounter<L: MetricLabel> {
    counter: Counter<u64>,
    _marker: PhantomData<L>,
}

impl<L: MetricLabel> EnumCounter<L> {
    fn new(counter: Counter<u64>) -> Self {
        Self {
            counter,
            _marker: PhantomData,
        }
    }

    fn add(&self, label: L, value: u64) {
        let attributes = [KeyValue::new(L::KEY, label.as_str())];
        self.counter.add(value, &attributes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, MetricError};

    #[test]
    fn registers_runtime_metrics_instruments() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("runtime-test");
        let metrics = RuntimeMetrics::from_meter(&meter);

        metrics
            .record_consensus_stage_duration(ConsensusStage::Proposal, Duration::from_millis(10));
        metrics.record_wallet_rpc_latency(
            WalletRpcMethod::SubmitTransaction,
            Duration::from_millis(20),
        );
        metrics.record_wal_flush_duration(WalFlushOutcome::Success, Duration::from_millis(30));
        metrics.record_wal_flush_bytes(WalFlushOutcome::Success, 512);
        metrics.record_proof_generation_duration(ProofKind::Stwo, Duration::from_millis(40));
        metrics.record_proof_generation_size(ProofKind::Stwo, 1024);
        metrics.increment_proof_generation(ProofKind::Mock);

        provider.force_flush().expect("force flush metrics");
        let exported = exporter.get_finished_metrics()?;

        let mut seen = HashMap::new();
        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    seen.insert(metric.name.clone(), metric.unit.clone());
                }
            }
        }

        assert_eq!(
            seen.get("rpp.runtime.consensus.block_duration"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.rpc_latency"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.storage.wal_flush.duration"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.storage.wal_flush.bytes"),
            Some(&"By".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.proof.generation.duration"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.proof.generation.size"),
            Some(&"By".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.proof.generation.count"),
            Some(&"1".to_string())
        );

        Ok(())
    }
}
