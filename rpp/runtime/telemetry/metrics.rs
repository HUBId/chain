use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use firewood_storage::{
    StorageMetrics as StorageMetricsFacade, WalFlushOutcome as StorageWalFlushOutcome,
};
use http::StatusCode;
use log::warn;
use opentelemetry::global;
use opentelemetry::metrics::noop::NoopMeterProvider;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::{PeriodicReader, SdkMeterProvider};
use opentelemetry_sdk::Resource;

use super::exporter::TelemetryExporterBuilder;
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
        let exporter_builder = TelemetryExporterBuilder::new(config);
        match exporter_builder.build_metric_exporter()? {
            Some(exporter) => {
                let interval = Duration::from_secs(config.sample_interval_secs.max(1));
                let reader = PeriodicReader::builder(exporter)
                    .with_interval(interval)
                    .build();
                provider_builder = provider_builder.with_reader(reader);
            }
            None => {
                if config.warn_on_drop {
                    warn!(
                        target = "telemetry",
                        "telemetry metrics exporter disabled due to missing OTLP/HTTP endpoint; metrics will only be logged"
                    );
                }
            }
        }
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
    proofs: ProofMetrics,
    consensus_block_duration: EnumF64Histogram<ConsensusStage>,
    wallet_rpc_latency: EnumF64Histogram<WalletRpcMethod>,
    wallet_action_total: RpcCounter<WalletAction, WalletActionResult>,
    wallet_fee_estimate_latency: Histogram<f64>,
    wallet_prover_job_duration: Histogram<f64>,
    wallet_rescan_duration: Histogram<f64>,
    wallet_broadcast_rejected: Counter<u64>,
    wallet_runtime_watch_active: Histogram<u64>,
    wallet_sync_driver_active: Histogram<u64>,
    rpc_request_latency: RpcHistogram<RpcMethod, RpcResult>,
    rpc_request_total: RpcCounter<RpcMethod, RpcResult>,
    wal_flush_duration: EnumF64Histogram<WalFlushOutcome>,
    wal_flush_bytes: EnumU64Histogram<WalFlushOutcome>,
    wal_flush_total: EnumCounter<WalFlushOutcome>,
    header_flush_duration: Histogram<f64>,
    header_flush_bytes: Histogram<u64>,
    header_flush_total: Counter<u64>,
    consensus_round_duration: Histogram<f64>,
    consensus_quorum_latency: Histogram<f64>,
    consensus_vrf_verification_time: Histogram<f64>,
    consensus_vrf_verifications_total: Counter<u64>,
    consensus_quorum_verifications_total: Counter<u64>,
    consensus_leader_changes: Counter<u64>,
    consensus_witness_events: Counter<u64>,
    consensus_slashing_events: Counter<u64>,
    consensus_failed_votes: Counter<u64>,
    chain_block_height: Histogram<u64>,
    network_peer_counts: Histogram<u64>,
    reputation_penalties: Counter<u64>,
    state_sync_stream_starts: Counter<u64>,
    state_sync_stream_chunks: Counter<u64>,
    state_sync_stream_backpressure: Counter<u64>,
    state_sync_active_streams: Histogram<u64>,
}

impl RuntimeMetrics {
    fn from_meter(meter: &Meter) -> Self {
        Self {
            proofs: ProofMetrics::new(meter),
            consensus_block_duration: EnumF64Histogram::new(
                meter
                    .f64_histogram("rpp.runtime.consensus.block_duration")
                    .with_description("Duration of consensus block pipeline phases in milliseconds")
                    .with_unit("ms")
                    .build(),
            ),
            wallet_rpc_latency: EnumF64Histogram::new(
                meter
                    .f64_histogram("rpp.runtime.wallet.rpc_latency")
                    .with_description("Latency of wallet RPC requests in milliseconds")
                    .with_unit("ms")
                    .build(),
            ),
            wallet_action_total: RpcCounter::new(
                meter
                    .u64_counter("rpp.runtime.wallet.action.total")
                    .with_description("Total wallet action outcomes grouped by label and result")
                    .with_unit("1")
                    .build(),
            ),
            wallet_fee_estimate_latency: meter
                .f64_histogram("rpp.runtime.wallet.fee.estimate.latency_ms")
                .with_description("Latency of wallet fee estimation requests in milliseconds")
                .with_unit("ms")
                .build(),
            wallet_prover_job_duration: meter
                .f64_histogram("rpp.runtime.wallet.prover.job.duration_ms")
                .with_description("Duration of wallet prover jobs in milliseconds")
                .with_unit("ms")
                .build(),
            wallet_rescan_duration: meter
                .f64_histogram("rpp.runtime.wallet.scan.rescan.duration_ms")
                .with_description("Latency of wallet rescan scheduling requests in milliseconds")
                .with_unit("ms")
                .build(),
            wallet_broadcast_rejected: meter
                .u64_counter("rpp.runtime.wallet.broadcast.rejected")
                .with_description("Total wallet transaction broadcast rejections grouped by reason")
                .with_unit("1")
                .build(),
            wallet_runtime_watch_active: meter
                .u64_histogram("rpp.runtime.wallet.runtime.active")
                .with_description("Samples indicating whether the wallet runtime loop is active")
                .with_unit("1")
                .build(),
            wallet_sync_driver_active: meter
                .u64_histogram("rpp.runtime.wallet.sync.active")
                .with_description("Samples indicating whether the wallet sync driver is active")
                .with_unit("1")
                .build(),
            rpc_request_latency: RpcHistogram::new(
                meter
                    .f64_histogram("rpp.runtime.rpc.request.latency")
                    .with_description("Latency of RPC handlers in milliseconds")
                    .with_unit("ms")
                    .build(),
            ),
            rpc_request_total: RpcCounter::new(
                meter
                    .u64_counter("rpp.runtime.rpc.request.total")
                    .with_description("Total RPC handler invocations grouped by method and result")
                    .with_unit("1")
                    .build(),
            ),
            wal_flush_duration: EnumF64Histogram::new(
                meter
                    .f64_histogram("rpp.runtime.storage.wal_flush.duration")
                    .with_description("Duration of WAL flush operations in milliseconds")
                    .with_unit("ms")
                    .build(),
            ),
            wal_flush_bytes: EnumU64Histogram::new(
                meter
                    .u64_histogram("rpp.runtime.storage.wal_flush.bytes")
                    .with_description("Size of flushed WAL batches in bytes")
                    .with_unit("By")
                    .build(),
            ),
            wal_flush_total: EnumCounter::new(
                meter
                    .u64_counter("rpp.runtime.storage.wal_flush.total")
                    .with_description("Count of WAL flush attempts grouped by outcome")
                    .with_unit("1")
                    .build(),
            ),
            header_flush_duration: meter
                .f64_histogram("rpp.runtime.storage.header_flush.duration")
                .with_description("Duration of header flush operations in milliseconds")
                .with_unit("ms")
                .build(),
            header_flush_bytes: meter
                .u64_histogram("rpp.runtime.storage.header_flush.bytes")
                .with_description("Size of flushed headers in bytes")
                .with_unit("By")
                .build(),
            header_flush_total: meter
                .u64_counter("rpp.runtime.storage.header_flush.total")
                .with_description("Total number of header flush operations")
                .with_unit("1")
                .build(),
            consensus_round_duration: meter
                .f64_histogram("rpp.runtime.consensus.round.duration")
                .with_description("Duration of consensus rounds in milliseconds")
                .with_unit("ms")
                .build(),
            consensus_quorum_latency: meter
                .f64_histogram("rpp.runtime.consensus.round.quorum_latency")
                .with_description(
                    "Latency between round start and quorum formation in milliseconds",
                )
                .with_unit("ms")
                .build(),
            consensus_vrf_verification_time: meter
                .f64_histogram("consensus_vrf_verification_time_ms")
                .with_description(
                    "VRF verification duration for consensus certificates in milliseconds",
                )
                .with_unit("ms")
                .build(),
            consensus_vrf_verifications_total: meter
                .u64_counter("consensus_vrf_verifications_total")
                .with_description("Total VRF verification attempts grouped by result")
                .with_unit("1")
                .build(),
            consensus_quorum_verifications_total: meter
                .u64_counter("consensus_quorum_verifications_total")
                .with_description("Consensus quorum verification attempts grouped by result")
                .with_unit("1")
                .build(),
            consensus_leader_changes: meter
                .u64_counter("rpp.runtime.consensus.round.leader_changes")
                .with_description("Total leader changes observed by the runtime")
                .with_unit("1")
                .build(),
            consensus_witness_events: meter
                .u64_counter("rpp.runtime.consensus.witness.events")
                .with_description("Total witness gossip events emitted by the runtime")
                .with_unit("1")
                .build(),
            consensus_slashing_events: meter
                .u64_counter("rpp.runtime.consensus.slashing.events")
                .with_description("Total slashing events applied by the runtime")
                .with_unit("1")
                .build(),
            consensus_failed_votes: meter
                .u64_counter("rpp.runtime.consensus.failed_votes")
                .with_description("Total failed consensus vote registrations")
                .with_unit("1")
                .build(),
            chain_block_height: meter
                .u64_histogram("rpp.runtime.chain.block_height")
                .with_description("Observed blockchain heights on the local node")
                .with_unit("1")
                .build(),
            network_peer_counts: meter
                .u64_histogram("rpp.runtime.network.peer_count")
                .with_description("Number of connected peers observed by the runtime")
                .with_unit("1")
                .build(),
            reputation_penalties: meter
                .u64_counter("rpp.runtime.reputation.penalties")
                .with_description("Total reputation penalties applied by the runtime")
                .with_unit("1")
                .build(),
            state_sync_stream_starts: meter
                .u64_counter("rpp.runtime.state_sync.stream.starts")
                .with_description("Total number of state sync session streams started")
                .with_unit("1")
                .build(),
            state_sync_stream_chunks: meter
                .u64_counter("rpp.runtime.state_sync.stream.chunks")
                .with_description("Total number of state sync snapshot chunks streamed")
                .with_unit("1")
                .build(),
            state_sync_stream_backpressure: meter
                .u64_counter("rpp.runtime.state_sync.stream.backpressure")
                .with_description(
                    "Number of times clients waited for state sync chunk stream capacity",
                )
                .with_unit("1")
                .build(),
            state_sync_active_streams: meter
                .u64_histogram("rpp.runtime.state_sync.stream.active")
                .with_description("Active state sync stream count sampled on lifecycle changes")
                .with_unit("1")
                .build(),
        }
    }

    /// Construct a new metrics handle from the provided meter.
    ///
    /// This helper primarily exists to support integration tests that need to
    /// attach `RuntimeMetrics` to custom in-memory exporters.
    pub fn from_meter_for_testing(meter: &Meter) -> Self {
        Self::from_meter(meter)
    }

    pub fn proofs(&self) -> &ProofMetrics {
        &self.proofs
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

    /// Record a wallet action result for in-memory and OTLP consumers.
    pub fn record_wallet_action(&self, action: WalletAction, outcome: WalletActionResult) {
        self.wallet_action_total.add(action, outcome, 1);
    }

    /// Record the latency of wallet fee estimation requests.
    pub fn record_wallet_fee_estimate_latency(&self, duration: Duration) {
        self.wallet_fee_estimate_latency
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &[]);
    }

    /// Record the duration of a wallet prover job grouped by backend and result.
    pub fn record_wallet_prover_job_duration(
        &self,
        backend: &str,
        proof_generated: bool,
        duration: Duration,
    ) {
        let attributes = [
            KeyValue::new("backend", backend.to_string()),
            KeyValue::new("proof_generated", proof_generated),
        ];
        self.wallet_prover_job_duration
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    /// Record the time taken to schedule a wallet rescan along with its outcome.
    pub fn record_wallet_rescan_duration(&self, scheduled: bool, duration: Duration) {
        let attributes = [KeyValue::new("scheduled", scheduled)];
        self.wallet_rescan_duration
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    /// Increment the wallet broadcast rejection counter grouped by reason.
    pub fn record_wallet_broadcast_rejected(&self, reason: &str) {
        let attributes = [KeyValue::new("reason", reason.to_string())];
        self.wallet_broadcast_rejected.add(1, &attributes);
    }

    /// Record that the wallet runtime loop has started processing events.
    pub fn record_wallet_runtime_watch_started(&self) {
        self.wallet_runtime_watch_active.record(1, &[]);
    }

    /// Record that the wallet runtime loop has stopped processing events.
    pub fn record_wallet_runtime_watch_stopped(&self) {
        self.wallet_runtime_watch_active.record(0, &[]);
    }

    /// Record that the wallet sync driver became active.
    pub fn record_wallet_sync_driver_started(&self) {
        self.wallet_sync_driver_active.record(1, &[]);
    }

    /// Record that the wallet sync driver has stopped.
    pub fn record_wallet_sync_driver_stopped(&self) {
        self.wallet_sync_driver_active.record(0, &[]);
    }

    /// Record the latency and result of an RPC handler invocation.
    pub fn record_rpc_request(&self, method: RpcMethod, result: RpcResult, duration: Duration) {
        self.rpc_request_latency
            .record_duration(method, result, duration);
        self.rpc_request_total.add(method, result, 1);
    }

    /// Record the duration of a WAL flush attempt.
    pub fn record_wal_flush_duration(&self, outcome: WalFlushOutcome, duration: Duration) {
        self.wal_flush_duration.record_duration(outcome, duration);
    }

    /// Record the number of bytes flushed to the WAL for the provided outcome.
    pub fn record_wal_flush_bytes(&self, outcome: WalFlushOutcome, bytes: u64) {
        self.wal_flush_bytes.record(outcome, bytes);
    }

    /// Increment the WAL flush counter for the provided outcome.
    pub fn increment_wal_flushes(&self, outcome: WalFlushOutcome) {
        self.wal_flush_total.add(outcome, 1);
    }

    /// Record the duration of a header flush attempt.
    pub fn record_header_flush_duration(&self, duration: Duration) {
        self.header_flush_duration
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &[]);
    }

    /// Record the size of a flushed header.
    pub fn record_header_flush_bytes(&self, bytes: u64) {
        self.header_flush_bytes.record(bytes, &[]);
    }

    /// Increment the header flush counter.
    pub fn increment_header_flushes(&self) {
        self.header_flush_total.add(1, &[]);
    }

    /// Record the time it took to generate a proof for the given kind.
    pub fn record_proof_generation_duration(&self, kind: ProofKind, duration: Duration) {
        self.proofs.record_generation_duration(kind, duration);
    }

    /// Record the resulting proof size for the provided proving backend.
    pub fn record_proof_generation_size(&self, kind: ProofKind, bytes: u64) {
        self.proofs.record_generation_size(kind, bytes);
    }

    /// Increment the proof generation counter without emitting duration/size data.
    pub fn increment_proof_generation(&self, kind: ProofKind) {
        self.proofs.increment_generation(kind);
    }

    /// Record the duration of an entire consensus round.
    pub fn record_consensus_round_duration(&self, height: u64, round: u64, duration: Duration) {
        let attributes = [
            KeyValue::new("height", height as i64),
            KeyValue::new("round", round as i64),
        ];
        self.consensus_round_duration
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    /// Record the latency between round start and quorum formation.
    pub fn record_consensus_quorum_latency(&self, height: u64, round: u64, latency: Duration) {
        let attributes = [
            KeyValue::new("height", height as i64),
            KeyValue::new("round", round as i64),
        ];
        self.consensus_quorum_latency
            .record(latency.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    /// Record the outcome of verifying the VRF portion of a consensus certificate.
    pub fn record_consensus_vrf_verification_success(&self, duration: Duration) {
        let attributes = [KeyValue::new("result", "success")];
        self.consensus_vrf_verifications_total.add(1, &attributes);
        self.consensus_vrf_verification_time
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    /// Record a failed VRF verification alongside the failure reason.
    pub fn record_consensus_vrf_verification_failure(
        &self,
        duration: Duration,
        reason: &'static str,
    ) {
        let attributes = [
            KeyValue::new("result", "failure"),
            KeyValue::new("reason", reason),
        ];
        self.consensus_vrf_verifications_total.add(1, &attributes);
        self.consensus_vrf_verification_time
            .record(duration.as_secs_f64() * MILLIS_PER_SECOND, &attributes);
    }

    /// Record a successful quorum verification.
    pub fn record_consensus_quorum_verification_success(&self) {
        let attributes = [KeyValue::new("result", "success")];
        self.consensus_quorum_verifications_total
            .add(1, &attributes);
    }

    /// Record a failed quorum verification with the supplied reason label.
    pub fn record_consensus_quorum_verification_failure(&self, reason: &'static str) {
        let attributes = [
            KeyValue::new("result", "failure"),
            KeyValue::new("reason", reason),
        ];
        self.consensus_quorum_verifications_total
            .add(1, &attributes);
    }

    /// Record a leader change for the provided round.
    pub fn record_consensus_leader_change<S: Into<String>>(
        &self,
        height: u64,
        round: u64,
        leader: S,
    ) {
        let leader = leader.into();
        let attributes = [
            KeyValue::new("height", height as i64),
            KeyValue::new("round", round as i64),
            KeyValue::new("leader", leader),
        ];
        self.consensus_leader_changes.add(1, &attributes);
    }

    /// Record a consensus witness gossip event for the provided topic label.
    pub fn record_consensus_witness_event<S: Into<String>>(&self, topic: S) {
        let topic = topic.into();
        let attributes = [KeyValue::new("topic", topic)];
        self.consensus_witness_events.add(1, &attributes);
    }

    /// Record a slashing event along with its reason label.
    pub fn record_consensus_slashing_event<S: Into<String>>(&self, reason: S) {
        let reason = reason.into();
        let attributes = [KeyValue::new("reason", reason)];
        self.consensus_slashing_events.add(1, &attributes);
    }

    /// Record a failed vote event with an optional reason label.
    pub fn record_consensus_failed_vote<S: Into<String>>(&self, reason: S) {
        let reason = reason.into();
        let attributes = [KeyValue::new("reason", reason)];
        self.consensus_failed_votes.add(1, &attributes);
    }

    /// Record the latest observed block height.
    pub fn record_block_height(&self, height: u64) {
        self.chain_block_height.record(height, &[]);
    }

    /// Record the latest observed peer count on the networking layer.
    pub fn record_peer_count(&self, peers: usize) {
        self.network_peer_counts.record(peers as u64, &[]);
    }

    /// Record a reputation penalty emitted by the networking layer.
    pub fn record_reputation_penalty<S: Into<String>>(&self, label: S) {
        let label = label.into();
        let attributes = [KeyValue::new("label", label)];
        self.reputation_penalties.add(1, &attributes);
    }

    pub fn record_state_sync_stream_start(&self, active: u64) {
        self.state_sync_stream_starts.add(1, &[]);
        self.state_sync_active_streams.record(active, &[]);
    }

    pub fn record_state_sync_stream_finish(&self, active: u64) {
        self.state_sync_active_streams.record(active, &[]);
    }

    pub fn record_state_sync_chunk_served(&self) {
        self.state_sync_stream_chunks.add(1, &[]);
    }

    pub fn record_state_sync_stream_backpressure(&self) {
        self.state_sync_stream_backpressure.add(1, &[]);
    }
}

pub struct ProofMetrics {
    generation_duration: EnumF64Histogram<ProofKind>,
    generation_size: EnumU64Histogram<ProofKind>,
    generation_total: EnumCounter<ProofKind>,
    verification_duration: Histogram<f64>,
    verification_total_bytes: Histogram<u64>,
    verification_params_bytes: Histogram<u64>,
    verification_public_inputs_bytes: Histogram<u64>,
    verification_payload_bytes: Histogram<u64>,
    verification_stage_checks: Counter<u64>,
}

impl ProofMetrics {
    fn new(meter: &Meter) -> Self {
        Self {
            generation_duration: EnumF64Histogram::new(
                meter
                    .f64_histogram("rpp.runtime.proof.generation.duration")
                    .with_description("Time spent generating proving artefacts in milliseconds")
                    .with_unit("ms")
                    .build(),
            ),
            generation_size: EnumU64Histogram::new(
                meter
                    .u64_histogram("rpp.runtime.proof.generation.size")
                    .with_description("Size of generated proofs in bytes")
                    .with_unit("By")
                    .build(),
            ),
            generation_total: EnumCounter::new(
                meter
                    .u64_counter("rpp.runtime.proof.generation.count")
                    .with_description("Total number of proofs generated by the runtime")
                    .with_unit("1")
                    .build(),
            ),
            verification_duration: meter
                .f64_histogram("rpp_stark_verify_duration_seconds")
                .with_description(
                    "Duration of proof verification for the RPP-STARK backend in seconds",
                )
                .with_unit("s")
                .build(),
            verification_total_bytes: meter
                .u64_histogram("rpp_stark_proof_total_bytes")
                .with_description("Total serialized byte length observed during proof verification")
                .with_unit("By")
                .build(),
            verification_params_bytes: meter
                .u64_histogram("rpp_stark_params_bytes")
                .with_description("Parameter segment sizes emitted during proof verification")
                .with_unit("By")
                .build(),
            verification_public_inputs_bytes: meter
                .u64_histogram("rpp_stark_public_inputs_bytes")
                .with_description("Public input segment sizes emitted during proof verification")
                .with_unit("By")
                .build(),
            verification_payload_bytes: meter
                .u64_histogram("rpp_stark_payload_bytes")
                .with_description("Payload segment sizes emitted during proof verification")
                .with_unit("By")
                .build(),
            verification_stage_checks: meter
                .u64_counter("rpp_stark_stage_checks_total")
                .with_description("Verification stage outcomes observed for the RPP-STARK backend")
                .with_unit("1")
                .build(),
        }
    }

    pub fn record_generation_duration(&self, kind: ProofKind, duration: Duration) {
        self.generation_duration.record_duration(kind, duration);
        self.generation_total.add(kind, 1);
    }

    pub fn record_generation_size(&self, kind: ProofKind, bytes: u64) {
        self.generation_size.record(kind, bytes);
    }

    pub fn increment_generation(&self, kind: ProofKind) {
        self.generation_total.add(kind, 1);
    }

    pub fn observe_verification(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        duration: Duration,
    ) {
        let attributes = verification_attributes(backend, kind);
        self.verification_duration
            .record(duration.as_secs_f64(), &attributes);
    }

    pub fn observe_verification_total_bytes(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        bytes: u64,
    ) {
        let attributes = verification_attributes(backend, kind);
        self.verification_total_bytes.record(bytes, &attributes);
    }

    pub fn observe_verification_params_bytes(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        bytes: u64,
    ) {
        let attributes = verification_attributes(backend, kind);
        self.verification_params_bytes.record(bytes, &attributes);
    }

    pub fn observe_verification_public_inputs_bytes(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        bytes: u64,
    ) {
        let attributes = verification_attributes(backend, kind);
        self.verification_public_inputs_bytes
            .record(bytes, &attributes);
    }

    pub fn observe_verification_payload_bytes(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        bytes: u64,
    ) {
        let attributes = verification_attributes(backend, kind);
        self.verification_payload_bytes.record(bytes, &attributes);
    }

    pub fn observe_verification_stage(
        &self,
        backend: ProofVerificationBackend,
        kind: ProofVerificationKind,
        stage: ProofVerificationStage,
        outcome: ProofVerificationOutcome,
    ) {
        let attributes = [
            KeyValue::new(ProofVerificationBackend::KEY, backend.as_str()),
            KeyValue::new(ProofVerificationKind::KEY, kind.as_str()),
            KeyValue::new(ProofVerificationStage::KEY, stage.as_str()),
            KeyValue::new(ProofVerificationOutcome::KEY, outcome.as_str()),
        ];
        self.verification_stage_checks.add(1, &attributes);
    }
}

fn verification_attributes(
    backend: ProofVerificationBackend,
    kind: ProofVerificationKind,
) -> [KeyValue; 2] {
    [
        KeyValue::new(ProofVerificationBackend::KEY, backend.as_str()),
        KeyValue::new(ProofVerificationKind::KEY, kind.as_str()),
    ]
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

    /// Flush any pending metric data and shutdown the provider, restoring the noop provider.
    pub fn flush_and_shutdown(&mut self) {
        if let Some(provider) = self.provider.take() {
            if let Err(err) = provider.force_flush() {
                warn!(
                    target: "telemetry",
                    "failed to flush OTLP metrics provider: {err}"
                );
            }
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

impl Drop for RuntimeMetricsGuard {
    fn drop(&mut self) {
        self.flush_and_shutdown();
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
    /// Runtime level liveness probes emitted internally.
    RuntimeStatus,
    /// JSON-RPC: `get_balance`.
    JsonGetBalance,
    /// JSON-RPC: `list_utxos`.
    JsonListUtxos,
    /// JSON-RPC: `list_txs`.
    JsonListTransactions,
    /// JSON-RPC: `derive_address`.
    JsonDeriveAddress,
    /// JSON-RPC: `create_tx`.
    JsonCreateTransaction,
    /// JSON-RPC: `sign_tx`.
    JsonSignTransaction,
    /// JSON-RPC: `hw.enumerate`.
    JsonHwEnumerate,
    /// JSON-RPC: `hw.sign`.
    JsonHwSign,
    /// JSON-RPC: `backup.export`.
    JsonBackupExport,
    /// JSON-RPC: `backup.validate`.
    JsonBackupValidate,
    /// JSON-RPC: `backup.import`.
    JsonBackupImport,
    /// JSON-RPC: `watch_only.status`.
    JsonWatchOnlyStatus,
    /// JSON-RPC: `watch_only.enable`.
    JsonWatchOnlyEnable,
    /// JSON-RPC: `watch_only.disable`.
    JsonWatchOnlyDisable,
    /// JSON-RPC: `multisig.get_scope`.
    JsonMultisigGetScope,
    /// JSON-RPC: `multisig.set_scope`.
    JsonMultisigSetScope,
    /// JSON-RPC: `multisig.get_cosigners`.
    JsonMultisigGetCosigners,
    /// JSON-RPC: `multisig.set_cosigners`.
    JsonMultisigSetCosigners,
    /// JSON-RPC: `multisig.export`.
    JsonMultisigExport,
    /// JSON-RPC: `broadcast`.
    JsonBroadcast,
    /// JSON-RPC: `policy_preview`.
    JsonPolicyPreview,
    /// JSON-RPC: `get_policy`.
    JsonGetPolicy,
    /// JSON-RPC: `set_policy`.
    JsonSetPolicy,
    /// JSON-RPC: `estimate_fee`.
    JsonEstimateFee,
    /// JSON-RPC: `list_pending_locks`.
    JsonListPendingLocks,
    /// JSON-RPC: `release_pending_locks`.
    JsonReleasePendingLocks,
    /// JSON-RPC: `sync_status`.
    JsonSyncStatus,
    /// JSON-RPC: `rescan`.
    JsonRescan,
    /// JSON-RPC: `zsi_prove`.
    #[cfg(feature = "wallet_zsi")]
    JsonZsiProve,
    /// JSON-RPC: `zsi_verify`.
    #[cfg(feature = "wallet_zsi")]
    JsonZsiVerify,
    /// JSON-RPC: `zsi_bind_account`.
    #[cfg(feature = "wallet_zsi")]
    JsonZsiBindAccount,
    /// JSON-RPC: `zsi_list`.
    #[cfg(feature = "wallet_zsi")]
    JsonZsiList,
    /// JSON-RPC: `zsi_delete`.
    #[cfg(feature = "wallet_zsi")]
    JsonZsiDelete,
    /// REST: `/wallet/state/root`.
    StateRoot,
    /// REST: `/wallet/ui/history`.
    UiHistory,
    /// REST: `/wallet/ui/send/preview`.
    UiSendPreview,
    /// REST: `/wallet/ui/receive`.
    UiReceive,
    /// REST: `/wallet/ui/node`.
    UiNode,
    /// REST: `/wallet/account`.
    Account,
    /// REST: `/wallet/balance/:address`.
    Balance,
    /// REST: `/wallet/reputation/:address`.
    Reputation,
    /// REST: `/wallet/tier/:address`.
    Tier,
    /// REST: `/wallet/history`.
    History,
    /// REST: `/wallet/send/preview`.
    SendPreview,
    /// REST: `/wallet/tx/build`.
    BuildTransaction,
    /// REST: `/wallet/tx/sign`.
    SignTransaction,
    /// REST: `/wallet/tx/prove`.
    ProveTransaction,
    /// REST: `/wallet/tx/submit`.
    SubmitTransaction,
    /// REST: `/wallet/receive`.
    ReceiveAddresses,
    /// REST: `/wallet/node`.
    NodeView,
    /// REST: `/wallet/uptime/scheduler`.
    UptimeSchedulerStatus,
    /// REST: `/wallet/uptime/scheduler/trigger`.
    UptimeSchedulerTrigger,
    /// REST: `/wallet/uptime/scheduler/offload`.
    UptimeSchedulerOffload,
    /// REST: `/wallet/uptime/proof`.
    UptimeProofGenerate,
    /// REST: `/wallet/uptime/submit`.
    UptimeSubmit,
    /// REST: `/wallet/pipeline/dashboard`.
    PipelineDashboard,
    /// REST: `/wallet/pipeline/telemetry`.
    PipelineTelemetry,
    /// REST: `/wallet/pipeline/stream`.
    PipelineStream,
    /// REST: `/wallet/pipeline/wait`.
    PipelineWait,
    /// REST: `/wallet/pipeline/shutdown`.
    PipelineShutdown,
    /// Any wallet RPC that does not match a known endpoint.
    Unknown,
}

impl MetricLabel for WalletRpcMethod {
    const KEY: &'static str = "method";

    fn as_str(&self) -> &'static str {
        match self {
            Self::RuntimeStatus => "runtime_status",
            Self::JsonGetBalance => "json_get_balance",
            Self::JsonListUtxos => "json_list_utxos",
            Self::JsonListTransactions => "json_list_transactions",
            Self::JsonDeriveAddress => "json_derive_address",
            Self::JsonCreateTransaction => "json_create_transaction",
            Self::JsonSignTransaction => "json_sign_transaction",
            Self::JsonHwEnumerate => "json_hw_enumerate",
            Self::JsonHwSign => "json_hw_sign",
            Self::JsonBackupExport => "json_backup_export",
            Self::JsonBackupValidate => "json_backup_validate",
            Self::JsonBackupImport => "json_backup_import",
            Self::JsonWatchOnlyStatus => "json_watch_only_status",
            Self::JsonWatchOnlyEnable => "json_watch_only_enable",
            Self::JsonWatchOnlyDisable => "json_watch_only_disable",
            Self::JsonMultisigGetScope => "json_multisig_get_scope",
            Self::JsonMultisigSetScope => "json_multisig_set_scope",
            Self::JsonMultisigGetCosigners => "json_multisig_get_cosigners",
            Self::JsonMultisigSetCosigners => "json_multisig_set_cosigners",
            Self::JsonMultisigExport => "json_multisig_export",
            Self::JsonBroadcast => "json_broadcast",
            Self::JsonPolicyPreview => "json_policy_preview",
            Self::JsonGetPolicy => "json_get_policy",
            Self::JsonSetPolicy => "json_set_policy",
            Self::JsonEstimateFee => "json_estimate_fee",
            Self::JsonListPendingLocks => "json_list_pending_locks",
            Self::JsonReleasePendingLocks => "json_release_pending_locks",
            Self::JsonSyncStatus => "json_sync_status",
            Self::JsonRescan => "json_rescan",
            #[cfg(feature = "wallet_zsi")]
            Self::JsonZsiProve => "json_zsi_prove",
            #[cfg(feature = "wallet_zsi")]
            Self::JsonZsiVerify => "json_zsi_verify",
            #[cfg(feature = "wallet_zsi")]
            Self::JsonZsiBindAccount => "json_zsi_bind_account",
            #[cfg(feature = "wallet_zsi")]
            Self::JsonZsiList => "json_zsi_list",
            #[cfg(feature = "wallet_zsi")]
            Self::JsonZsiDelete => "json_zsi_delete",
            Self::StateRoot => "state_root",
            Self::UiHistory => "ui_history",
            Self::UiSendPreview => "ui_send_preview",
            Self::UiReceive => "ui_receive",
            Self::UiNode => "ui_node",
            Self::Account => "account",
            Self::Balance => "balance",
            Self::Reputation => "reputation",
            Self::Tier => "tier",
            Self::History => "history",
            Self::SendPreview => "send_preview",
            Self::BuildTransaction => "build_transaction",
            Self::SignTransaction => "sign_transaction",
            Self::ProveTransaction => "prove_transaction",
            Self::SubmitTransaction => "submit_transaction",
            Self::ReceiveAddresses => "receive_addresses",
            Self::NodeView => "node_view",
            Self::UptimeSchedulerStatus => "uptime_scheduler_status",
            Self::UptimeSchedulerTrigger => "uptime_scheduler_trigger",
            Self::UptimeSchedulerOffload => "uptime_scheduler_offload",
            Self::UptimeProofGenerate => "uptime_proof_generate",
            Self::UptimeSubmit => "uptime_submit",
            Self::PipelineDashboard => "pipeline_dashboard",
            Self::PipelineTelemetry => "pipeline_telemetry",
            Self::PipelineStream => "pipeline_stream",
            Self::PipelineWait => "pipeline_wait",
            Self::PipelineShutdown => "pipeline_shutdown",
            Self::Unknown => "unknown",
        }
    }
}

/// Wallet actions instrumented for telemetry counters.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum WalletAction {
    BackupExport,
    BackupValidate,
    BackupImport,
    WatchOnlyStatus,
    WatchOnlyEnable,
    WatchOnlyDisable,
    MultisigGetScope,
    MultisigSetScope,
    MultisigGetCosigners,
    MultisigSetCosigners,
    MultisigExport,
    #[cfg(feature = "wallet_zsi")]
    ZsiProve,
    #[cfg(feature = "wallet_zsi")]
    ZsiVerify,
    #[cfg(feature = "wallet_zsi")]
    ZsiBindAccount,
    #[cfg(feature = "wallet_zsi")]
    ZsiList,
    #[cfg(feature = "wallet_zsi")]
    ZsiDelete,
    HwEnumerate,
    HwSign,
}

impl MetricLabel for WalletAction {
    const KEY: &'static str = "action";

    fn as_str(&self) -> &'static str {
        match self {
            Self::BackupExport => "backup.export",
            Self::BackupValidate => "backup.validate",
            Self::BackupImport => "backup.import",
            Self::WatchOnlyStatus => "watch_only.status",
            Self::WatchOnlyEnable => "watch_only.enable",
            Self::WatchOnlyDisable => "watch_only.disable",
            Self::MultisigGetScope => "multisig.get_scope",
            Self::MultisigSetScope => "multisig.set_scope",
            Self::MultisigGetCosigners => "multisig.get_cosigners",
            Self::MultisigSetCosigners => "multisig.set_cosigners",
            Self::MultisigExport => "multisig.export",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiProve => "zsi.prove",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiVerify => "zsi.verify",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiBindAccount => "zsi.bind_account",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiList => "zsi.list",
            #[cfg(feature = "wallet_zsi")]
            Self::ZsiDelete => "zsi.delete",
            Self::HwEnumerate => "hw.enumerate",
            Self::HwSign => "hw.sign",
        }
    }
}

/// Result label emitted alongside [`WalletAction`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum WalletActionResult {
    Success,
    Error,
}

impl MetricLabel for WalletActionResult {
    const KEY: &'static str = "outcome";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "ok",
            Self::Error => "err",
        }
    }
}

/// RPC handlers grouped by logical subsystem.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum RpcMethod {
    /// Wallet-centric RPC handlers.
    Wallet(WalletRpcMethod),
    /// Proof related RPC handlers.
    Proof(ProofRpcMethod),
    /// Any other handler that is not explicitly categorised.
    Other,
}

impl MetricLabel for RpcMethod {
    const KEY: &'static str = "method";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Wallet(method) => method.as_str(),
            Self::Proof(method) => method.as_str(),
            Self::Other => "other",
        }
    }
}

/// Aggregated outcomes for RPC invocations.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum RpcResult {
    Success,
    ClientError,
    ServerError,
}

impl RpcResult {
    pub fn from_status(status: StatusCode) -> Self {
        if status.is_success() {
            Self::Success
        } else if status.is_client_error() {
            Self::ClientError
        } else {
            Self::ServerError
        }
    }

    pub const fn from_error() -> Self {
        Self::ServerError
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ClientError => "client_error",
            Self::ServerError => "server_error",
        }
    }
}

impl MetricLabel for RpcResult {
    const KEY: &'static str = "result";

    fn as_str(&self) -> &'static str {
        self.as_str()
    }
}

/// Proof specific RPC handlers.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofRpcMethod {
    /// Block proof retrieval endpoints.
    Block,
    /// Validator proof inspection endpoints.
    Validator,
    /// Wallet initiated proof operations.
    Wallet,
}

impl MetricLabel for ProofRpcMethod {
    const KEY: &'static str = "method";

    fn as_str(&self) -> &'static str {
        match self {
            Self::Block => "block_proof",
            Self::Validator => "validator_proof",
            Self::Wallet => "wallet_proof",
        }
    }
}

impl StorageMetricsFacade for RuntimeMetrics {
    fn record_header_flush_duration(&self, duration: Duration) {
        RuntimeMetrics::record_header_flush_duration(self, duration);
    }

    fn record_header_flush_bytes(&self, bytes: u64) {
        RuntimeMetrics::record_header_flush_bytes(self, bytes);
    }

    fn increment_header_flushes(&self) {
        RuntimeMetrics::increment_header_flushes(self);
    }

    fn record_wal_flush_duration(&self, outcome: StorageWalFlushOutcome, duration: Duration) {
        let outcome = WalFlushOutcome::from(outcome);
        RuntimeMetrics::record_wal_flush_duration(self, outcome, duration);
    }

    fn record_wal_flush_bytes(&self, outcome: StorageWalFlushOutcome, bytes: u64) {
        let outcome = WalFlushOutcome::from(outcome);
        RuntimeMetrics::record_wal_flush_bytes(self, outcome, bytes);
    }

    fn increment_wal_flushes(&self, outcome: StorageWalFlushOutcome) {
        let outcome = WalFlushOutcome::from(outcome);
        RuntimeMetrics::increment_wal_flushes(self, outcome);
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

impl From<StorageWalFlushOutcome> for WalFlushOutcome {
    fn from(value: StorageWalFlushOutcome) -> Self {
        match value {
            StorageWalFlushOutcome::Success => WalFlushOutcome::Success,
            StorageWalFlushOutcome::Retried => WalFlushOutcome::Retried,
            StorageWalFlushOutcome::Failed => WalFlushOutcome::Failed,
        }
    }
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
    /// Production Plonky3 proving backend.
    Plonky3,
    /// Deterministic mock backend for tests.
    Mock,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofVerificationBackend {
    RppStark,
}

impl ProofVerificationBackend {
    pub const KEY: &'static str = "proof_backend";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RppStark => "rpp-stark",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofVerificationKind {
    Transaction,
    State,
    Pruning,
    Consensus,
    Recursive,
}

impl ProofVerificationKind {
    pub const KEY: &'static str = "proof_kind";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transaction => "transaction",
            Self::State => "state",
            Self::Pruning => "pruning",
            Self::Consensus => "consensus",
            Self::Recursive => "recursive",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofVerificationStage {
    Params,
    Public,
    Merkle,
    Fri,
    Composition,
}

impl ProofVerificationStage {
    pub const KEY: &'static str = "stage";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Params => "params",
            Self::Public => "public",
            Self::Merkle => "merkle",
            Self::Fri => "fri",
            Self::Composition => "composition",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProofVerificationOutcome {
    Ok,
    Fail,
}

impl ProofVerificationOutcome {
    pub const KEY: &'static str = "result";

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Fail => "fail",
        }
    }

    pub const fn from_bool(ok: bool) -> Self {
        if ok {
            Self::Ok
        } else {
            Self::Fail
        }
    }
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

#[derive(Clone)]
struct RpcHistogram<M: MetricLabel, R: MetricLabel> {
    histogram: Histogram<f64>,
    _marker: PhantomData<(M, R)>,
}

impl<M: MetricLabel, R: MetricLabel> RpcHistogram<M, R> {
    fn new(histogram: Histogram<f64>) -> Self {
        Self {
            histogram,
            _marker: PhantomData,
        }
    }

    fn record_duration(&self, method: M, result: R, duration: Duration) {
        self.record(method, result, duration.as_secs_f64() * MILLIS_PER_SECOND);
    }

    fn record(&self, method: M, result: R, value: f64) {
        let attributes = [
            KeyValue::new(M::KEY, method.as_str()),
            KeyValue::new(R::KEY, result.as_str()),
        ];
        self.histogram.record(value, &attributes);
    }
}

#[derive(Clone)]
struct RpcCounter<M: MetricLabel, R: MetricLabel> {
    counter: Counter<u64>,
    _marker: PhantomData<(M, R)>,
}

impl<M: MetricLabel, R: MetricLabel> RpcCounter<M, R> {
    fn new(counter: Counter<u64>) -> Self {
        Self {
            counter,
            _marker: PhantomData,
        }
    }

    fn add(&self, method: M, result: R, value: u64) {
        let attributes = [
            KeyValue::new(M::KEY, method.as_str()),
            KeyValue::new(R::KEY, result.as_str()),
        ];
        self.counter.add(value, &attributes);
    }
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
    use std::collections::{HashMap, HashSet};
    use std::sync::{Mutex, OnceLock};

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
        metrics.record_rpc_request(
            RpcMethod::Wallet(WalletRpcMethod::RuntimeStatus),
            RpcResult::Success,
            Duration::from_millis(25),
        );
        metrics.record_wallet_fee_estimate_latency(Duration::from_millis(21));
        metrics.record_wallet_prover_job_duration("mock", true, Duration::from_millis(22));
        metrics.record_wallet_rescan_duration(true, Duration::from_millis(23));
        metrics.record_wallet_broadcast_rejected("NODE_REJECTED");
        metrics.record_wal_flush_duration(WalFlushOutcome::Success, Duration::from_millis(30));
        metrics.record_wal_flush_bytes(WalFlushOutcome::Success, 512);
        metrics.increment_wal_flushes(WalFlushOutcome::Success);
        metrics.record_header_flush_duration(Duration::from_millis(12));
        metrics.record_header_flush_bytes(256);
        metrics.increment_header_flushes();
        metrics.record_proof_generation_duration(ProofKind::Stwo, Duration::from_millis(40));
        metrics.record_proof_generation_size(ProofKind::Stwo, 1024);
        metrics.increment_proof_generation(ProofKind::Mock);
        metrics.record_consensus_round_duration(1, 2, Duration::from_millis(50));
        metrics.record_consensus_quorum_latency(1, 2, Duration::from_millis(15));
        metrics.record_consensus_leader_change(1, 2, "leader");
        metrics.record_consensus_witness_event("blocks");
        metrics.record_consensus_slashing_event("invalid_vote");
        metrics.record_consensus_failed_vote("timeout");
        metrics.record_block_height(42);
        metrics.record_peer_count(8);
        metrics.record_reputation_penalty("invalid_proof");
        metrics.proofs().observe_verification(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            Duration::from_millis(5),
        );
        metrics.proofs().observe_verification_total_bytes(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            2048,
        );
        metrics.proofs().observe_verification_params_bytes(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            256,
        );
        metrics.proofs().observe_verification_public_inputs_bytes(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            512,
        );
        metrics.proofs().observe_verification_payload_bytes(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            1280,
        );
        metrics.proofs().observe_verification_stage(
            ProofVerificationBackend::RppStark,
            ProofVerificationKind::Transaction,
            ProofVerificationStage::Fri,
            ProofVerificationOutcome::Ok,
        );

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
            seen.get("rpp.runtime.wallet.fee.estimate.latency_ms"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.prover.job.duration_ms"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.scan.rescan.duration_ms"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.wallet.broadcast.rejected"),
            Some(&"1".to_string())
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
        assert_eq!(
            seen.get("rpp_stark_verify_duration_seconds"),
            Some(&"s".to_string())
        );
        assert_eq!(
            seen.get("rpp_stark_proof_total_bytes"),
            Some(&"By".to_string())
        );
        assert_eq!(seen.get("rpp_stark_params_bytes"), Some(&"By".to_string()));
        assert_eq!(
            seen.get("rpp_stark_public_inputs_bytes"),
            Some(&"By".to_string())
        );
        assert_eq!(seen.get("rpp_stark_payload_bytes"), Some(&"By".to_string()));
        assert_eq!(
            seen.get("rpp_stark_stage_checks_total"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.round.duration"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.round.quorum_latency"),
            Some(&"ms".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.round.leader_changes"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.witness.events"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.slashing.events"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.consensus.failed_votes"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.chain.block_height"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.network.peer_count"),
            Some(&"1".to_string())
        );
        assert_eq!(
            seen.get("rpp.runtime.reputation.penalties"),
            Some(&"1".to_string())
        );

        Ok(())
    }

    #[test]
    fn runtime_metrics_provide_storage_handle() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("runtime-storage-handle-test");
        let metrics = Arc::new(RuntimeMetrics::from_meter(&meter));

        let handle: firewood_storage::StorageMetricsHandle = metrics.clone();
        handle.increment_header_flushes();
        handle.record_header_flush_duration(Duration::from_millis(3));
        handle.record_header_flush_bytes(256);
        handle.increment_wal_flushes(StorageWalFlushOutcome::Success);
        handle.record_wal_flush_duration(StorageWalFlushOutcome::Success, Duration::from_millis(7));
        handle.record_wal_flush_bytes(StorageWalFlushOutcome::Success, 1024);

        provider.force_flush()?;
        let exported = exporter.get_finished_metrics()?;

        let mut seen = HashSet::new();
        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    seen.insert(metric.name.clone());
                }
            }
        }

        assert!(seen.contains("rpp.runtime.storage.header_flush.total"));
        assert!(seen.contains("rpp.runtime.storage.wal_flush.total"));
        assert!(seen.contains("rpp.runtime.storage.wal_flush.duration"));

        Ok(())
    }

    #[test]
    fn metrics_missing_endpoint_emits_warning() {
        struct TestLogger {
            records: Mutex<Vec<String>>,
        }

        impl TestLogger {
            fn new() -> Self {
                Self {
                    records: Mutex::new(Vec::new()),
                }
            }

            fn clear(&self) {
                self.records.lock().expect("logger mutex").clear();
            }

            fn take(&self) -> Vec<String> {
                self.records
                    .lock()
                    .expect("logger mutex")
                    .drain(..)
                    .collect()
            }
        }

        impl log::Log for TestLogger {
            fn enabled(&self, metadata: &log::Metadata) -> bool {
                metadata.level() <= log::Level::Warn
            }

            fn log(&self, record: &log::Record) {
                if self.enabled(record.metadata()) {
                    self.records
                        .lock()
                        .expect("logger mutex")
                        .push(format!("{}", record.args()));
                }
            }

            fn flush(&self) {}
        }

        fn ensure_logger() -> &'static TestLogger {
            static LOGGER: OnceLock<&'static TestLogger> = OnceLock::new();
            LOGGER.get_or_init(|| {
                let logger = Box::leak(Box::new(TestLogger::new()));
                if log::set_logger(logger).is_ok() {
                    log::set_max_level(log::LevelFilter::Warn);
                }
                logger
            })
        }

        let logger = ensure_logger();
        logger.clear();

        let mut config = TelemetryConfig::default();
        config.enabled = true;
        config.warn_on_drop = true;

        let resource = Resource::new(Vec::new());
        let (_metrics, mut guard) =
            init_runtime_metrics(&config, resource).expect("init metrics without exporter");
        guard.flush_and_shutdown();

        let warnings = logger.take();
        assert!(
            warnings
                .iter()
                .any(|entry| entry.contains("telemetry metrics exporter disabled")),
            "expected warning about missing OTLP/HTTP endpoint, got {warnings:?}"
        );
    }
}
