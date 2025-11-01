//! High-level orchestrator connecting the runtime node with wallet workflows and
//! gossip interfaces.
//!
//! [`PipelineOrchestrator`] supervises asynchronous tasks that bridge the
//! consensus engine, mempool, and external clients. It is responsible for
//! coordinating transaction submission, gossip fan-out, and system health
//! monitoring. Channels created here have bounded capacity to prevent unbounded
//! backpressure on gossip ingress, and all spawned tasks are tracked so they can
//! be cancelled during shutdown via [`NodeHandle`].
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hex;
use serde_json;
use tokio::sync::{broadcast, mpsc, watch, Mutex};
use tokio::time;
use tracing::field::display;
use tracing::Instrument;
use tracing::{debug, info, info_span, warn, Span};

use crate::errors::{ChainError, ChainResult};
use crate::node::{NodeHandle, PipelineObservation};
use crate::reputation::Tier;
use crate::runtime::node_runtime::{node::MetaTelemetryReport, NodeEvent, NodeHandle as P2pHandle};
use crate::types::{Address, Block, TransactionProofBundle};
use crate::wallet::workflows::TransactionWorkflow;
use rpp_p2p::GossipTopic;

/// Default buffer size for the gossip → mempool proof channel.
const DEFAULT_QUEUE_DEPTH: usize = 64;

/// Enumeration of lifecycle stages the orchestrator tracks for each submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PipelineStage {
    /// Proof bundle accepted from the wallet/gossip surface.
    GossipReceived,
    /// Transaction surfaced in the node mempool.
    MempoolAccepted,
    /// The local node acted as VRF leader for the block containing the transaction.
    LeaderElected,
    /// Malachite BFT finalised the block that applies the transaction.
    BftFinalised,
    /// Firewood persisted the state commitment and pruning proof for the block.
    FirewoodCommitted,
    /// Ledger rewards and nonce updates materialised for the originating wallet.
    RewardsDistributed,
}

impl PipelineStage {
    pub fn as_str(&self) -> &'static str {
        match self {
            PipelineStage::GossipReceived => "gossip_received",
            PipelineStage::MempoolAccepted => "mempool_accepted",
            PipelineStage::LeaderElected => "leader_elected",
            PipelineStage::BftFinalised => "bft_finalised",
            PipelineStage::FirewoodCommitted => "firewood_committed",
            PipelineStage::RewardsDistributed => "rewards_distributed",
        }
    }
}

/// Snapshot of the tracked metrics for a single pipeline item.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FlowSnapshot {
    pub hash: String,
    pub origin: Address,
    pub target_nonce: u64,
    pub expected_balance: u128,
    pub stages: HashMap<PipelineStage, u128>,
    pub commit_height: Option<u64>,
}

/// Aggregated dashboard view used by the API/UI to display orchestrator progress.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct PipelineDashboardSnapshot {
    pub flows: Vec<FlowSnapshot>,
}

impl PipelineDashboardSnapshot {
    pub fn is_stage_complete(&self, hash: &str, stage: PipelineStage) -> bool {
        self.flows
            .iter()
            .find(|flow| flow.hash == hash)
            .and_then(|flow| flow.stages.get(&stage))
            .is_some()
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PipelineError {
    pub stage: &'static str,
    pub reason: &'static str,
    pub height: u64,
    pub round: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<String>,
    pub message: String,
    pub observed_at_ms: u128,
}

impl PipelineError {
    fn new(
        stage: &'static str,
        reason: &'static str,
        height: u64,
        round: u64,
        block_hash: Option<String>,
        message: String,
    ) -> Self {
        let observed_at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        Self {
            stage,
            reason,
            height,
            round,
            block_hash,
            message,
            observed_at_ms,
        }
    }
}

#[derive(Clone)]
struct PipelineSubmission {
    workflow: TransactionWorkflow,
    bundle: TransactionProofBundle,
    received_at: Instant,
}

#[derive(Clone)]
struct FlowMetrics {
    origin: Address,
    start: Instant,
    target_nonce: u64,
    expected_balance: u128,
    stage_times: HashMap<PipelineStage, Instant>,
    commit_height: Option<u64>,
}

impl FlowMetrics {
    fn new(origin: Address, target_nonce: u64, expected_balance: u128, start: Instant) -> Self {
        Self {
            origin,
            start,
            target_nonce,
            expected_balance,
            stage_times: HashMap::new(),
            commit_height: None,
        }
    }

    fn record_stage(&mut self, stage: PipelineStage, at: Instant) -> bool {
        use std::collections::hash_map::Entry;

        match self.stage_times.entry(stage) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(at);
                true
            }
        }
    }

    fn set_commit_height(&mut self, height: u64) {
        self.commit_height = Some(height);
    }

    fn latency_ms(&self, stage: PipelineStage) -> Option<u128> {
        self.stage_times
            .get(&stage)
            .map(|instant| instant.duration_since(self.start).as_millis())
    }

    fn to_snapshot(&self, hash: String) -> FlowSnapshot {
        let mut stages = HashMap::new();
        for stage in [
            PipelineStage::GossipReceived,
            PipelineStage::MempoolAccepted,
            PipelineStage::LeaderElected,
            PipelineStage::BftFinalised,
            PipelineStage::FirewoodCommitted,
            PipelineStage::RewardsDistributed,
        ] {
            if let Some(latency) = self.latency_ms(stage) {
                stages.insert(stage, latency);
            }
        }
        FlowSnapshot {
            hash,
            origin: self.origin.clone(),
            target_nonce: self.target_nonce,
            expected_balance: self.expected_balance,
            stages,
            commit_height: self.commit_height,
        }
    }
}

fn pipeline_task_span(task: &'static str) -> Span {
    info_span!("runtime.pipeline.task", task)
}

fn pipeline_wallet_span(method: &'static str, wallet: &Address, hash: &str) -> Span {
    info_span!(
        "runtime.wallet.rpc",
        method,
        wallet = %wallet,
        tx_hash = %hash
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::Registry;

    #[derive(Clone, Default)]
    struct RecordingLayer {
        spans: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingLayer {
        fn names(&self) -> Vec<String> {
            self.spans.lock().expect("record spans").clone()
        }
    }

    impl<S> Layer<S> for RecordingLayer
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::Id,
            _ctx: Context<'_, S>,
        ) {
            self.spans
                .lock()
                .expect("record span name")
                .push(attrs.metadata().name().to_string());
        }
    }

    #[test]
    fn pipeline_wallet_span_emits_runtime_span() {
        let recorder = RecordingLayer::default();
        let subscriber = Registry::default().with(recorder.clone());
        tracing::subscriber::with_default(subscriber, || {
            let wallet: Address = "pipeline-wallet".into();
            let span = pipeline_wallet_span("submit", &wallet, "hash");
            let _guard = span.enter();
            info!("pipeline wallet span");
        });
        assert!(recorder
            .names()
            .iter()
            .any(|name| name == "runtime.wallet.rpc"));
    }
}

struct PipelineMetrics {
    flows: Mutex<HashMap<String, FlowMetrics>>,
    dashboard: watch::Sender<PipelineDashboardSnapshot>,
    gossip_success: AtomicU64,
    gossip_failure: AtomicU64,
    gossip_failure_reasons: Mutex<HashMap<&'static str, u64>>,
    error_counts: Mutex<HashMap<&'static str, HashMap<&'static str, u64>>>,
    leader_observations: AtomicU64,
}

impl PipelineMetrics {
    fn new() -> Self {
        let (tx, _rx) = watch::channel(PipelineDashboardSnapshot::default());
        Self {
            flows: Mutex::new(HashMap::new()),
            dashboard: tx,
            gossip_success: AtomicU64::new(0),
            gossip_failure: AtomicU64::new(0),
            gossip_failure_reasons: Mutex::new(HashMap::new()),
            error_counts: Mutex::new(HashMap::new()),
            leader_observations: AtomicU64::new(0),
        }
    }

    async fn register(&self, hash: String, metrics: FlowMetrics) {
        let active = {
            let mut flows = self.flows.lock().await;
            flows.insert(hash.clone(), metrics);
            flows.len()
        };
        metrics::gauge!(METRIC_PIPELINE_ACTIVE_FLOWS, active as f64);
        self.publish().await;
    }

    async fn record_stage(&self, hash: &str, stage: PipelineStage, at: Instant) {
        let (latency, first_recorded) = {
            let mut flows = self.flows.lock().await;
            let mut latency = None;
            let mut newly_recorded = false;
            if let Some(flow) = flows.get_mut(hash) {
                newly_recorded = flow.record_stage(stage, at);
                latency = flow
                    .latency_ms(stage)
                    .map(|value| value.min(u128::from(u64::MAX)) as u64);
            }
            (latency, newly_recorded)
        };
        if let Some(latency) = latency {
            metrics::histogram!(
                METRIC_PIPELINE_STAGE_LATENCY,
                latency as f64,
                "stage" => stage.as_str(),
            );
        }
        self.publish().await;
    }

    async fn record_commit_height(&self, hash: &str, height: u64) {
        let mut flows = self.flows.lock().await;
        if let Some(flow) = flows.get_mut(hash) {
            flow.set_commit_height(height);
        }
        drop(flows);
        self.publish().await;
    }

    async fn publish(&self) {
        let flows = self.flows.lock().await;
        let snapshot = PipelineDashboardSnapshot {
            flows: flows
                .iter()
                .map(|(hash, metrics)| metrics.to_snapshot(hash.clone()))
                .collect(),
        };
        let _ = self.dashboard.send(snapshot);
    }

    fn subscribe(&self) -> watch::Receiver<PipelineDashboardSnapshot> {
        self.dashboard.subscribe()
    }

    async fn hashes(&self) -> Vec<String> {
        self.flows.lock().await.keys().cloned().collect::<Vec<_>>()
    }

    fn record_gossip_success(&self) {
        self.gossip_success.fetch_add(1, Ordering::Relaxed);
        metrics::counter!(METRIC_PIPELINE_GOSSIP_EVENTS, 1, "outcome" => "success");
    }

    async fn record_gossip_failure(&self, reason: &'static str) {
        self.gossip_failure.fetch_add(1, Ordering::Relaxed);
        {
            let mut reasons = self.gossip_failure_reasons.lock().await;
            *reasons.entry(reason).or_insert(0) += 1;
        }
        metrics::counter!(
            METRIC_PIPELINE_GOSSIP_EVENTS,
            1,
            "outcome" => "failure",
            "reason" => reason,
        );
    }

    async fn record_error(&self, stage: &'static str, reason: &'static str) {
        let mut errors = self.error_counts.lock().await;
        let stage_entry = errors.entry(stage).or_insert_with(HashMap::new);
        *stage_entry.entry(reason).or_insert(0) += 1;
        metrics::counter!(
            METRIC_PIPELINE_ERRORS,
            1,
            "stage" => stage,
            "reason" => reason,
        );
    }

    fn record_leader_observation(&self) {
        self.leader_observations.fetch_add(1, Ordering::Relaxed);
        metrics::counter!(METRIC_PIPELINE_LEADER_ROTATIONS, 1, "source" => "pipeline");
    }

    async fn telemetry_summary(&self) -> PipelineTelemetrySummary {
        let flows = self.flows.lock().await;
        let active = flows.len();
        let mut stage_samples: HashMap<PipelineStage, Vec<u64>> = HashMap::new();
        for metrics in flows.values() {
            for stage in PIPELINE_STAGES {
                if let Some(latency) = metrics.latency_ms(stage) {
                    let value = latency.min(u128::from(u64::MAX)) as u64;
                    stage_samples.entry(stage).or_default().push(value);
                }
            }
        }
        drop(flows);

        let mut stage_latency_ms = HashMap::new();
        for (stage, mut samples) in stage_samples {
            if samples.is_empty() {
                continue;
            }
            samples.sort_unstable();
            let count = samples.len() as u64;
            let total: u128 = samples.iter().map(|value| u128::from(*value)).sum();
            let average = if count == 0 {
                0.0
            } else {
                total as f64 / count as f64
            };
            let max = samples.last().copied();
            let p95 = if count == 0 {
                None
            } else {
                let index = ((count as f64 * 0.95).ceil() as usize).saturating_sub(1);
                samples.get(index.min(samples.len() - 1)).copied()
            };
            stage_latency_ms.insert(
                stage,
                PipelineStageLatencySummary {
                    count,
                    average_ms: average,
                    p95_ms: p95.map(|value| value as f64),
                    max_ms: max,
                },
            );
        }

        let gossip_failure_reasons = {
            let reasons = self.gossip_failure_reasons.lock().await;
            reasons
                .iter()
                .map(|(reason, count)| (reason.to_string(), *count))
                .collect()
        };
        let errors = {
            let error_counts = self.error_counts.lock().await;
            error_counts
                .iter()
                .map(|(stage, reasons)| {
                    let inner = reasons
                        .iter()
                        .map(|(reason, count)| (reason.to_string(), *count))
                        .collect();
                    (stage.to_string(), inner)
                })
                .collect()
        };

        PipelineTelemetrySummary {
            active_flows: active,
            stage_latency_ms,
            gossip: PipelineGossipTelemetry {
                success_total: self.gossip_success.load(Ordering::Relaxed),
                failure_total: self.gossip_failure.load(Ordering::Relaxed),
                failure_reasons: gossip_failure_reasons,
            },
            errors,
            leader_observations: self.leader_observations.load(Ordering::Relaxed),
        }
    }
}

const PIPELINE_STAGES: [PipelineStage; 6] = [
    PipelineStage::GossipReceived,
    PipelineStage::MempoolAccepted,
    PipelineStage::LeaderElected,
    PipelineStage::BftFinalised,
    PipelineStage::FirewoodCommitted,
    PipelineStage::RewardsDistributed,
];

const METRIC_PIPELINE_STAGE_LATENCY: &str = "pipeline_stage_latency_ms";
const METRIC_PIPELINE_GOSSIP_EVENTS: &str = "pipeline_gossip_events_total";
const METRIC_PIPELINE_ERRORS: &str = "pipeline_errors_total";
const METRIC_PIPELINE_LEADER_ROTATIONS: &str = "pipeline_leader_rotations_total";
const METRIC_PIPELINE_ACTIVE_FLOWS: &str = "pipeline_active_flows";
const METRIC_PIPELINE_SUBMISSIONS: &str = "pipeline_submissions_total";

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct PipelineStageLatencySummary {
    pub count: u64,
    pub average_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p95_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct PipelineGossipTelemetry {
    pub success_total: u64,
    pub failure_total: u64,
    pub failure_reasons: HashMap<String, u64>,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct PipelineTelemetrySummary {
    pub active_flows: usize,
    pub stage_latency_ms: HashMap<PipelineStage, PipelineStageLatencySummary>,
    pub gossip: PipelineGossipTelemetry,
    pub errors: HashMap<String, HashMap<String, u64>>,
    pub leader_observations: u64,
}

/// Public handle to the orchestrator allowing pipeline submissions and telemetry queries.
#[derive(Clone)]
pub struct PipelineOrchestrator {
    node: NodeHandle,
    p2p: Option<P2pHandle>,
    metrics: Arc<PipelineMetrics>,
    submissions: mpsc::Sender<PipelineSubmission>,
    submissions_rx: Arc<Mutex<Option<mpsc::Receiver<PipelineSubmission>>>>,
    shutdown: watch::Sender<bool>,
    errors: broadcast::Sender<PipelineError>,
}

impl PipelineOrchestrator {
    /// Construct an orchestrator that drives the end-to-end pipeline for the provided node.
    pub fn new(node: NodeHandle, p2p: Option<P2pHandle>) -> (Self, watch::Receiver<bool>) {
        let (tx, rx) = mpsc::channel(DEFAULT_QUEUE_DEPTH);
        let metrics = Arc::new(PipelineMetrics::new());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (error_tx, _error_rx) = broadcast::channel(DEFAULT_QUEUE_DEPTH);
        (
            Self {
                node,
                p2p,
                metrics,
                submissions: tx,
                submissions_rx: Arc::new(Mutex::new(Some(rx))),
                shutdown: shutdown_tx,
                errors: error_tx,
            },
            shutdown_rx,
        )
    }

    pub fn subscribe_errors(&self) -> broadcast::Receiver<PipelineError> {
        self.errors.subscribe()
    }

    /// Spawn the orchestrator loops driving ingestion, observation, and telemetry publishing.
    pub fn spawn(&self, shutdown_rx: watch::Receiver<bool>) {
        let node = self.node.clone();
        let metrics = self.metrics.clone();
        let ingest_shutdown = shutdown_rx.clone();
        let submissions_rx = self.submissions_rx.clone();
        let ingest_span = pipeline_task_span("ingest");
        tokio::spawn(
            async move {
                let receiver = submissions_rx
                    .lock()
                    .await
                    .take()
                    .expect("pipeline orchestrator already running");
                PipelineOrchestrator::ingest_loop(node, metrics, receiver, ingest_shutdown).await;
            }
            .instrument(ingest_span),
        );

        let observe_node = self.node.clone();
        let observe_metrics = self.metrics.clone();
        let observe_shutdown = shutdown_rx.clone();
        let observe_errors = self.errors.clone();
        let observe_span = pipeline_task_span("observe");
        tokio::spawn(
            async move {
                PipelineOrchestrator::observe_loop(
                    observe_node,
                    observe_metrics,
                    observe_shutdown,
                    observe_errors,
                )
                .await;
            }
            .instrument(observe_span),
        );

        if let Some(handle) = self.p2p.clone() {
            let gossip_metrics = self.metrics.clone();
            let gossip_shutdown = shutdown_rx;
            let gossip_span = pipeline_task_span("gossip");
            tokio::spawn(
                async move {
                    let events = handle.subscribe();
                    PipelineOrchestrator::gossip_loop(gossip_metrics, events, gossip_shutdown)
                        .await;
                }
                .instrument(gossip_span),
            );
        }
    }

    /// Returns the latest P2P meta telemetry snapshot as observed by the node runtime.
    pub async fn meta_telemetry_snapshot(&self) -> ChainResult<MetaTelemetryReport> {
        self.node.meta_telemetry_snapshot().await
    }

    /// Submit a transaction workflow into the orchestrated pipeline.
    #[instrument(
        name = "pipeline.submit_transaction",
        skip(self, workflow),
        fields(hash = tracing::field::Empty, origin = tracing::field::Empty),
        err
    )]
    pub async fn submit_transaction(&self, workflow: TransactionWorkflow) -> ChainResult<String> {
        if workflow.policy.required_tier < Tier::Tl1 {
            metrics::counter!(
                METRIC_PIPELINE_SUBMISSIONS,
                1,
                "result" => "rejected",
                "reason" => "tier_requirement",
            );
            return Err(ChainError::Transaction(
                "transaction workflow does not meet TL1 submission requirements".into(),
            ));
        }
        let sender = workflow.preview.from.clone();
        Span::current().record("origin", &display(&sender));
        let account = self
            .node
            .get_account(sender.as_str())?
            .ok_or_else(|| ChainError::Transaction("origin account missing from ledger".into()))?;
        if account.reputation.tier < workflow.policy.required_tier {
            metrics::counter!(
                METRIC_PIPELINE_SUBMISSIONS,
                1,
                "result" => "rejected",
                "reason" => "account_tier",
            );
            return Err(ChainError::Transaction(
                "account tier insufficient for orchestrated submission".into(),
            ));
        }
        let bundle = workflow.bundle.clone();
        let hash = bundle.hash();
        Span::current().record("hash", &display(&hash));
        let wallet_span = pipeline_wallet_span("submit_transaction", &sender, &hash);
        let _wallet_guard = wallet_span.enter();
        let expected_balance = workflow
            .sender_post_utxos
            .iter()
            .map(|utxo| utxo.value)
            .sum();
        let metrics = FlowMetrics::new(
            sender.clone(),
            workflow.nonce,
            expected_balance,
            Instant::now(),
        );
        self.metrics.register(hash.clone(), metrics).await;
        if let Some(handle) = &self.p2p {
            let payload = serde_json::to_vec(&bundle).map_err(|err| {
                metrics::counter!(
                    METRIC_PIPELINE_SUBMISSIONS,
                    1,
                    "result" => "rejected",
                    "reason" => "gossip_encode",
                );
                ChainError::Config(format!(
                    "failed to serialise proofs bundle for {hash}: {err}"
                ))
            })?;
            handle
                .publish_gossip(GossipTopic::WitnessProofs, payload)
                .await
                .map_err(|err| {
                    metrics::counter!(
                        METRIC_PIPELINE_SUBMISSIONS,
                        1,
                        "result" => "rejected",
                        "reason" => "gossip_publish",
                    );
                    ChainError::Config(format!("failed to publish proofs gossip for {hash}: {err}"))
                })?;
        }
        let submission = PipelineSubmission {
            workflow,
            bundle,
            received_at: Instant::now(),
        };
        self.submissions
            .send(submission)
            .await
            .map_err(|_| ChainError::Config("pipeline submission channel closed".into()))?;
        metrics::counter!(
            METRIC_PIPELINE_SUBMISSIONS,
            1,
            "result" => "accepted",
        );
        Ok(hash)
    }

    /// Subscribe to dashboard snapshots for observability dashboards.
    pub fn subscribe_dashboard(&self) -> watch::Receiver<PipelineDashboardSnapshot> {
        self.metrics.subscribe()
    }

    /// Summarise pipeline telemetry for monitoring endpoints.
    pub async fn telemetry_summary(&self) -> PipelineTelemetrySummary {
        self.metrics.telemetry_summary().await
    }

    /// Await a specific stage for the given transaction hash.
    pub async fn wait_for_stage(
        &self,
        hash: &str,
        stage: PipelineStage,
        timeout: Duration,
    ) -> ChainResult<()> {
        let mut receiver = self.metrics.subscribe();
        let deadline = Instant::now() + timeout;
        loop {
            if receiver
                .has_changed()
                .map_err(|_| ChainError::Config("pipeline dashboard closed".into()))?
            {
                let snapshot = receiver.borrow().clone();
                if snapshot.is_stage_complete(hash, stage) {
                    return Ok(());
                }
            }
            if Instant::now() > deadline {
                break;
            }
            receiver
                .changed()
                .await
                .map_err(|_| ChainError::Config("pipeline dashboard closed".into()))?;
            let snapshot = receiver.borrow().clone();
            if snapshot.is_stage_complete(hash, stage) {
                return Ok(());
            }
            if Instant::now() > deadline {
                break;
            }
        }
        Err(ChainError::Config(format!(
            "stage {:?} not reached for {hash}",
            stage
        )))
    }

    /// Stop the orchestrator loops.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    /// Publish a pipeline error to all subscribers.
    ///
    /// This helper is primarily intended for integration tests that need to
    /// deterministically drive the pipeline error feed without spinning up the
    /// full validator stack.
    pub async fn publish_error_for_testing(&self, error: PipelineError) {
        self.metrics.record_error(error.stage, error.reason).await;
        let _ = self.errors.send(error);
    }

    #[cfg(test)]
    pub(crate) async fn seed_flow_for_testing(
        &self,
        hash: String,
        origin: Address,
        target_nonce: u64,
        expected_balance: u128,
        started_at: Instant,
    ) {
        let metrics = FlowMetrics::new(origin, target_nonce, expected_balance, started_at);
        self.metrics.register(hash, metrics).await;
    }

    #[cfg(test)]
    pub(crate) async fn record_stage_for_testing(
        &self,
        hash: &str,
        stage: PipelineStage,
        at: Instant,
    ) {
        self.metrics.record_stage(hash, stage, at).await;
    }

    #[cfg(test)]
    pub(crate) async fn record_error_for_testing(&self, stage: &'static str, reason: &'static str) {
        self.metrics.record_error(stage, reason).await;
    }

    #[cfg(test)]
    pub(crate) async fn record_gossip_failure_for_testing(&self, reason: &'static str) {
        self.metrics.record_gossip_failure(reason).await;
    }

    #[cfg(test)]
    pub(crate) fn record_gossip_success_for_testing(&self) {
        self.metrics.record_gossip_success();
    }

    #[cfg(test)]
    pub(crate) fn record_leader_observation_for_testing(&self) {
        self.metrics.record_leader_observation();
    }

    #[instrument(
        name = "pipeline.ingest_loop",
        skip(node, metrics, submissions_rx, shutdown_rx)
    )]
    async fn ingest_loop(
        node: NodeHandle,
        metrics: Arc<PipelineMetrics>,
        mut submissions_rx: mpsc::Receiver<PipelineSubmission>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!("pipeline ingest loop shutting down");
                        break;
                    }
                }
                maybe_submission = submissions_rx.recv() => {
                    let Some(submission) = maybe_submission else {
                        break;
                    };
                    let hash = submission.bundle.hash();
                    metrics
                        .record_stage(&hash, PipelineStage::GossipReceived, submission.received_at)
                        .await;
                    match node.submit_transaction(submission.bundle.clone()) {
                        Ok(_) => {
                            info!(?hash, "transaction enqueued into node mempool");
                        }
                        Err(err) => {
                            warn!(?hash, ?err, "failed to submit transaction to mempool");
                            metrics.record_error("ingest", "submit_failed").await;
                            continue;
                        }
                    }
                }
            }
        }
    }

    #[instrument(
        name = "pipeline.observe_loop",
        skip(node, metrics, shutdown_rx, errors)
    )]
    async fn observe_loop(
        node: NodeHandle,
        metrics: Arc<PipelineMetrics>,
        mut shutdown_rx: watch::Receiver<bool>,
        errors: broadcast::Sender<PipelineError>,
    ) {
        let mut consensus_events = node.subscribe_pipeline();
        let mut vrf_observations: HashMap<(u64, u64), Instant> = HashMap::new();
        let mut block_flow_index: HashMap<String, Vec<String>> = HashMap::new();
        let mut processed_blocks: HashSet<String> = HashSet::new();
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!("pipeline observation loop shutting down");
                        break;
                    }
                }
                event = consensus_events.recv() => {
                    match event {
                        Ok(PipelineObservation::VrfLeadership { height, round, .. }) => {
                            metrics.record_leader_observation();
                            vrf_observations.insert((height, round), Instant::now());
                        }
                        Ok(PipelineObservation::BftFinalised { height, round, block_hash, .. }) => {
                            if processed_blocks.contains(&block_hash) {
                                continue;
                            }
                            let now = Instant::now();
                            match node.get_block(height) {
                                Ok(Some(block)) => {
                                    if block.hash != block_hash {
                                        let message = format!(
                                            "block hash mismatch for finalised block: expected {} got {}",
                                            block_hash,
                                            block.hash
                                        );
                                        metrics
                                            .record_error("bft_finalised", "hash_mismatch")
                                            .await;
                                        let _ = errors.send(PipelineError::new(
                                            "bft_finalised",
                                            "hash_mismatch",
                                            height,
                                            round,
                                            Some(block_hash.clone()),
                                            message,
                                        ));
                                        continue;
                                    }
                                    match PipelineOrchestrator::handle_block(&node, &metrics, &block).await {
                                        Ok(tracked) => {
                                            processed_blocks.insert(block_hash.clone());
                                            if let Some(vrf_at) = vrf_observations.remove(&(height, round)) {
                                                for hash in &tracked {
                                                    metrics
                                                        .record_stage(hash, PipelineStage::LeaderElected, vrf_at)
                                                        .await;
                                                }
                                            }
                                            for hash in &tracked {
                                                metrics
                                                    .record_stage(hash, PipelineStage::BftFinalised, now)
                                                    .await;
                                            }
                                            block_flow_index.insert(block_hash.clone(), tracked);
                                        }
                                        Err(err) => {
                                            metrics
                                                .record_error("bft_finalised", "handle_block")
                                                .await;
                                            let _ = errors.send(PipelineError::new(
                                                "bft_finalised",
                                                "handle_block",
                                                height,
                                                round,
                                                Some(block_hash.clone()),
                                                format!("failed to process block: {err}"),
                                            ));
                                        }
                                    }
                                }
                                Ok(None) => {
                                    metrics
                                        .record_error("bft_finalised", "not_found")
                                        .await;
                                    let _ = errors.send(PipelineError::new(
                                        "bft_finalised",
                                        "not_found",
                                        height,
                                        round,
                                        Some(block_hash.clone()),
                                        "finalised block not found".to_string(),
                                    ));
                                }
                                Err(err) => {
                                    metrics
                                        .record_error("bft_finalised", "fetch_failed")
                                        .await;
                                    let _ = errors.send(PipelineError::new(
                                        "bft_finalised",
                                        "fetch_failed",
                                        height,
                                        round,
                                        Some(block_hash.clone()),
                                        format!("failed to fetch block: {err}"),
                                    ));
                                }
                            }
                        }
                        Ok(PipelineObservation::FirewoodCommitment { height, round, block_hash, .. }) => {
                            let now = Instant::now();
                            if let Some(tracked) = block_flow_index.remove(&block_hash) {
                                for hash in &tracked {
                                    metrics
                                        .record_stage(hash, PipelineStage::FirewoodCommitted, now)
                                        .await;
                                }
                            } else if let Ok(Some(block)) = node.get_block(height) {
                                let hashes: Vec<String> = block
                                    .transactions
                                    .iter()
                                    .map(|tx| hex::encode(tx.hash()))
                                    .collect();
                                for hash in &hashes {
                                    metrics
                                        .record_commit_height(hash, block.header.height)
                                        .await;
                                    metrics
                                        .record_stage(hash, PipelineStage::FirewoodCommitted, now)
                                        .await;
                                }
                            } else {
                                metrics
                                    .record_error("firewood_commitment", "missing_context")
                                    .await;
                                let _ = errors.send(PipelineError::new(
                                    "firewood_commitment",
                                    "missing_context",
                                    height,
                                    round,
                                    Some(block_hash.clone()),
                                    "missing transaction context for firewood stage".to_string(),
                                ));
                            }
                            processed_blocks.remove(&block_hash);
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(skipped, "lagged on consensus event stream");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            debug!("consensus event stream closed");
                            break;
                        }
                    }
                }
                _ = time::sleep(Duration::from_millis(100)) => {
                    if let Err(err) = PipelineOrchestrator::poll_mempool(&node, &metrics).await {
                        warn!(?err, "unable to poll mempool status");
                        metrics.record_error("mempool", "poll_failed").await;
                    }
                    if let Err(err) = PipelineOrchestrator::poll_rewards(&node, &metrics).await {
                        warn!(?err, "failed to evaluate reward application");
                        metrics.record_error("rewards", "poll_failed").await;
                    }
                }
            }
        }
    }

    #[instrument(name = "pipeline.poll_mempool", skip(node, metrics), err)]
    async fn poll_mempool(node: &NodeHandle, metrics: &Arc<PipelineMetrics>) -> ChainResult<()> {
        let mempool = node.mempool_status()?;
        let now = Instant::now();
        for entry in &mempool.transactions {
            metrics
                .record_stage(&entry.hash, PipelineStage::MempoolAccepted, now)
                .await;
        }
        Ok(())
    }

    #[instrument(
        name = "pipeline.handle_block",
        skip(node, metrics, block),
        fields(height = tracing::field::Empty, proposer = tracing::field::Empty),
        err
    )]
    async fn handle_block(
        node: &NodeHandle,
        metrics: &Arc<PipelineMetrics>,
        block: &Block,
    ) -> ChainResult<Vec<String>> {
        Span::current().record("height", &display(block.header.height));
        Span::current().record("proposer", &display(&block.header.proposer));
        let mut tracked_hashes = Vec::new();
        for tx in &block.transactions {
            let hash = hex::encode(tx.hash());
            metrics
                .record_commit_height(&hash, block.header.height)
                .await;
            tracked_hashes.push(hash);
        }
        let proposer = block.header.proposer.clone();
        let status = node.consensus_status()?;
        info!(
            height = block.header.height,
            %proposer,
            quorum = status.quorum_reached,
            "block finalised"
        );
        Ok(tracked_hashes)
    }

    #[instrument(name = "pipeline.poll_rewards", skip(node, metrics), err)]
    async fn poll_rewards(node: &NodeHandle, metrics: &Arc<PipelineMetrics>) -> ChainResult<()> {
        let hashes = metrics.hashes().await;
        for hash in hashes {
            let maybe_flow = {
                let flows = metrics.flows.lock().await;
                flows.get(&hash).cloned()
            };
            let Some(flow) = maybe_flow else {
                continue;
            };
            if flow
                .stage_times
                .contains_key(&PipelineStage::RewardsDistributed)
            {
                continue;
            }
            if !flow.stage_times.contains_key(&PipelineStage::BftFinalised) {
                continue;
            }
            if !flow
                .stage_times
                .contains_key(&PipelineStage::FirewoodCommitted)
            {
                continue;
            }
            let account = node
                .get_account(flow.origin.as_str())?
                .ok_or_else(|| ChainError::Config("tracked account missing".into()))?;
            if account.nonce >= flow.target_nonce && account.balance == flow.expected_balance {
                metrics
                    .record_stage(&hash, PipelineStage::RewardsDistributed, Instant::now())
                    .await;
            }
        }
        Ok(())
    }

    #[instrument(name = "pipeline.gossip_loop", skip(metrics, events, shutdown_rx))]
    async fn gossip_loop(
        metrics: Arc<PipelineMetrics>,
        mut events: broadcast::Receiver<NodeEvent>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!("pipeline gossip loop shutting down");
                        break;
                    }
                }
                event = events.recv() => {
                    match event {
                        Ok(NodeEvent::Gossip { topic, data, .. }) => {
                            if topic != GossipTopic::WitnessProofs {
                                continue;
                            }
                            match serde_json::from_slice::<TransactionProofBundle>(&data) {
                                Ok(bundle) => {
                                    metrics.record_gossip_success();
                                    let hash = bundle.hash();
                                    if metrics.hashes().await.iter().any(|tracked| tracked == &hash) {
                                        metrics
                                            .record_stage(
                                                &hash,
                                                PipelineStage::GossipReceived,
                                                Instant::now(),
                                            )
                                            .await;
                                    }
                                }
                                Err(err) => {
                                    warn!(?err, "invalid proofs gossip payload");
                                    metrics.record_gossip_failure("decode").await;
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(skipped, "lagged on gossip event stream");
                            metrics.record_gossip_failure("lagged").await;
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            debug!("p2p event stream closed");
                            break;
                        }
                    }
                }
            }
        }
    }
}

impl Drop for PipelineOrchestrator {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}
