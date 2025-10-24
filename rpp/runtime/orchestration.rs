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
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hex;
use serde_json;
use tokio::sync::{Mutex, broadcast, mpsc, watch};
use tokio::time;
use tracing::{debug, info, warn};

use crate::errors::{ChainError, ChainResult};
use crate::node::{DEFAULT_STATE_SYNC_CHUNK, NodeHandle, PipelineObservation};
use crate::reputation::Tier;
use crate::runtime::node_runtime::{NodeEvent, NodeHandle as P2pHandle, node::MetaTelemetryReport};
use crate::types::{Address, Block, TransactionProofBundle};
use crate::wallet::workflows::TransactionWorkflow;
use rpp_p2p::GossipTopic;

/// Default buffer size for the gossip → mempool proof channel.
const DEFAULT_QUEUE_DEPTH: usize = 64;
const PRUNING_SYNC_INTERVAL_SECS: u64 = 30;

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

    fn record_stage(&mut self, stage: PipelineStage, at: Instant) {
        self.stage_times.entry(stage).or_insert(at);
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

struct PipelineMetrics {
    flows: Mutex<HashMap<String, FlowMetrics>>,
    dashboard: watch::Sender<PipelineDashboardSnapshot>,
}

impl PipelineMetrics {
    fn new() -> Self {
        let (tx, _rx) = watch::channel(PipelineDashboardSnapshot::default());
        Self {
            flows: Mutex::new(HashMap::new()),
            dashboard: tx,
        }
    }

    async fn register(&self, hash: String, metrics: FlowMetrics) {
        let mut flows = self.flows.lock().await;
        flows.insert(hash.clone(), metrics);
        drop(flows);
        self.publish().await;
    }

    async fn record_stage(&self, hash: &str, stage: PipelineStage, at: Instant) {
        let mut flows = self.flows.lock().await;
        if let Some(flow) = flows.get_mut(hash) {
            flow.record_stage(stage, at);
        }
        drop(flows);
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
        tokio::spawn(async move {
            let receiver = submissions_rx
                .lock()
                .await
                .take()
                .expect("pipeline orchestrator already running");
            PipelineOrchestrator::ingest_loop(node, metrics, receiver, ingest_shutdown).await;
        });

        let observe_node = self.node.clone();
        let observe_metrics = self.metrics.clone();
        let observe_shutdown = shutdown_rx.clone();
        let observe_errors = self.errors.clone();
        tokio::spawn(async move {
            PipelineOrchestrator::observe_loop(
                observe_node,
                observe_metrics,
                observe_shutdown,
                observe_errors,
            )
            .await;
        });

        if let Some(handle) = self.p2p.clone() {
            let gossip_metrics = self.metrics.clone();
            let gossip_shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                let events = handle.subscribe();
                PipelineOrchestrator::gossip_loop(gossip_metrics, events, gossip_shutdown).await;
            });
        }

        let pruning_node = self.node.clone();
        let pruning_shutdown = shutdown_rx;
        tokio::spawn(async move {
            PipelineOrchestrator::pruning_loop(
                pruning_node,
                DEFAULT_STATE_SYNC_CHUNK,
                Duration::from_secs(PRUNING_SYNC_INTERVAL_SECS),
                pruning_shutdown,
            )
            .await;
        });
    }

    /// Returns the latest P2P meta telemetry snapshot as observed by the node runtime.
    pub async fn meta_telemetry_snapshot(&self) -> ChainResult<MetaTelemetryReport> {
        self.node.meta_telemetry_snapshot().await
    }

    /// Submit a transaction workflow into the orchestrated pipeline.
    pub async fn submit_transaction(&self, workflow: TransactionWorkflow) -> ChainResult<String> {
        if workflow.policy.required_tier < Tier::Tl1 {
            return Err(ChainError::Transaction(
                "transaction workflow does not meet TL1 submission requirements".into(),
            ));
        }
        let sender = workflow.preview.from.clone();
        let account = self
            .node
            .get_account(sender.as_str())?
            .ok_or_else(|| ChainError::Transaction("origin account missing from ledger".into()))?;
        if account.reputation.tier < workflow.policy.required_tier {
            return Err(ChainError::Transaction(
                "account tier insufficient for orchestrated submission".into(),
            ));
        }
        let bundle = workflow.bundle.clone();
        let hash = bundle.hash();
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
                ChainError::Config(format!(
                    "failed to serialise proofs bundle for {hash}: {err}"
                ))
            })?;
            handle
                .publish_gossip(GossipTopic::Proofs, payload)
                .await
                .map_err(|err| {
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
        Ok(hash)
    }

    /// Subscribe to dashboard snapshots for observability dashboards.
    pub fn subscribe_dashboard(&self) -> watch::Receiver<PipelineDashboardSnapshot> {
        self.metrics.subscribe()
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
    pub fn publish_error_for_testing(&self, error: PipelineError) {
        let _ = self.errors.send(error);
    }

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
                            continue;
                        }
                    }
                }
            }
        }
    }

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
                                        let _ = errors.send(PipelineError::new(
                                            "bft_finalised",
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
                                            let _ = errors.send(PipelineError::new(
                                                "bft_finalised",
                                                height,
                                                round,
                                                Some(block_hash.clone()),
                                                format!("failed to process block: {err}"),
                                            ));
                                        }
                                    }
                                }
                                Ok(None) => {
                                    let _ = errors.send(PipelineError::new(
                                        "bft_finalised",
                                        height,
                                        round,
                                        Some(block_hash.clone()),
                                        "finalised block not found".to_string(),
                                    ));
                                }
                                Err(err) => {
                                    let _ = errors.send(PipelineError::new(
                                        "bft_finalised",
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
                                let _ = errors.send(PipelineError::new(
                                    "firewood_commitment",
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
                    }
                    if let Err(err) = PipelineOrchestrator::poll_rewards(&node, &metrics).await {
                        warn!(?err, "failed to evaluate reward application");
                    }
                }
            }
        }
    }

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

    async fn handle_block(
        node: &NodeHandle,
        metrics: &Arc<PipelineMetrics>,
        block: &Block,
    ) -> ChainResult<Vec<String>> {
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
                            if topic != GossipTopic::Proofs {
                                continue;
                            }
                            match serde_json::from_slice::<TransactionProofBundle>(&data) {
                                Ok(bundle) => {
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
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(skipped, "lagged on gossip event stream");
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

    async fn pruning_loop(
        node: NodeHandle,
        chunk_size: usize,
        interval: Duration,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let mut ticker = time::interval(interval);
        if let Err(err) = node.run_pruning_cycle(chunk_size) {
            warn!(?err, "initial pruning cycle failed");
        }
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        debug!("pruning loop shutting down");
                        break;
                    }
                }
                _ = ticker.tick() => {
                    if let Err(err) = node.run_pruning_cycle(chunk_size) {
                        warn!(?err, "scheduled pruning cycle failed");
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
