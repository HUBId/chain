use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::errors::{ChainError, ChainResult};
use crate::node::NodeHandle;
use crate::runtime::node_runtime::node::{MetaTelemetryReport, NodeHandle as P2pHandle};
use crate::types::Address;
use tokio::sync::{broadcast, watch};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum PipelineStage {
    GossipReceived,
    MempoolAccepted,
    LeaderElected,
    BftFinalised,
    FirewoodCommitted,
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

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct FlowSnapshot {
    pub hash: String,
    pub origin: Address,
    pub target_nonce: u64,
    pub expected_balance: u128,
    pub stages: HashMap<PipelineStage, u128>,
    pub commit_height: Option<u64>,
}

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
    pub fn new(
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

#[derive(Clone)]
pub struct PipelineOrchestrator {
    node: NodeHandle,
    shutdown: watch::Sender<bool>,
    dashboard_tx: watch::Sender<PipelineDashboardSnapshot>,
    dashboard_rx: watch::Receiver<PipelineDashboardSnapshot>,
    errors: broadcast::Sender<PipelineError>,
}

impl PipelineOrchestrator {
    pub fn new(node: NodeHandle, _p2p: Option<P2pHandle>) -> (Self, watch::Receiver<bool>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (dashboard_tx, dashboard_rx) = watch::channel(PipelineDashboardSnapshot::default());
        let (errors_tx, _errors_rx) = broadcast::channel(1);
        (
            Self {
                node,
                shutdown: shutdown_tx,
                dashboard_tx,
                dashboard_rx,
                errors: errors_tx,
            },
            shutdown_rx,
        )
    }

    pub fn spawn(&self, _shutdown_rx: watch::Receiver<bool>) {}

    pub fn subscribe_errors(&self) -> broadcast::Receiver<PipelineError> {
        self.errors.subscribe()
    }

    pub fn subscribe_dashboard(&self) -> watch::Receiver<PipelineDashboardSnapshot> {
        self.dashboard_rx.clone()
    }

    pub async fn telemetry_summary(&self) -> PipelineTelemetrySummary {
        PipelineTelemetrySummary::default()
    }

    pub async fn wait_for_stage(
        &self,
        _hash: &str,
        _stage: PipelineStage,
        _timeout: Duration,
    ) -> ChainResult<()> {
        Err(ChainError::Config(
            "pipeline orchestrator unavailable without wallet integration".into(),
        ))
    }

    pub async fn meta_telemetry_snapshot(&self) -> ChainResult<MetaTelemetryReport> {
        self.node.meta_telemetry_snapshot().await
    }

    pub async fn submit_transaction(
        &self,
        _workflow: rpp_wallet_interface::TransactionWorkflow,
    ) -> ChainResult<String> {
        Err(ChainError::Config(
            "pipeline orchestrator unavailable without wallet integration".into(),
        ))
    }

    pub async fn publish_error_for_testing(&self, error: PipelineError) {
        let _ = self.errors.send(error);
    }
}
