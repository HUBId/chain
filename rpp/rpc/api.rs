use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::fmt;
use std::future::Future;
use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU64;
use std::path::Path;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::body::Body;
use axum::error_handling::HandleErrorLayer;
use axum::extract::connect_info::ConnectInfo;
use axum::extract::{Path, Query, Request, State};
use axum::http::header;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{BoxError, Json, Router};
use futures::future::pending;
use hex;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as HyperConnBuilder;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use tokio::fs;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch, Notify};

use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::{BroadcastStream, WatchStream};
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tower::layer::Layer;
use tower::limit::RateLimitLayer;
use tower::Service;
use tower::ServiceBuilder;
use tower::ServiceExt;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::{RequestBodyTimeoutLayer, ResponseBodyTimeoutLayer, TimeoutLayer};
use tracing::{info, warn};

use crate::consensus::SignedBftVote;
use crate::crypto::{
    generate_vrf_keypair, vrf_public_key_from_hex, vrf_public_key_to_hex, vrf_secret_key_to_hex,
    DynVrfKeyStore, VrfKeyIdentifier, VrfKeypair,
};
use crate::errors::{ChainError, ChainResult};
#[cfg(feature = "vendor_electrs")]
use crate::interfaces::WalletTrackerSnapshot;
use crate::interfaces::{
    WalletBalanceResponse, WalletHistoryResponse, WalletUiHistoryContract, WalletUiNodeContract,
    WalletUiReceiveContract, WalletUiSendContract, WALLET_UI_HISTORY_CONTRACT,
    WALLET_UI_NODE_CONTRACT, WALLET_UI_RECEIVE_CONTRACT, WALLET_UI_SEND_CONTRACT,
};
use crate::ledger::{ReputationAudit, SlashingEvent};
use crate::node::{
    BftMembership, BlockProofArtifactsView, ConsensusStatus, LightClientVerificationEvent,
    MempoolStatus, NodeHandle, NodeStatus, P2pCensorshipReport, PendingUptimeSummary,
    PruningJobStatus, RolloutStatus, UptimeSchedulerRun, UptimeSchedulerStatus,
    ValidatorConsensusTelemetry, ValidatorMempoolTelemetry, ValidatorTelemetryView, VrfStatus,
    VrfThresholdStatus, DEFAULT_STATE_SYNC_CHUNK,
};
use crate::orchestration::{
    PipelineDashboardSnapshot, PipelineError, PipelineOrchestrator, PipelineStage,
    PipelineTelemetrySummary,
};
use crate::proof_system::VerifierMetricsSnapshot;
use crate::reputation::{Tier, TimetokeParams};
use crate::rpp::TimetokeRecord;
use crate::runtime::config::{
    NetworkLimitsConfig, NetworkTlsConfig, P2pAllowlistEntry, QueueWeightsConfig,
    SecretsBackendConfig, SecretsConfig,
};
use crate::runtime::node::{StateSyncChunkError, StateSyncVerificationStatus};
use crate::runtime::node_runtime::node::{
    NodeError as P2pNodeError, NodeHandle as P2pRuntimeHandle, SnapshotSessionId,
    SnapshotStreamStatus,
};
use crate::runtime::{
    ProofRpcMethod, RpcMethod, RpcResult, RuntimeMetrics, RuntimeMode, WalletRpcMethod,
};
use crate::storage::pruner::receipt::{SnapshotRebuildReceipt, SnapshotTriggerReceipt};
use crate::sync::ReconstructionPlan;
use crate::types::{
    Account, Address, AttestedIdentityRequest, Block, SignedTransaction, Transaction,
    TransactionProofBundle, UptimeProof,
};
use crate::vrf::{PoseidonVrfInput, VrfProof, VrfSubmission};
#[cfg(feature = "vendor_electrs")]
use crate::wallet::ScriptStatusMetadata;
use crate::wallet::{
    ConsensusReceipt, HistoryEntry, NodeTabMetrics, ReceiveTabAddress, SendPreview, Wallet,
    WalletAccountSummary,
};
#[cfg(feature = "vendor_electrs")]
use crate::wallet::{TrackerState, WalletTrackerHandle};
use blake3::Hash as Blake3Hash;
use parking_lot::{Mutex, RwLock};
use rpp::node::VerificationErrorKind;
use rpp_p2p::vendor::PeerId as NetworkPeerId;
use rpp_p2p::{
    AdmissionAuditTrail, AllowlistedPeer, LightClientHead, NetworkMetaTelemetryReport,
    NetworkPeerTelemetry, NetworkStateSyncChunk, NetworkStateSyncPlan, SnapshotChunk,
};
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::server::{ClientCertVerifier, WebPkiClientVerifier};
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys};

#[path = "src/routes/mod.rs"]
mod routes;
pub use routes::p2p::{cancel_snapshot_stream, snapshot_stream_status, start_snapshot_stream};
pub use routes::state::{rebuild_snapshots, trigger_snapshot};
pub use routes::state_sync::{
    chunk_by_id as state_sync_chunk_by_id, head_stream as state_sync_head_stream,
    session_status as state_sync_session_status, SnapshotChunkJson, StateSyncChunkResponse,
    StateSyncStatusResponse,
};

#[derive(Clone, Debug, Serialize)]
pub struct LightHeadSse {
    pub height: u64,
    pub hash: String,
    pub state_root: String,
    pub proof_commitment: String,
    pub timestamp: u64,
    pub finalized: bool,
}

impl From<LightClientHead> for LightHeadSse {
    fn from(head: LightClientHead) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            height: head.height,
            hash: head.block_hash,
            state_root: head.state_root,
            proof_commitment: head.proof_commitment,
            timestamp,
            finalized: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StateSyncSessionInfo {
    pub root: Option<Blake3Hash>,
    pub total_chunks: Option<u32>,
    pub verified: bool,
    pub last_completed_step: Option<LightClientVerificationEvent>,
    pub message: Option<String>,
    pub served_chunks: Vec<u64>,
    pub progress_log: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum StateSyncErrorKind {
    MissingRuntime,
    NoActiveSession,
    BuildFailed,
    ChunkIndexOutOfRange { index: u32, total: u32 },
    ChunkNotFound { index: u32 },
    Unauthorized,
    Internal,
}

#[derive(Debug, Clone)]
pub struct StateSyncError {
    pub kind: StateSyncErrorKind,
    pub message: Option<String>,
}

impl StateSyncError {
    pub fn new(kind: StateSyncErrorKind, message: impl Into<Option<String>>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl fmt::Display for StateSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.message {
            Some(message) => write!(f, "{message}"),
            None => write!(f, "state sync error: {:?}", self.kind),
        }
    }
}

impl std::error::Error for StateSyncError {}

#[async_trait]
pub trait StateSyncApi: Send + Sync {
    fn watch_light_client_heads(
        &self,
    ) -> Result<watch::Receiver<Option<LightClientHead>>, StateSyncError>;

    fn latest_light_client_head(&self) -> Result<Option<LightClientHead>, StateSyncError>;

    fn ensure_state_sync_session(&self) -> Result<(), StateSyncError>;

    fn reset_state_sync_session(&self, root: Blake3Hash, chunk_size: usize, total_chunks: usize);

    fn state_sync_active_session(&self) -> Result<StateSyncSessionInfo, StateSyncError>;

    async fn state_sync_chunk_by_index(&self, index: u32) -> Result<SnapshotChunk, StateSyncError>;
}

#[derive(Debug)]
pub enum SnapshotStreamRuntimeError {
    Runtime(P2pNodeError),
    SessionNotFound(u64),
}

impl fmt::Display for SnapshotStreamRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(err) => write!(f, "{err}"),
            Self::SessionNotFound(session) => {
                write!(f, "snapshot session {session} not found")
            }
        }
    }
}

impl std::error::Error for SnapshotStreamRuntimeError {}

#[async_trait]
pub trait SnapshotStreamRuntime: Send + Sync {
    async fn start_snapshot_stream(
        &self,
        session: u64,
        peer: NetworkPeerId,
        root: String,
    ) -> Result<SnapshotStreamStatus, SnapshotStreamRuntimeError>;

    fn snapshot_stream_status(&self, session: u64) -> Option<SnapshotStreamStatus>;

    async fn cancel_snapshot_stream(&self, session: u64) -> Result<(), SnapshotStreamRuntimeError>;
}

#[derive(Clone)]
struct NodeSnapshotStreamRuntime {
    handle: P2pRuntimeHandle,
}

impl NodeSnapshotStreamRuntime {
    fn new(handle: P2pRuntimeHandle) -> Self {
        Self { handle }
    }
}

#[async_trait]
impl SnapshotStreamRuntime for NodeSnapshotStreamRuntime {
    async fn start_snapshot_stream(
        &self,
        session: u64,
        peer: NetworkPeerId,
        root: String,
    ) -> Result<SnapshotStreamStatus, SnapshotStreamRuntimeError> {
        let session_id = SnapshotSessionId::new(session);
        self.handle
            .start_snapshot_stream(session_id, peer, root)
            .await
            .map_err(SnapshotStreamRuntimeError::Runtime)?;
        self.snapshot_stream_status(session)
            .ok_or(SnapshotStreamRuntimeError::SessionNotFound(session))
    }

    fn snapshot_stream_status(&self, session: u64) -> Option<SnapshotStreamStatus> {
        let session_id = SnapshotSessionId::new(session);
        self.handle.snapshot_stream_status(session_id)
    }

    async fn cancel_snapshot_stream(&self, session: u64) -> Result<(), SnapshotStreamRuntimeError> {
        let session_id = SnapshotSessionId::new(session);
        self.handle
            .cancel_snapshot_stream(session_id)
            .await
            .map_err(SnapshotStreamRuntimeError::Runtime)
    }
}

pub trait PruningServiceApi: Send + Sync {
    fn rebuild_snapshots(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<SnapshotRebuildReceipt, PruningServiceError>>
                + Send
                + 'static,
        >,
    >;

    fn trigger_snapshot(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<SnapshotTriggerReceipt, PruningServiceError>>
                + Send
                + 'static,
        >,
    >;
}

#[derive(Clone, Debug)]
pub enum PruningServiceError {
    Unavailable,
    InvalidRequest(String),
    Internal(String),
}

impl fmt::Display for PruningServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PruningServiceError::Unavailable => f.write_str("pruning service unavailable"),
            PruningServiceError::InvalidRequest(message) => f.write_str(message),
            PruningServiceError::Internal(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for PruningServiceError {}

#[derive(Clone)]
pub struct ApiContext {
    mode: Arc<RwLock<RuntimeMode>>,
    node: Option<NodeHandle>,
    wallet: Option<Arc<Wallet>>,
    #[cfg(feature = "vendor_electrs")]
    tracker: Option<WalletTrackerHandle>,
    orchestrator: Option<Arc<PipelineOrchestrator>>,
    request_limit_per_minute: Option<NonZeroU64>,
    auth_token_enabled: bool,
    state_sync_api: Option<Arc<dyn StateSyncApi>>,
    pruning_service: Option<Arc<dyn PruningServiceApi>>,
    metrics: Arc<RuntimeMetrics>,
    wallet_runtime_active: bool,
    pruning_status: Option<watch::Receiver<Option<PruningJobStatus>>>,
    snapshot_runtime: Option<Arc<dyn SnapshotStreamRuntime>>,
}

impl ApiContext {
    pub fn new(
        mode: Arc<RwLock<RuntimeMode>>,
        node: Option<NodeHandle>,
        wallet: Option<Arc<Wallet>>,
        orchestrator: Option<Arc<PipelineOrchestrator>>,
        request_limit_per_minute: Option<NonZeroU64>,
        auth_token_enabled: bool,
        pruning_status: Option<watch::Receiver<Option<PruningJobStatus>>>,
        pruning_service: Option<Arc<dyn PruningServiceApi>>,
        wallet_runtime_active: bool,
    ) -> Self {
        #[cfg(feature = "vendor_electrs")]
        let tracker = wallet.as_ref().and_then(|wallet| wallet.tracker_handle());

        let state_sync_api = node
            .as_ref()
            .map(|handle| Arc::new(handle.clone()) as Arc<dyn StateSyncApi>);

        let metrics = if let Some(handle) = node.as_ref() {
            handle.runtime_metrics()
        } else if let Some(wallet) = wallet.as_ref() {
            wallet.metrics()
        } else {
            RuntimeMetrics::noop()
        };

        Self {
            mode,
            node,
            wallet,
            #[cfg(feature = "vendor_electrs")]
            tracker,
            orchestrator,
            request_limit_per_minute,
            auth_token_enabled,
            state_sync_api,
            pruning_service,
            metrics,
            wallet_runtime_active,
            pruning_status,
            snapshot_runtime: None,
        }
    }

    fn current_mode(&self) -> RuntimeMode {
        *self.mode.read()
    }

    fn wallet_node_running(&self) -> bool {
        self.wallet
            .as_ref()
            .map(|wallet| wallet.node_runtime_running())
            .unwrap_or(false)
    }

    fn wallet_node_handle(&self) -> Option<NodeHandle> {
        self.wallet
            .as_ref()
            .and_then(|wallet| wallet.node_runtime_handle())
    }

    fn node_available(&self) -> bool {
        self.node.is_some() || self.wallet_node_running()
    }

    fn wallet_available(&self) -> bool {
        self.wallet_runtime_active && self.wallet.is_some()
    }

    fn wallet_routes_enabled(&self) -> bool {
        self.wallet_runtime_active
    }

    fn node_enabled(&self) -> bool {
        self.node_available() && self.current_mode().includes_node()
    }

    fn pruning_status_stream(&self) -> Option<watch::Receiver<Option<PruningJobStatus>>> {
        self.pruning_status.as_ref().map(Clone::clone)
    }

    fn wallet_enabled(&self) -> bool {
        self.wallet_available() && self.current_mode().includes_wallet()
    }

    fn orchestrator_available(&self) -> bool {
        self.orchestrator.is_some()
    }

    fn orchestrator_enabled(&self) -> bool {
        self.orchestrator_available() && self.node_enabled()
    }

    fn node_handle(&self) -> Option<NodeHandle> {
        if let Some(handle) = self.node.clone() {
            Some(handle)
        } else {
            self.wallet_node_handle()
        }
    }

    fn wallet_handle(&self) -> Option<Arc<Wallet>> {
        self.wallet.as_ref().map(Arc::clone)
    }

    fn state_sync_api(&self) -> Option<Arc<dyn StateSyncApi>> {
        self.state_sync_api.as_ref().map(Arc::clone)
    }

    fn pruning_service(&self) -> Option<Arc<dyn PruningServiceApi>> {
        self.pruning_service.as_ref().map(Arc::clone)
    }

    fn snapshot_runtime(&self) -> Option<Arc<dyn SnapshotStreamRuntime>> {
        self.snapshot_runtime.as_ref().map(Arc::clone)
    }

    fn require_pruning_service(
        &self,
    ) -> Result<Arc<dyn PruningServiceApi>, (StatusCode, Json<ErrorResponse>)> {
        let Some(service) = self.pruning_service() else {
            return Err(pruning_service_not_configured());
        };
        if !self.current_mode().includes_node() {
            return Err(unavailable("node"));
        }
        Ok(service)
    }

    fn require_snapshot_runtime(
        &self,
    ) -> Result<Arc<dyn SnapshotStreamRuntime>, (StatusCode, Json<ErrorResponse>)> {
        if let Some(runtime) = self.snapshot_runtime() {
            return Ok(runtime);
        }
        let node = self.require_node()?;
        let handle = node.p2p_handle().ok_or_else(|| not_started("p2p"))?;
        Ok(Arc::new(NodeSnapshotStreamRuntime::new(handle)))
    }

    pub fn metrics(&self) -> Arc<RuntimeMetrics> {
        Arc::clone(&self.metrics)
    }

    fn require_state_sync_api(
        &self,
    ) -> Result<Arc<dyn StateSyncApi>, (StatusCode, Json<ErrorResponse>)> {
        let Some(api) = self.state_sync_api() else {
            return Err(not_started("node"));
        };
        if self.node_available() && !self.node_enabled() {
            return Err(unavailable("node"));
        }
        Ok(api)
    }

    pub fn with_state_sync_api(mut self, api: Arc<dyn StateSyncApi>) -> Self {
        self.state_sync_api = Some(api);
        self
    }

    pub fn with_pruning_service(mut self, service: Arc<dyn PruningServiceApi>) -> Self {
        self.pruning_service = Some(service);
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<RuntimeMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    pub fn with_snapshot_runtime(mut self, runtime: Arc<dyn SnapshotStreamRuntime>) -> Self {
        self.snapshot_runtime = Some(runtime);
        self
    }

    #[cfg(feature = "vendor_electrs")]
    fn tracker_state(&self) -> Option<TrackerState> {
        self.tracker.as_ref().map(|handle| handle.state())
    }

    fn require_node(&self) -> Result<NodeHandle, (StatusCode, Json<ErrorResponse>)> {
        if !self.node_available() {
            return Err(not_started("node"));
        }
        if !self.node_enabled() {
            return Err(unavailable("node"));
        }
        Ok(self.node_handle().expect("node handle available"))
    }

    fn require_wallet(&self) -> Result<Arc<Wallet>, (StatusCode, Json<ErrorResponse>)> {
        if !self.wallet_available() {
            return Err(not_started("wallet"));
        }
        if !self.wallet_enabled() {
            return Err(unavailable("wallet"));
        }
        Ok(self.wallet_handle().expect("wallet handle available"))
    }

    fn require_orchestrator(
        &self,
    ) -> Result<Arc<PipelineOrchestrator>, (StatusCode, Json<ErrorResponse>)> {
        if !self.orchestrator_available() {
            return Err(not_started("orchestrator"));
        }
        if !self.orchestrator_enabled() {
            return Err(unavailable("orchestrator"));
        }
        Ok(self
            .orchestrator_handle()
            .expect("orchestrator handle available"))
    }

    fn node_for_mode(&self) -> Option<NodeHandle> {
        if self.node_enabled() {
            self.node_handle()
        } else {
            None
        }
    }

    fn wallet_for_mode(&self) -> Option<Arc<Wallet>> {
        if self.wallet_enabled() {
            self.wallet_handle()
        } else {
            None
        }
    }

    fn orchestrator_handle(&self) -> Option<Arc<PipelineOrchestrator>> {
        self.orchestrator.as_ref().map(Arc::clone)
    }

    fn orchestrator_for_mode(&self) -> Option<Arc<PipelineOrchestrator>> {
        if self.orchestrator_enabled() {
            self.orchestrator_handle()
        } else {
            None
        }
    }

    fn runtime_state(&self) -> RuntimeModeResponse {
        RuntimeModeResponse {
            mode: self.current_mode(),
            node_available: self.node_available(),
            wallet_available: self.wallet_available(),
            node_enabled: self.node_enabled(),
            wallet_enabled: self.wallet_enabled(),
            orchestrator_available: self.orchestrator_available(),
            orchestrator_enabled: self.orchestrator_enabled(),
        }
    }

    fn update_mode(&self, mode: RuntimeMode) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
        if mode.includes_node() && !self.node_available() {
            return Err(not_started("node"));
        }
        if mode.includes_wallet() && !self.wallet_available() {
            return Err(not_started("wallet"));
        }
        *self.mode.write() = mode;
        Ok(())
    }

    fn request_limit_per_minute(&self) -> Option<NonZeroU64> {
        self.request_limit_per_minute
    }

    fn auth_enabled(&self) -> bool {
        self.auth_token_enabled
    }

    fn ensure_validator_tier(
        &self,
        minimum: Tier,
    ) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
        if self.auth_enabled() {
            return Ok(());
        }
        let wallet = self.require_wallet()?;
        let summary = wallet.account_summary().map_err(to_http_error)?;
        if summary.tier < minimum {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: format!(
                        "validator tier {} does not meet required tier {}",
                        summary.tier.name(),
                        minimum.name()
                    ),
                }),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct ApiSecurity {
    auth_token: Option<Arc<String>>,
    allowed_origin: Option<HeaderValue>,
}

impl ApiSecurity {
    fn new(auth_token: Option<String>, allowed_origin: Option<String>) -> ChainResult<Self> {
        let allowed_origin = match allowed_origin {
            Some(origin) => {
                let trimmed = origin.trim();
                if trimmed.is_empty() {
                    return Err(ChainError::Config(
                        "invalid rpc allowed origin: value must not be empty".into(),
                    ));
                }
                Some(HeaderValue::from_str(trimmed).map_err(|err| {
                    ChainError::Config(format!("invalid rpc allowed origin: {err}"))
                })?)
            }
            None => None,
        };
        Ok(Self {
            auth_token: auth_token.map(Arc::new),
            allowed_origin,
        })
    }

    fn auth_enabled(&self) -> bool {
        self.auth_token.is_some()
    }

    fn cors_enabled(&self) -> bool {
        self.allowed_origin.is_some()
    }
}

#[derive(Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
struct SubmitResponse {
    hash: String,
}

#[derive(Serialize)]
struct SubmitVrfProofResponse {
    status: &'static str,
}

#[derive(Serialize)]
struct UptimeResponse {
    credited_hours: u64,
}

#[derive(Debug, Deserialize)]
struct SubmitVrfInput {
    last_block_header: String,
    epoch: u64,
    tier_seed: String,
}

#[derive(Debug, Deserialize)]
struct SubmitVrfProofRequest {
    address: Address,
    public_key: Option<String>,
    input: SubmitVrfInput,
    proof: VrfProof,
    tier: Tier,
    timetoke_hours: u64,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    address: String,
    role: &'static str,
}

#[derive(Serialize, Deserialize)]
struct RuntimeModeResponse {
    mode: RuntimeMode,
    node_available: bool,
    wallet_available: bool,
    node_enabled: bool,
    wallet_enabled: bool,
    orchestrator_available: bool,
    orchestrator_enabled: bool,
}

#[derive(Serialize)]
struct ValidatorStatusResponse {
    consensus: ConsensusStatus,
    node: NodeStatus,
}

#[derive(Serialize)]
struct ValidatorProofQueueResponse {
    uptime_proofs: Vec<PendingUptimeSummary>,
    totals: ValidatorProofQueueTotals,
}

#[derive(Serialize)]
struct ValidatorProofQueueTotals {
    transactions: usize,
    identities: usize,
    votes: usize,
    uptime_proofs: usize,
}

#[derive(Serialize)]
struct ValidatorVrfResponse {
    backend: String,
    identifier: String,
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<String>,
}

#[derive(Serialize)]
struct ValidatorTelemetryResponse {
    rollout: RolloutStatus,
    node: NodeStatus,
    consensus: ValidatorConsensusTelemetry,
    mempool: ValidatorMempoolTelemetry,
    timetoke_params: TimetokeParams,
    verifier_metrics: VerifierMetricsSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pruning: Option<PruningJobStatus>,
    vrf_threshold: VrfThresholdStatus,
}

#[derive(Serialize)]
struct ValidatorPeerResponse {
    local_peer_id: String,
    peer_count: usize,
    peers: Vec<NetworkPeerTelemetry>,
}

#[derive(Deserialize)]
struct RuntimeModeUpdate {
    mode: RuntimeMode,
}

#[derive(Deserialize)]
struct SlashingQuery {
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct AuditStreamQuery {
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct TimetokeSyncRequest {
    records: Vec<TimetokeRecord>,
}

#[derive(Serialize)]
struct TimetokeSyncResponse {
    updated: Vec<Address>,
}

#[derive(Deserialize)]
struct TxComposeRequest {
    to: Address,
    amount: u128,
    fee: u64,
    memo: Option<String>,
}

#[derive(Serialize)]
struct TxComposeResponse {
    transaction: Transaction,
    preview: SendPreview,
}

#[derive(Serialize, Deserialize)]
struct SignTxRequest {
    transaction: Transaction,
}

#[derive(Serialize, Deserialize)]
struct SignTxResponse {
    signed: SignedTransaction,
}

#[derive(Deserialize)]
struct ProveTxRequest {
    signed: SignedTransaction,
}

#[derive(Serialize)]
struct ProveTxResponse {
    bundle: TransactionProofBundle,
}

#[derive(Deserialize)]
struct SubmitTxRequest {
    bundle: TransactionProofBundle,
}

#[derive(Deserialize)]
struct ReceiveQuery {
    count: Option<usize>,
}

#[derive(Serialize)]
struct ReceiveResponse {
    addresses: Vec<ReceiveTabAddress>,
}

struct WalletHistoryFragments {
    entries: Vec<HistoryEntry>,
    #[cfg(feature = "vendor_electrs")]
    script_metadata: Option<Vec<ScriptStatusMetadata>>,
    #[cfg(feature = "vendor_electrs")]
    tracker: Option<WalletTrackerSnapshot>,
}

#[derive(Serialize)]
struct WalletNodeResponse {
    metrics: NodeTabMetrics,
    consensus: Option<ConsensusReceipt>,
    pipeline: Option<PipelineDashboardSnapshot>,
}

#[derive(Serialize)]
struct UiNodeStatusResponse {
    mode: RuntimeMode,
    node: Option<NodeStatus>,
    consensus: Option<ConsensusStatus>,
    mempool: Option<MempoolStatus>,
    bft: Option<BftMembership>,
}

#[derive(Serialize)]
struct UiReputationResponse {
    mode: RuntimeMode,
    summary: Option<WalletAccountSummary>,
}

#[derive(Serialize)]
struct TierResponse {
    tier: Tier,
}

#[derive(Serialize)]
struct StateRootResponse {
    state_root: String,
}

#[derive(Serialize)]
struct WalletAccountResponse {
    summary: WalletAccountSummary,
}

#[derive(Serialize)]
struct WalletUptimeProofResponse {
    proof: UptimeProof,
}

#[derive(Serialize)]
struct BlockProofResponse {
    height: u64,
    proof: Option<BlockProofArtifactsView>,
}

#[derive(Deserialize)]
struct SnapshotPlanQuery {
    start: Option<u64>,
}

#[derive(Deserialize)]
struct StateSyncChunkQuery {
    start: u64,
}

#[derive(Deserialize)]
struct SubmitUptimeRequest {
    proof: Option<UptimeProof>,
}

#[derive(Serialize, Deserialize)]
struct PipelineWaitRequest {
    hash: String,
    stage: PipelineStage,
    timeout_ms: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct PipelineWaitResponse {
    hash: String,
    stage: PipelineStage,
    completed: bool,
}

#[derive(Serialize)]
struct PipelineShutdownResponse {
    status: &'static str,
}

#[derive(Deserialize)]
struct UpdateMempoolRequest {
    limit: Option<usize>,
    priority_weight: Option<f64>,
    fee_weight: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct UpdateAccessListsRequest {
    #[serde(default)]
    allowlist: Vec<P2pAllowlistEntry>,
    #[serde(default)]
    blocklist: Vec<String>,
}

fn apply_cors_headers(headers: &mut HeaderMap, origin: &HeaderValue) {
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin.clone());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("authorization,content-type"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET,POST,OPTIONS"),
    );
}

async fn cors_middleware(
    State(security): State<ApiSecurity>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(origin) = security.allowed_origin.clone() {
        if request.method() == Method::OPTIONS {
            let mut response = Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .expect("failed to build CORS preflight response");
            apply_cors_headers(response.headers_mut(), &origin);
            return Ok(response);
        }
        let mut response = next.run(request).await;
        apply_cors_headers(response.headers_mut(), &origin);
        Ok(response)
    } else {
        Ok(next.run(request).await)
    }
}

async fn auth_middleware(
    State(security): State<ApiSecurity>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(expected) = security.auth_token.as_ref() {
        if request.method() == Method::OPTIONS {
            return Ok(next.run(request).await);
        }
        let header_value = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let token = header_value
            .strip_prefix("Bearer ")
            .unwrap_or(header_value)
            .trim();
        if token != expected.as_str() {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }
    Ok(next.run(request).await)
}

fn classify_rpc_method(method: &Method, path: &str) -> RpcMethod {
    if method == Method::OPTIONS {
        return RpcMethod::Other;
    }

    if let Some(wallet) = wallet_rpc_method(method, path) {
        return RpcMethod::Wallet(wallet);
    }

    if let Some(proof) = proof_rpc_method(path) {
        return RpcMethod::Proof(proof);
    }

    RpcMethod::Other
}

fn wallet_rpc_method(method: &Method, path: &str) -> Option<WalletRpcMethod> {
    if !path.starts_with("/wallet/") {
        return None;
    }

    if path.starts_with("/wallet/history") || path.starts_with("/wallet/ui/history") {
        return Some(WalletRpcMethod::GetHistory);
    }

    if path.starts_with("/wallet/tx/submit")
        || path.starts_with("/wallet/tx/sign")
        || path.starts_with("/wallet/uptime/submit")
    {
        return Some(WalletRpcMethod::SubmitTransaction);
    }

    if path.starts_with("/wallet/tx/prove")
        || path.starts_with("/wallet/tx/build")
        || path.starts_with("/wallet/send/preview")
        || path.starts_with("/wallet/ui/send/preview")
        || path.starts_with("/wallet/uptime/proof")
    {
        return Some(WalletRpcMethod::BuildProof);
    }

    if method == Method::GET
        && (path.starts_with("/wallet/account")
            || path.starts_with("/wallet/balance/")
            || path.starts_with("/wallet/reputation/")
            || path.starts_with("/wallet/tier/")
            || path.starts_with("/wallet/receive")
            || path.starts_with("/wallet/ui/receive")
            || path.starts_with("/wallet/node")
            || path.starts_with("/wallet/ui/node")
            || path.starts_with("/wallet/state/root"))
    {
        return Some(WalletRpcMethod::GetBalance);
    }

    Some(WalletRpcMethod::Status)
}

fn proof_rpc_method(path: &str) -> Option<ProofRpcMethod> {
    if path.starts_with("/proofs/block/") {
        return Some(ProofRpcMethod::Block);
    }

    if path.starts_with("/validator/proofs") {
        return Some(ProofRpcMethod::Validator);
    }

    if path.starts_with("/wallet/tx/prove") {
        return Some(ProofRpcMethod::Wallet);
    }

    None
}

#[derive(Clone)]
pub struct RpcMetricsLayer {
    metrics: Arc<RuntimeMetrics>,
}

impl RpcMetricsLayer {
    pub fn new(metrics: Arc<RuntimeMetrics>) -> Self {
        Self { metrics }
    }
}

impl<S> Layer<S> for RpcMetricsLayer {
    type Service = RpcMetricsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RpcMetricsService {
            inner,
            metrics: Arc::clone(&self.metrics),
        }
    }
}

#[derive(Clone)]
struct RpcMetricsService<S> {
    inner: S,
    metrics: Arc<RuntimeMetrics>,
}

impl<S> Service<Request<Body>> for RpcMetricsService<S>
where
    S: Service<Request<Body>, Response = Response> + Send + 'static,
    S::Error: Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let start = Instant::now();
        let metrics = Arc::clone(&self.metrics);
        let rpc_method = classify_rpc_method(&method, &path);
        let fut = self.inner.call(request);

        Box::pin(async move {
            match fut.await {
                Ok(response) => {
                    let result = RpcResult::from_status(response.status());
                    metrics.record_rpc_request(rpc_method, result, start.elapsed());
                    Ok(response)
                }
                Err(err) => {
                    metrics.record_rpc_request(
                        rpc_method,
                        RpcResult::from_error(),
                        start.elapsed(),
                    );
                    Err(err)
                }
            }
        })
    }
}

fn unwrap_infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => match err {},
    }
}

#[derive(Clone)]
struct PerIpTokenBucketLayer {
    state: Arc<PerIpTokenBucketState>,
}

impl PerIpTokenBucketLayer {
    fn new(burst: u64, replenish_per_minute: u64) -> Self {
        Self {
            state: Arc::new(PerIpTokenBucketState::new(burst, replenish_per_minute)),
        }
    }
}

impl<S> Layer<S> for PerIpTokenBucketLayer {
    type Service = PerIpTokenBucketService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PerIpTokenBucketService {
            inner,
            state: self.state.clone(),
        }
    }
}

struct PerIpTokenBucketState {
    buckets: Mutex<HashMap<IpAddr, TokenBucket>>,
    burst: f64,
    replenish_per_second: f64,
}

impl PerIpTokenBucketState {
    fn new(burst: u64, replenish_per_minute: u64) -> Self {
        let replenish_per_second = replenish_per_minute as f64 / 60.0;
        Self {
            buckets: Mutex::new(HashMap::new()),
            burst: burst as f64,
            replenish_per_second,
        }
    }

    fn try_acquire(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.lock();
        let bucket = buckets.entry(ip).or_insert_with(|| TokenBucket {
            tokens: self.burst,
            last_refill: Instant::now(),
        });

        let now = Instant::now();
        let elapsed = now.saturating_duration_since(bucket.last_refill);
        if elapsed.as_secs_f64() > 0.0 {
            bucket.tokens =
                (bucket.tokens + self.replenish_per_second * elapsed.as_secs_f64()).min(self.burst);
            bucket.last_refill = now;
        }

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Clone)]
struct PerIpTokenBucketService<S> {
    inner: S,
    state: Arc<PerIpTokenBucketState>,
}

impl<S> Service<Request<Body>> for PerIpTokenBucketService<S>
where
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let remote_ip = request
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());
        let mut inner = self.inner.clone();
        let state = self.state.clone();

        Box::pin(async move {
            if let Some(ip) = remote_ip {
                if !state.try_acquire(ip) {
                    let response = Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .body(Body::from("rate limit exceeded"))
                        .unwrap();
                    return Ok(response);
                }
            }

            inner.call(request).await
        })
    }
}

pub async fn serve(
    context: ApiContext,
    addr: SocketAddr,
    auth_token: Option<String>,
    allowed_origin: Option<String>,
    limits: NetworkLimitsConfig,
    tls: NetworkTlsConfig,
) -> ChainResult<()> {
    serve_with_shutdown(
        context,
        addr,
        auth_token,
        allowed_origin,
        limits,
        tls,
        pending(),
        None,
    )
    .await
}

pub async fn serve_with_shutdown<F>(
    context: ApiContext,
    addr: SocketAddr,
    auth_token: Option<String>,
    allowed_origin: Option<String>,
    limits: NetworkLimitsConfig,
    tls: NetworkTlsConfig,
    shutdown: F,
    ready: Option<oneshot::Sender<Result<(), std::io::Error>>>,
) -> ChainResult<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let security = ApiSecurity::new(auth_token, allowed_origin)?;
    let request_limit_per_minute = context.request_limit_per_minute();
    let metrics = context.metrics();
    let enable_wallet_routes = context.wallet_routes_enabled();

    let mut router = Router::new()
        .route("/health", get(health))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/runtime/mode", get(runtime_mode).post(update_runtime_mode))
        .route("/ui/node", get(ui_node_status))
        .route("/ui/reputation", get(ui_reputation))
        .route("/ui/bft/membership", get(ui_bft_membership))
        .route("/proofs/block/:height", get(block_proofs))
        .route("/snapshots/plan", get(snapshot_plan))
        .route("/snapshots/jobs", get(snapshot_jobs))
        .route("/snapshots/rebuild", post(routes::state::rebuild_snapshots))
        .route("/snapshots/snapshot", post(routes::state::trigger_snapshot))
        .route("/state-sync/plan", get(state_sync_plan))
        .route(
            "/state-sync/session",
            get(routes::state_sync::session_status),
        )
        .route(
            "/state-sync/head/stream",
            get(routes::state_sync::head_stream),
        )
        .route("/state-sync/chunk", get(state_sync_chunk))
        .route(
            "/state-sync/chunk/:id",
            get(routes::state_sync::chunk_by_id),
        )
        .route("/validator/status", get(validator_status))
        .route("/validator/proofs", get(validator_proofs))
        .route("/validator/peers", get(validator_peers))
        .route("/validator/telemetry", get(validator_telemetry))
        .route("/validator/vrf", get(validator_vrf))
        .route("/validator/vrf/rotate", post(validator_rotate_vrf))
        .route("/validator/uptime", post(validator_submit_uptime))
        .route("/p2p/peers", get(p2p_meta_telemetry))
        .route("/p2p/censorship", get(p2p_censorship_report))
        .route(
            "/p2p/admission/policies",
            get(routes::p2p::admission_policies).post(routes::p2p::update_admission_policies),
        )
        .route(
            "/p2p/admission/audit",
            get(routes::p2p::admission_audit_log),
        )
        .route("/p2p/snapshots", post(routes::p2p::start_snapshot_stream))
        .route(
            "/p2p/snapshots/:id",
            get(routes::p2p::snapshot_stream_status).delete(routes::p2p::cancel_snapshot_stream),
        )
        .route("/p2p/access-lists", post(update_access_lists))
        .route("/status/node", get(node_status))
        .route("/status/mempool", get(mempool_status))
        .route("/control/mempool", post(update_mempool_limits))
        .route("/status/consensus", get(consensus_status))
        .route("/status/rollout", get(rollout_status))
        .route("/consensus/vrf/submit", post(submit_vrf_proof))
        .route("/consensus/vrf/threshold", get(vrf_threshold))
        .route("/consensus/vrf/:address", get(vrf_status))
        .route(
            "/consensus/proof/status",
            get(routes::consensus::proof_status),
        )
        .route("/transactions", post(submit_transaction))
        .route("/identities", post(submit_identity))
        .route("/consensus/votes", post(submit_vote))
        .route("/uptime/proofs", post(submit_uptime_proof))
        .route("/ledger/slashing", get(slashing_events))
        .route("/ledger/timetoke", get(timetoke_snapshot))
        .route("/ledger/timetoke/sync", post(sync_timetoke))
        .route("/ledger/reputation/:address", get(reputation_audit))
        .route(
            "/observability/audits/reputation",
            get(reputation_audit_stream),
        )
        .route("/observability/audits/slashing", get(slashing_audit_stream))
        .route("/blocks/latest", get(latest_block))
        .route("/blocks/:height", get(block_by_height))
        .route("/accounts/:address", get(account_info))
        .route("/wallet/state/root", get(wallet_state_root));

    if enable_wallet_routes {
        router = router
            .route("/ui/history", get(ui_history))
            .route("/ui/send/preview", post(ui_send_preview))
            .route("/ui/receive", get(ui_receive))
            .route("/wallet/ui/history", get(wallet_ui_history))
            .route("/wallet/ui/send/preview", post(wallet_ui_send_preview))
            .route("/wallet/ui/receive", get(wallet_ui_receive))
            .route("/wallet/ui/node", get(wallet_ui_node))
            .route("/wallet/account", get(wallet_account))
            .route("/wallet/balance/:address", get(wallet_balance))
            .route("/wallet/reputation/:address", get(wallet_reputation))
            .route("/wallet/tier/:address", get(wallet_tier))
            .route("/wallet/history", get(wallet_history))
            .route("/wallet/send/preview", post(wallet_send_preview))
            .route("/wallet/tx/build", post(wallet_build_transaction))
            .route("/wallet/tx/sign", post(wallet_sign_transaction))
            .route("/wallet/tx/prove", post(wallet_prove_transaction))
            .route("/wallet/tx/submit", post(wallet_submit_transaction))
            .route("/wallet/receive", get(wallet_receive_addresses))
            .route("/wallet/node", get(wallet_node_view))
            .route(
                "/wallet/uptime/scheduler",
                get(wallet_uptime_scheduler_status),
            )
            .route(
                "/wallet/uptime/scheduler/trigger",
                post(wallet_trigger_uptime_scheduler),
            )
            .route(
                "/wallet/uptime/scheduler/offload",
                post(wallet_offload_uptime_proof),
            )
            .route("/wallet/uptime/proof", post(wallet_generate_uptime))
            .route("/wallet/uptime/submit", post(wallet_submit_uptime))
            .route("/wallet/pipeline/dashboard", get(wallet_pipeline_dashboard))
            .route("/wallet/pipeline/telemetry", get(wallet_pipeline_telemetry))
            .route("/wallet/pipeline/stream", get(wallet_pipeline_stream))
            .route("/wallet/pipeline/wait", post(wallet_pipeline_wait))
            .route("/wallet/pipeline/shutdown", post(wallet_pipeline_shutdown));
    }

    if security.cors_enabled() {
        router = router.layer(middleware::from_fn_with_state(
            security.clone(),
            cors_middleware,
        ));
    }
    if security.auth_enabled() {
        router = router.layer(middleware::from_fn_with_state(
            security.clone(),
            auth_middleware,
        ));
    }
    if let Some(limit) = request_limit_per_minute {
        router = router.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(|_: BoxError| async move {
                    StatusCode::TOO_MANY_REQUESTS
                }))
                .layer(RateLimitLayer::new(limit.get(), Duration::from_secs(60))),
        );
    }

    let header_timeout = Duration::from_millis(limits.header_read_timeout_ms);
    let read_timeout = Duration::from_millis(limits.read_timeout_ms);
    let write_timeout = Duration::from_millis(limits.write_timeout_ms);
    let max_header_bytes = limits.max_header_bytes;

    let mut service_builder = ServiceBuilder::new();
    if limits.per_ip_token_bucket.enabled {
        service_builder = service_builder.layer(PerIpTokenBucketLayer::new(
            limits.per_ip_token_bucket.burst,
            limits.per_ip_token_bucket.replenish_per_minute,
        ));
    }
    service_builder = service_builder
        .layer(RequestBodyLimitLayer::new(limits.max_body_bytes))
        .layer(RequestBodyTimeoutLayer::new(read_timeout))
        .layer(ResponseBodyTimeoutLayer::new(write_timeout))
        .layer(TimeoutLayer::new(header_timeout));

    router = router.layer(service_builder);
    router = router.layer(RpcMetricsLayer::new(metrics));

    let router = router.with_state(context);
    let mut make_service = router.into_make_service_with_connect_info::<SocketAddr>();

    let tls_acceptor = build_tls_acceptor(&tls).await?;

    let mut listener = match TcpListener::bind(addr).await {
        Ok(listener) => {
            if let Some(sender) = ready {
                let _ = sender.send(Ok(()));
            }
            listener
        }
        Err(err) => {
            if let Some(sender) = ready {
                let _ = sender.send(Err(std::io::Error::new(err.kind(), err.to_string())));
            }
            return Err(ChainError::Io(err));
        }
    };

    info!(?addr, tls_enabled = tls.enabled, "RPC server listening");

    let notify = Arc::new(Notify::new());
    let mut tasks: JoinSet<()> = JoinSet::new();
    let mut shutdown = Box::pin(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            accept_result = listener.accept() => {
                let (stream, remote_addr) = match accept_result {
                    Ok(value) => value,
                    Err(err) => {
                        warn!(error = %err, "failed to accept RPC connection");
                        continue;
                    }
                };

                let tower_service = unwrap_infallible(make_service.call(remote_addr).await);
                let tls_acceptor = tls_acceptor.clone();
                let notify = notify.clone();
                tasks.spawn(async move {
                    let io = match tls_acceptor {
                        Some(acceptor) => match acceptor.accept(stream).await {
                            Ok(tls_stream) => TokioIo::new(tls_stream),
                            Err(err) => {
                                warn!(?remote_addr, error = %err, "TLS handshake failed");
                                return;
                            }
                        },
                        None => TokioIo::new(stream),
                    };

                    let hyper_service = service_fn(move |request: Request<Incoming>| {
                        let service = tower_service.clone();
                        async move { service.oneshot(request).await }
                    });

                    let mut builder = HyperConnBuilder::new(TokioExecutor::new());
                    #[cfg(feature = "http1")]
                    {
                        let http1 = builder.http1();
                        http1.timer(TokioTimer::new());
                        http1.header_read_timeout(header_timeout);
                        http1.read_timeout(read_timeout);
                        http1.write_timeout(write_timeout);
                        http1.max_header_list_size(max_header_bytes.min(u32::MAX as usize) as u32);
                    }
                    #[cfg(feature = "http2")]
                    builder.http2().enable_connect_protocol();

                    let mut conn = builder.serve_connection_with_upgrades(io, hyper_service);
                    tokio::pin!(conn);
                    let shutdown_signal = notify.notified();
                    tokio::pin!(shutdown_signal);

                    loop {
                        tokio::select! {
                            result = &mut conn => {
                                if let Err(err) = result {
                                    warn!(?remote_addr, error = %err, "RPC connection terminated with error");
                                }
                                break;
                            }
                            _ = &mut shutdown_signal => {
                                conn.as_mut().graceful_shutdown();
                            }
                        }
                    }
                });
            }
        }
    }

    notify.notify_waiters();
    while tasks.join_next().await.is_some() {}

    Ok(())
}

async fn build_tls_acceptor(config: &NetworkTlsConfig) -> ChainResult<Option<TlsAcceptor>> {
    if !config.enabled {
        return Ok(None);
    }

    let certificate_path = config
        .certificate
        .as_ref()
        .ok_or_else(|| ChainError::Config("network.tls.certificate is required".into()))?;
    let private_key_path = config
        .private_key
        .as_ref()
        .ok_or_else(|| ChainError::Config("network.tls.private_key is required".into()))?;

    let certificates = load_certificates(certificate_path).await?;
    let private_key = load_private_key(private_key_path).await?;

    let _ = aws_lc_rs::default_provider().install_default();

    let mut builder = ServerConfig::builder()
        .with_safe_default_protocol_versions()
        .map_err(|err| {
            ChainError::Config(format!("failed to configure TLS protocol versions: {err}"))
        })?;

    if let Some(ca_path) = config.client_ca.as_ref() {
        let verifier = build_client_verifier(ca_path, config.require_client_auth).await?;
        builder = builder.with_client_cert_verifier(verifier);
    } else {
        if config.require_client_auth {
            return Err(ChainError::Config(
                "network.tls.client_ca must be configured when client authentication is required"
                    .into(),
            ));
        }

        builder = builder.with_no_client_auth();
    }

    let mut server_config = builder
        .with_single_cert(certificates, private_key)
        .map_err(|err| ChainError::Config(format!("failed to build TLS server config: {err}")))?;

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
}

async fn build_client_verifier(
    ca_path: &Path,
    require_client_auth: bool,
) -> ChainResult<Arc<dyn ClientCertVerifier>> {
    let ca_certs = load_certificates(ca_path).await?;
    let mut roots = RootCertStore::empty();
    for cert in &ca_certs {
        roots
            .add(cert.clone())
            .map_err(|err| ChainError::Config(format!("invalid client CA certificate: {err}")))?;
    }

    let roots = Arc::new(roots);
    let mut builder = WebPkiClientVerifier::builder(roots);
    if !require_client_auth {
        builder = builder.allow_unauthenticated();
    }

    builder.build().map_err(|err| {
        ChainError::Config(format!(
            "failed to build client certificate verifier: {err}"
        ))
    })
}

async fn load_certificates(path: &Path) -> ChainResult<Vec<CertificateDer<'static>>> {
    let bytes = fs::read(path)
        .await
        .map_err(|err| ChainError::Config(format!("failed to read {path:?}: {err}")))?;
    let mut reader = BufReader::new(bytes.as_slice());
    let certs = certs(&mut reader).map_err(|err| {
        ChainError::Config(format!("failed to parse certificates from {path:?}: {err}"))
    })?;
    Ok(certs
        .into_iter()
        .map(|cert| CertificateDer::from(cert).into_owned())
        .collect())
}

async fn load_private_key(path: &Path) -> ChainResult<PrivateKeyDer<'static>> {
    let bytes = fs::read(path)
        .await
        .map_err(|err| ChainError::Config(format!("failed to read {path:?}: {err}")))?;

    let mut reader = BufReader::new(bytes.as_slice());
    if let Some(key) = pkcs8_private_keys(&mut reader)
        .map_err(|err| {
            ChainError::Config(format!("failed to parse private key from {path:?}: {err}"))
        })?
        .into_iter()
        .next()
    {
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key));
        return Ok(key.clone_key());
    }

    let mut reader = BufReader::new(bytes.as_slice());
    if let Some(key) = rsa_private_keys(&mut reader)
        .map_err(|err| {
            ChainError::Config(format!("failed to parse private key from {path:?}: {err}"))
        })?
        .into_iter()
        .next()
    {
        let key = PrivateKeyDer::from(PrivatePkcs1KeyDer::from(key));
        return Ok(key.clone_key());
    }

    let mut reader = BufReader::new(bytes.as_slice());
    if let Some(key) = ec_private_keys(&mut reader)
        .map_err(|err| {
            ChainError::Config(format!("failed to parse private key from {path:?}: {err}"))
        })?
        .into_iter()
        .next()
    {
        let key = PrivateKeyDer::from(PrivateSec1KeyDer::from(key));
        return Ok(key.clone_key());
    }

    Err(ChainError::Config(format!(
        "no valid private key found in {path:?}"
    )))
}

async fn health(State(state): State<ApiContext>) -> Json<HealthResponse> {
    let mode = state.current_mode();
    let address = if let Some(node) = state.node_for_mode() {
        node.address().to_string()
    } else if let Some(wallet) = state.wallet_for_mode() {
        wallet.address().clone()
    } else if let Some(node) = state.node_handle() {
        node.address().to_string()
    } else if let Some(wallet) = state.wallet_handle() {
        wallet.address().clone()
    } else {
        String::from("unknown")
    };
    Json(HealthResponse {
        status: "ok",
        address,
        role: mode.as_str(),
    })
}

async fn health_live(State(state): State<ApiContext>) -> StatusCode {
    match state.node_for_mode() {
        Some(node) => match node.node_status() {
            Ok(_) => StatusCode::OK,
            Err(_) => StatusCode::SERVICE_UNAVAILABLE,
        },
        None => StatusCode::OK,
    }
}

async fn health_ready(State(state): State<ApiContext>) -> StatusCode {
    let mode = state.current_mode();

    let node_ready = !mode.includes_node() || state.node_enabled();
    let wallet_ready = !mode.includes_wallet() || state.wallet_enabled();
    let orchestrator_ready =
        !matches!(mode, RuntimeMode::Validator) || state.orchestrator_enabled();

    if node_ready && wallet_ready && orchestrator_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn runtime_mode(State(state): State<ApiContext>) -> Json<RuntimeModeResponse> {
    Json(state.runtime_state())
}

async fn update_runtime_mode(
    State(state): State<ApiContext>,
    Json(request): Json<RuntimeModeUpdate>,
) -> Result<Json<RuntimeModeResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.update_mode(request.mode)?;
    Ok(Json(state.runtime_state()))
}

fn wallet_history_fragments(
    state: &ApiContext,
    wallet: &Wallet,
) -> Result<WalletHistoryFragments, (StatusCode, Json<ErrorResponse>)> {
    #[cfg(feature = "vendor_electrs")]
    let tracker_state = state.tracker_state();

    #[cfg(feature = "vendor_electrs")]
    if matches!(tracker_state.as_ref(), Some(TrackerState::Pending)) {
        return Err(tracker_sync_pending());
    }

    let entries = wallet.history().map_err(to_http_error)?;

    #[cfg(feature = "vendor_electrs")]
    let script_metadata = wallet.script_status_metadata();

    #[cfg(feature = "vendor_electrs")]
    let tracker = tracker_state.and_then(|state| match state {
        TrackerState::Ready(snapshot) => Some(WalletTrackerSnapshot::from(snapshot)),
        TrackerState::Pending | TrackerState::Disabled => None,
    });

    Ok(WalletHistoryFragments {
        entries,
        #[cfg(feature = "vendor_electrs")]
        script_metadata,
        #[cfg(feature = "vendor_electrs")]
        tracker,
    })
}

async fn ui_history(
    State(state): State<ApiContext>,
) -> Result<Json<WalletHistoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    wallet_history_fragments(&state, wallet.as_ref())
        .map(|payload| WalletHistoryResponse {
            entries: payload.entries,
            #[cfg(feature = "vendor_electrs")]
            script_metadata: payload.script_metadata,
            #[cfg(feature = "vendor_electrs")]
            tracker: payload.tracker,
        })
        .map(Json)
}

async fn wallet_ui_history(
    State(state): State<ApiContext>,
) -> Result<Json<WalletUiHistoryContract>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    wallet_history_fragments(&state, wallet.as_ref())
        .map(|payload| WalletUiHistoryContract {
            version: WALLET_UI_HISTORY_CONTRACT,
            entries: payload.entries,
            #[cfg(feature = "vendor_electrs")]
            script_metadata: payload.script_metadata,
            #[cfg(feature = "vendor_electrs")]
            tracker: payload.tracker,
        })
        .map(Json)
}

async fn ui_send_preview(
    State(state): State<ApiContext>,
    Json(request): Json<TxComposeRequest>,
) -> Result<Json<SendPreview>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let TxComposeRequest {
        to,
        amount,
        fee,
        memo,
    } = request;
    wallet
        .preview_send(to, amount, fee, memo)
        .map(Json)
        .map_err(to_http_error)
}

async fn wallet_ui_send_preview(
    State(state): State<ApiContext>,
    Json(request): Json<TxComposeRequest>,
) -> Result<Json<WalletUiSendContract>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let TxComposeRequest {
        to,
        amount,
        fee,
        memo,
    } = request;
    wallet
        .preview_send(to, amount, fee, memo)
        .map(|preview| WalletUiSendContract {
            version: WALLET_UI_SEND_CONTRACT,
            preview,
        })
        .map(Json)
        .map_err(to_http_error)
}

async fn ui_receive(
    State(state): State<ApiContext>,
    Query(query): Query<ReceiveQuery>,
) -> Result<Json<ReceiveResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let count = query.count.unwrap_or(10).min(256);
    Ok(Json(ReceiveResponse {
        addresses: wallet.receive_addresses(count),
    }))
}

async fn wallet_ui_receive(
    State(state): State<ApiContext>,
    Query(query): Query<ReceiveQuery>,
) -> Result<Json<WalletUiReceiveContract>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let count = query.count.unwrap_or(10).min(256);
    Ok(Json(WalletUiReceiveContract {
        version: WALLET_UI_RECEIVE_CONTRACT,
        addresses: wallet.receive_addresses(count),
    }))
}

async fn ui_node_status(
    State(state): State<ApiContext>,
) -> Result<Json<UiNodeStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mode = state.current_mode();
    if let Some(node) = state.node_for_mode() {
        let node_status = node.node_status().map_err(to_http_error)?;
        let consensus = node.consensus_status().map_err(to_http_error)?;
        let mempool = node.mempool_status().map_err(to_http_error)?;
        let bft = node.bft_membership().map_err(to_http_error)?;
        Ok(Json(UiNodeStatusResponse {
            mode,
            node: Some(node_status),
            consensus: Some(consensus),
            mempool: Some(mempool),
            bft: Some(bft),
        }))
    } else {
        Ok(Json(UiNodeStatusResponse {
            mode,
            node: None,
            consensus: None,
            mempool: None,
            bft: None,
        }))
    }
}

async fn ui_reputation(
    State(state): State<ApiContext>,
) -> Result<Json<UiReputationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mode = state.current_mode();
    let summary = if let Some(wallet) = state.wallet_for_mode() {
        Some(wallet.account_summary().map_err(to_http_error)?)
    } else {
        None
    };
    Ok(Json(UiReputationResponse { mode, summary }))
}

async fn ui_bft_membership(
    State(state): State<ApiContext>,
) -> Result<Json<BftMembership>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .bft_membership()
        .map(Json)
        .map_err(to_http_error)
}

async fn block_proofs(
    State(state): State<ApiContext>,
    Path(height): Path<u64>,
) -> Result<Json<BlockProofResponse>, (StatusCode, Json<ErrorResponse>)> {
    let proof = state
        .require_node()?
        .block_proofs(height)
        .map_err(to_http_error)?;
    Ok(Json(BlockProofResponse { height, proof }))
}

async fn snapshot_plan(
    State(state): State<ApiContext>,
    Query(query): Query<SnapshotPlanQuery>,
) -> Result<Json<ReconstructionPlan>, (StatusCode, Json<ErrorResponse>)> {
    let start = query.start.unwrap_or(0);
    state
        .require_node()?
        .reconstruction_plan(start)
        .map(Json)
        .map_err(to_http_error)
}

async fn snapshot_jobs(
    State(state): State<ApiContext>,
) -> Result<Json<Option<PruningJobStatus>>, (StatusCode, Json<ErrorResponse>)> {
    let status = state.require_node()?.pruning_job_status();
    Ok(Json(status))
}

async fn state_sync_plan(
    State(state): State<ApiContext>,
) -> Result<Json<NetworkStateSyncPlan>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    let plan = node
        .state_sync_plan(DEFAULT_STATE_SYNC_CHUNK)
        .map_err(to_http_error)?;
    let expected_root = Blake3Hash::from(plan.snapshot.commitments.global_state_root);
    let total_chunks = plan.chunks.len();
    node.maybe_reset_state_sync_session(&expected_root, DEFAULT_STATE_SYNC_CHUNK, total_chunks);
    if let Some(api) = state.state_sync_api() {
        api.reset_state_sync_session(expected_root, DEFAULT_STATE_SYNC_CHUNK, total_chunks);
    }
    plan.to_network_plan().map(Json).map_err(to_http_error)
}

async fn state_sync_chunk(
    State(state): State<ApiContext>,
    Query(query): Query<StateSyncChunkQuery>,
) -> Result<Json<NetworkStateSyncChunk>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .network_state_sync_chunk(DEFAULT_STATE_SYNC_CHUNK, query.start)
        .map(Json)
        .map_err(to_http_error)
}

async fn validator_status(
    State(state): State<ApiContext>,
) -> Result<Json<ValidatorStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    let consensus = node.consensus_status().map_err(to_http_error)?;
    let node_status = node.node_status().map_err(to_http_error)?;

    Ok(Json(ValidatorStatusResponse {
        consensus,
        node: node_status,
    }))
}

async fn validator_proofs(
    State(state): State<ApiContext>,
) -> Result<Json<ValidatorProofQueueResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mempool = state
        .require_node()?
        .mempool_status()
        .map_err(to_http_error)?;

    let totals = ValidatorProofQueueTotals {
        transactions: mempool.transactions.len(),
        identities: mempool.identities.len(),
        votes: mempool.votes.len(),
        uptime_proofs: mempool.uptime_proofs.len(),
    };

    Ok(Json(ValidatorProofQueueResponse {
        uptime_proofs: mempool.uptime_proofs,
        totals,
    }))
}

async fn validator_peers(
    State(state): State<ApiContext>,
) -> Result<Json<ValidatorPeerResponse>, (StatusCode, Json<ErrorResponse>)> {
    let report = state
        .require_node()?
        .meta_telemetry_snapshot()
        .await
        .map_err(to_http_error)?;
    let snapshot = NetworkMetaTelemetryReport::from(&report);

    Ok(Json(ValidatorPeerResponse {
        local_peer_id: snapshot.local_peer_id,
        peer_count: snapshot.peer_count,
        peers: snapshot.peers,
    }))
}

async fn validator_telemetry(
    State(state): State<ApiContext>,
) -> Result<Json<ValidatorTelemetryResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.ensure_validator_tier(Tier::Tl0)?;
    let snapshot = state
        .require_node()?
        .validator_telemetry()
        .map_err(to_http_error)?;
    Ok(Json(ValidatorTelemetryResponse {
        rollout: snapshot.rollout,
        node: snapshot.node,
        consensus: snapshot.consensus,
        mempool: snapshot.mempool,
        timetoke_params: snapshot.timetoke_params,
        verifier_metrics: snapshot.verifier_metrics,
        pruning: snapshot.pruning,
        vrf_threshold: snapshot.vrf_threshold,
    }))
}

async fn validator_vrf(
    State(state): State<ApiContext>,
) -> Result<Json<ValidatorVrfResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.ensure_validator_tier(Tier::Tl0)?;
    let node = state.require_node()?;
    let (secrets, identifier, store) = node_vrf_store(&node)?;
    let keypair = store.load(&identifier).map_err(to_http_error)?;
    Ok(Json(vrf_response(&secrets, &identifier, keypair.as_ref())))
}

async fn validator_rotate_vrf(
    State(state): State<ApiContext>,
) -> Result<Json<ValidatorVrfResponse>, (StatusCode, Json<ErrorResponse>)> {
    state.ensure_validator_tier(Tier::Tl0)?;
    let node = state.require_node()?;
    let (secrets, identifier, store) = node_vrf_store(&node)?;
    let keypair = generate_vrf_keypair().map_err(to_http_error)?;
    store.store(&identifier, &keypair).map_err(to_http_error)?;
    Ok(Json(vrf_response(&secrets, &identifier, Some(&keypair))))
}

async fn validator_submit_uptime(
    State(state): State<ApiContext>,
) -> Result<Json<UptimeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    let wallet = state.require_wallet()?;
    let proof = wallet.generate_uptime_proof().map_err(to_http_error)?;
    node.submit_uptime_proof(proof)
        .map(|credited_hours| Json(UptimeResponse { credited_hours }))
        .map_err(to_http_error)
}

async fn submit_vrf_proof(
    State(state): State<ApiContext>,
    Json(request): Json<SubmitVrfProofRequest>,
) -> Result<(StatusCode, Json<SubmitVrfProofResponse>), (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    let submission = build_vrf_submission(request)?;
    node.submit_vrf_submission(submission)
        .map_err(to_http_error)?;

    Ok((
        StatusCode::ACCEPTED,
        Json(SubmitVrfProofResponse { status: "queued" }),
    ))
}

async fn submit_transaction(
    State(state): State<ApiContext>,
    Json(bundle): Json<TransactionProofBundle>,
) -> Result<Json<SubmitResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .submit_transaction(bundle)
        .map(|hash| Json(SubmitResponse { hash }))
        .map_err(to_http_error)
}

async fn submit_identity(
    State(state): State<ApiContext>,
    Json(request): Json<AttestedIdentityRequest>,
) -> Result<Json<SubmitResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .submit_identity(request)
        .map(|hash| Json(SubmitResponse { hash }))
        .map_err(to_http_error)
}

async fn vrf_threshold(
    State(state): State<ApiContext>,
) -> Result<Json<VrfThresholdStatus>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    Ok(Json(node.vrf_threshold()))
}

async fn submit_vote(
    State(state): State<ApiContext>,
    Json(vote): Json<SignedBftVote>,
) -> Result<Json<SubmitResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .submit_vote(vote)
        .map(|hash| Json(SubmitResponse { hash }))
        .map_err(to_http_error)
}

async fn submit_uptime_proof(
    State(state): State<ApiContext>,
    Json(proof): Json<UptimeProof>,
) -> Result<Json<UptimeResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .submit_uptime_proof(proof)
        .map(|credited_hours| Json(UptimeResponse { credited_hours }))
        .map_err(to_http_error)
}

async fn latest_block(
    State(state): State<ApiContext>,
) -> Result<Json<Option<Block>>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .latest_block()
        .map(Json)
        .map_err(to_http_error)
}

async fn block_by_height(
    State(state): State<ApiContext>,
    Path(height): Path<u64>,
) -> Result<Json<Option<Block>>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .get_block(height)
        .map(Json)
        .map_err(to_http_error)
}

async fn account_info(
    State(state): State<ApiContext>,
    Path(address): Path<String>,
) -> Result<Json<Option<Account>>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .get_account(&address)
        .map(Json)
        .map_err(to_http_error)
}

async fn p2p_meta_telemetry(
    State(state): State<ApiContext>,
) -> Result<Json<NetworkMetaTelemetryReport>, (StatusCode, Json<ErrorResponse>)> {
    let report = state
        .require_node()?
        .meta_telemetry_snapshot()
        .await
        .map_err(to_http_error)?;
    Ok(Json(NetworkMetaTelemetryReport::from(&report)))
}

async fn p2p_censorship_report(
    State(state): State<ApiContext>,
) -> Result<Json<P2pCensorshipReport>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .p2p_censorship_report()
        .await
        .map(Json)
        .map_err(to_http_error)
}

async fn node_status(
    State(state): State<ApiContext>,
) -> Result<Json<NodeStatus>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .node_status()
        .map(Json)
        .map_err(to_http_error)
}

async fn mempool_status(
    State(state): State<ApiContext>,
) -> Result<Json<MempoolStatus>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .mempool_status()
        .map(Json)
        .map_err(to_http_error)
}

async fn update_access_lists(
    State(state): State<ApiContext>,
    Json(request): Json<UpdateAccessListsRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;

    let mut allowlist = Vec::with_capacity(request.allowlist.len());
    let mut allow_seen = HashSet::new();
    for entry in request.allowlist {
        let peer = NetworkPeerId::from_str(&entry.peer_id).map_err(|err| {
            bad_request(format!("invalid allowlist peer `{}`: {err}", entry.peer_id))
        })?;
        if !allow_seen.insert(peer.clone()) {
            return Err(bad_request(format!(
                "duplicate allowlist entry for peer `{}`",
                entry.peer_id
            )));
        }
        allowlist.push(AllowlistedPeer {
            peer,
            tier: entry.tier,
        });
    }

    let mut blocklist = Vec::with_capacity(request.blocklist.len());
    let mut block_seen = HashSet::new();
    for value in request.blocklist {
        let peer = NetworkPeerId::from_str(&value)
            .map_err(|err| bad_request(format!("invalid blocklist peer `{value}`: {err}")))?;
        if !block_seen.insert(peer.clone()) {
            return Err(bad_request(format!(
                "duplicate blocklist entry for peer `{value}`"
            )));
        }
        blocklist.push(peer);
    }

    for entry in &allowlist {
        if block_seen.contains(&entry.peer) {
            return Err(bad_request(format!(
                "peer `{}` cannot be in allowlist and blocklist",
                entry.peer.to_base58()
            )));
        }
    }

    let audit = AdmissionAuditTrail::new("rpc.legacy_access_lists", Some("POST /p2p/access-lists"));
    node.update_admission_policies(allowlist, blocklist, audit)
        .map_err(to_http_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn update_mempool_limits(
    State(state): State<ApiContext>,
    Json(request): Json<UpdateMempoolRequest>,
) -> Result<Json<MempoolStatus>, (StatusCode, Json<ErrorResponse>)> {
    if request.limit.is_none() && request.priority_weight.is_none() && request.fee_weight.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "no mempool updates provided".into(),
            }),
        ));
    }
    let node = state.require_node()?;
    if let Some(limit) = request.limit {
        node.update_mempool_limit(limit).map_err(to_http_error)?;
    }
    if request.priority_weight.is_some() || request.fee_weight.is_some() {
        let mut weights = node.queue_weights();
        if let Some(priority) = request.priority_weight {
            weights.priority = priority;
        }
        if let Some(fee) = request.fee_weight {
            weights.fee = fee;
        }
        node.update_queue_weights(weights).map_err(to_http_error)?;
    }
    node.mempool_status().map(Json).map_err(to_http_error)
}

async fn consensus_status(
    State(state): State<ApiContext>,
) -> Result<Json<ConsensusStatus>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .consensus_status()
        .map(Json)
        .map_err(to_http_error)
}

async fn rollout_status(
    State(state): State<ApiContext>,
) -> Result<Json<RolloutStatus>, (StatusCode, Json<ErrorResponse>)> {
    state.require_node().map(|node| Json(node.rollout_status()))
}

async fn vrf_status(
    State(state): State<ApiContext>,
    Path(address): Path<String>,
) -> Result<Json<VrfStatus>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .vrf_status(&address)
        .map(Json)
        .map_err(to_http_error)
}

fn build_vrf_submission(
    request: SubmitVrfProofRequest,
) -> Result<VrfSubmission, (StatusCode, Json<ErrorResponse>)> {
    let SubmitVrfProofRequest {
        address,
        public_key,
        input,
        proof,
        tier,
        timetoke_hours,
    } = request;

    let SubmitVrfInput {
        last_block_header,
        epoch,
        tier_seed,
    } = input;

    let last_block_header = decode_hex_array::<32>(&last_block_header, "input.last_block_header")?;
    let tier_seed = decode_hex_array::<32>(&tier_seed, "input.tier_seed")?;

    let public_key_hex = public_key
        .and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .ok_or_else(|| invalid_vrf_request("public_key is required"))?;

    let public_key = vrf_public_key_from_hex(&public_key_hex)
        .map_err(|err| invalid_vrf_request(format!("invalid VRF public key: {err}")))?;

    Ok(VrfSubmission {
        address,
        public_key: Some(public_key),
        input: PoseidonVrfInput::new(last_block_header, epoch, tier_seed),
        proof,
        tier,
        timetoke_hours,
    })
}

fn decode_hex_array<const N: usize>(
    value: &str,
    field: &'static str,
) -> Result<[u8; N], (StatusCode, Json<ErrorResponse>)> {
    let decoded = hex::decode(value)
        .map_err(|_| invalid_vrf_request(format!("{field} must be a {N}-byte hex string")))?;

    if decoded.len() != N {
        return Err(invalid_vrf_request(format!(
            "{field} must be {N} bytes (found {})",
            decoded.len()
        )));
    }

    let mut buffer = [0u8; N];
    buffer.copy_from_slice(&decoded);
    Ok(buffer)
}

fn invalid_vrf_request(message: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
}

async fn slashing_events(
    State(state): State<ApiContext>,
    Query(query): Query<SlashingQuery>,
) -> Result<Json<Vec<SlashingEvent>>, (StatusCode, Json<ErrorResponse>)> {
    let limit = query.limit.unwrap_or(50).min(500);
    state
        .require_node()?
        .slashing_events(limit)
        .map(Json)
        .map_err(to_http_error)
}

async fn slashing_audit_stream(
    State(state): State<ApiContext>,
    Query(query): Query<AuditStreamQuery>,
) -> Result<Json<Vec<SlashingEvent>>, (StatusCode, Json<ErrorResponse>)> {
    let limit = query.limit.unwrap_or(200).min(1000);
    state
        .require_node()?
        .audit_slashing_stream(limit)
        .map(Json)
        .map_err(to_http_error)
}

async fn timetoke_snapshot(
    State(state): State<ApiContext>,
) -> Result<Json<Vec<TimetokeRecord>>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .timetoke_snapshot()
        .map(Json)
        .map_err(to_http_error)
}

async fn sync_timetoke(
    State(state): State<ApiContext>,
    Json(request): Json<TimetokeSyncRequest>,
) -> Result<Json<TimetokeSyncResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .sync_timetoke_records(request.records)
        .map(|updated| Json(TimetokeSyncResponse { updated }))
        .map_err(to_http_error)
}

async fn reputation_audit(
    State(state): State<ApiContext>,
    Path(address): Path<String>,
) -> Result<Json<Option<ReputationAudit>>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .reputation_audit(&address)
        .map(Json)
        .map_err(to_http_error)
}

async fn reputation_audit_stream(
    State(state): State<ApiContext>,
    Query(query): Query<AuditStreamQuery>,
) -> Result<Json<Vec<ReputationAudit>>, (StatusCode, Json<ErrorResponse>)> {
    let limit = query.limit.unwrap_or(200).min(1000);
    state
        .require_node()?
        .audit_reputation_stream(limit)
        .map(Json)
        .map_err(to_http_error)
}

async fn wallet_account(
    State(state): State<ApiContext>,
) -> Result<Json<WalletAccountResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    wallet
        .account_summary()
        .map(|summary| Json(WalletAccountResponse { summary }))
        .map_err(to_http_error)
}

async fn wallet_balance(
    State(state): State<ApiContext>,
    Path(address): Path<String>,
) -> Result<Json<WalletBalanceResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    #[cfg(feature = "vendor_electrs")]
    if matches!(state.tracker_state(), Some(TrackerState::Pending)) {
        return Err(tracker_sync_pending());
    }
    match wallet
        .account_summary_for(&address)
        .map_err(to_http_error)?
    {
        Some(summary) => Ok(Json(WalletBalanceResponse {
            address: summary.address,
            balance: summary.balance,
            nonce: summary.nonce,
            #[cfg(feature = "vendor_electrs")]
            mempool_delta: summary.mempool_delta,
        })),
        None => Err(not_found("account not found")),
    }
}

async fn wallet_reputation(
    State(state): State<ApiContext>,
    Path(address): Path<String>,
) -> Result<Json<Option<WalletAccountSummary>>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    #[cfg(feature = "vendor_electrs")]
    if matches!(state.tracker_state(), Some(TrackerState::Pending)) {
        return Err(tracker_sync_pending());
    }
    wallet
        .account_summary_for(&address)
        .map(Json)
        .map_err(to_http_error)
}

async fn wallet_tier(
    State(state): State<ApiContext>,
    Path(address): Path<String>,
) -> Result<Json<TierResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let account = wallet.account_by_address(&address).map_err(to_http_error)?;
    match account {
        Some(account) => Ok(Json(TierResponse {
            tier: account.reputation.tier.clone(),
        })),
        None => Err(not_found("account not found")),
    }
}

async fn wallet_history(
    State(state): State<ApiContext>,
) -> Result<Json<WalletHistoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    wallet_history_fragments(&state, wallet.as_ref())
        .map(|payload| WalletHistoryResponse {
            entries: payload.entries,
            #[cfg(feature = "vendor_electrs")]
            script_metadata: payload.script_metadata,
            #[cfg(feature = "vendor_electrs")]
            tracker: payload.tracker,
        })
        .map(Json)
}

async fn wallet_send_preview(
    State(state): State<ApiContext>,
    Json(request): Json<TxComposeRequest>,
) -> Result<Json<SendPreview>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let TxComposeRequest {
        to,
        amount,
        fee,
        memo,
    } = request;
    wallet
        .preview_send(to, amount, fee, memo)
        .map(Json)
        .map_err(to_http_error)
}

async fn wallet_build_transaction(
    State(state): State<ApiContext>,
    Json(request): Json<TxComposeRequest>,
) -> Result<Json<TxComposeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let TxComposeRequest {
        to,
        amount,
        fee,
        memo,
    } = request;
    let preview = wallet
        .preview_send(to.clone(), amount, fee, memo.clone())
        .map_err(to_http_error)?;
    let transaction = wallet
        .build_transaction(to, amount, fee, memo)
        .map_err(to_http_error)?;
    Ok(Json(TxComposeResponse {
        transaction,
        preview,
    }))
}

async fn wallet_sign_transaction(
    State(state): State<ApiContext>,
    Json(request): Json<SignTxRequest>,
) -> Result<Json<SignTxResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    Ok(Json(SignTxResponse {
        signed: wallet.sign_transaction(request.transaction),
    }))
}

async fn wallet_prove_transaction(
    State(state): State<ApiContext>,
    Json(request): Json<ProveTxRequest>,
) -> Result<Json<ProveTxResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    wallet
        .prove_transaction(&request.signed)
        .map(|bundle| Json(ProveTxResponse { bundle }))
        .map_err(to_http_error)
}

async fn wallet_submit_transaction(
    State(state): State<ApiContext>,
    Json(request): Json<SubmitTxRequest>,
) -> Result<Json<SubmitResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .submit_transaction(request.bundle)
        .map(|hash| Json(SubmitResponse { hash }))
        .map_err(to_http_error)
}

async fn wallet_receive_addresses(
    State(state): State<ApiContext>,
    Query(query): Query<ReceiveQuery>,
) -> Result<Json<ReceiveResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let count = query.count.unwrap_or(10).min(256);
    Ok(Json(ReceiveResponse {
        addresses: wallet.receive_addresses(count),
    }))
}

async fn wallet_node_view(
    State(state): State<ApiContext>,
) -> Result<Json<WalletNodeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let metrics = wallet.node_metrics().map_err(to_http_error)?;
    let consensus = wallet.latest_consensus_receipt().map_err(to_http_error)?;
    let pipeline = state
        .orchestrator_for_mode()
        .map(|orchestrator| wallet.pipeline_dashboard(orchestrator.as_ref()));
    Ok(Json(WalletNodeResponse {
        metrics,
        consensus,
        pipeline,
    }))
}

async fn wallet_ui_node(
    State(state): State<ApiContext>,
) -> Result<Json<WalletUiNodeContract>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let metrics = wallet.node_metrics().map_err(to_http_error)?;
    let consensus = wallet.latest_consensus_receipt().map_err(to_http_error)?;
    let pipeline = state
        .orchestrator_for_mode()
        .map(|orchestrator| wallet.pipeline_dashboard(orchestrator.as_ref()));
    Ok(Json(WalletUiNodeContract {
        version: WALLET_UI_NODE_CONTRACT,
        metrics,
        consensus,
        pipeline,
    }))
}

async fn wallet_state_root(
    State(state): State<ApiContext>,
) -> Result<Json<StateRootResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .state_root()
        .map(|state_root| Json(StateRootResponse { state_root }))
        .map_err(to_http_error)
}

async fn wallet_uptime_scheduler_status(
    State(state): State<ApiContext>,
) -> Result<Json<UptimeSchedulerStatus>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    Ok(Json(node.uptime_scheduler_status()))
}

async fn wallet_trigger_uptime_scheduler(
    State(state): State<ApiContext>,
) -> Result<Json<UptimeSchedulerRun>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .trigger_uptime_scheduler()
        .map(Json)
        .map_err(to_http_error)
}

async fn wallet_offload_uptime_proof(
    State(state): State<ApiContext>,
) -> Result<Json<WalletUptimeProofResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    match node.offload_uptime_proof().map_err(to_http_error)? {
        Some(proof) => Ok(Json(WalletUptimeProofResponse { proof })),
        None => Err(not_found("uptime proof not available")),
    }
}

async fn wallet_generate_uptime(
    State(state): State<ApiContext>,
) -> Result<Json<WalletUptimeProofResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    wallet
        .generate_uptime_proof()
        .map(|proof| Json(WalletUptimeProofResponse { proof }))
        .map_err(to_http_error)
}

async fn wallet_submit_uptime(
    State(state): State<ApiContext>,
    Json(request): Json<SubmitUptimeRequest>,
) -> Result<Json<UptimeResponse>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    let proof = match request.proof {
        Some(proof) => proof,
        None => state
            .require_wallet()?
            .generate_uptime_proof()
            .map_err(to_http_error)?,
    };
    node.submit_uptime_proof(proof)
        .map(|credited_hours| Json(UptimeResponse { credited_hours }))
        .map_err(to_http_error)
}

#[derive(Clone, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PipelineStreamEvent {
    Dashboard { snapshot: PipelineDashboardSnapshot },
    Error { error: PipelineError },
}

async fn wallet_pipeline_stream(
    State(state): State<ApiContext>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, Json<ErrorResponse>)> {
    let _wallet = state.require_wallet()?;
    let orchestrator = state.require_orchestrator()?;
    let dashboard_rx = orchestrator.subscribe_dashboard();
    let errors_rx = orchestrator.subscribe_errors();

    let dashboard_stream = WatchStream::new(dashboard_rx).map(|snapshot| {
        let payload = serde_json::to_string(&PipelineStreamEvent::Dashboard { snapshot })
            .expect("failed to serialise pipeline dashboard event");
        Ok(Event::default().event("dashboard").data(payload))
    });

    let errors_stream = BroadcastStream::new(errors_rx).filter_map(|result| async move {
        match result {
            Ok(error) => {
                let payload = serde_json::to_string(&PipelineStreamEvent::Error { error })
                    .expect("failed to serialise pipeline error event");
                Some(Ok(Event::default().event("error").data(payload)))
            }
            Err(BroadcastStreamRecvError::Lagged(_)) => None,
            Err(BroadcastStreamRecvError::Closed) => None,
        }
    });

    let stream = dashboard_stream.merge(errors_stream);

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}

async fn wallet_pipeline_dashboard(
    State(state): State<ApiContext>,
) -> Result<Json<PipelineDashboardSnapshot>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let orchestrator = state.require_orchestrator()?;
    Ok(Json(wallet.pipeline_dashboard(orchestrator.as_ref())))
}

async fn wallet_pipeline_telemetry(
    State(state): State<ApiContext>,
) -> Result<Json<PipelineTelemetrySummary>, (StatusCode, Json<ErrorResponse>)> {
    let _wallet = state.require_wallet()?;
    let orchestrator = state.require_orchestrator()?;
    let summary = orchestrator.telemetry_summary().await;
    Ok(Json(summary))
}

async fn wallet_pipeline_wait(
    State(state): State<ApiContext>,
    Json(request): Json<PipelineWaitRequest>,
) -> Result<Json<PipelineWaitResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let orchestrator = state.require_orchestrator()?;
    let timeout = request
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_secs(10));
    wallet
        .wait_for_pipeline_stage(orchestrator.as_ref(), &request.hash, request.stage, timeout)
        .await
        .map_err(to_http_error)?;
    Ok(Json(PipelineWaitResponse {
        hash: request.hash,
        stage: request.stage,
        completed: true,
    }))
}

async fn wallet_pipeline_shutdown(
    State(state): State<ApiContext>,
) -> Result<Json<PipelineShutdownResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let orchestrator = state.require_orchestrator()?;
    wallet.shutdown_pipeline(orchestrator.as_ref());
    Ok(Json(PipelineShutdownResponse { status: "ok" }))
}

fn node_vrf_store(
    node: &NodeHandle,
) -> Result<(SecretsConfig, VrfKeyIdentifier, DynVrfKeyStore), (StatusCode, Json<ErrorResponse>)> {
    let secrets = node.vrf_secrets_config();
    let path = node.vrf_key_path();
    let identifier = secrets.vrf_identifier(&path).map_err(to_http_error)?;
    let store = secrets.build_keystore().map_err(to_http_error)?;
    Ok((secrets, identifier, store))
}

fn vrf_response(
    secrets: &SecretsConfig,
    identifier: &VrfKeyIdentifier,
    keypair: Option<&VrfKeypair>,
) -> ValidatorVrfResponse {
    let backend = match &secrets.backend {
        SecretsBackendConfig::Filesystem(_) => "filesystem",
        SecretsBackendConfig::Vault(_) => "vault",
        SecretsBackendConfig::Hsm(_) => "hsm",
    }
    .to_string();
    let identifier = match identifier {
        VrfKeyIdentifier::Filesystem(path) => path.display().to_string(),
        VrfKeyIdentifier::Remote(key) => key.clone(),
    };
    let public_key = keypair.map(|pair| vrf_public_key_to_hex(&pair.public));
    ValidatorVrfResponse {
        backend,
        identifier,
        available: keypair.is_some(),
        public_key,
    }
}

fn to_http_error(err: ChainError) -> (StatusCode, Json<ErrorResponse>) {
    let status = match &err {
        ChainError::Transaction(_)
        | ChainError::Config(_)
        | ChainError::InvalidProof(_)
        | ChainError::CommitmentMismatch(_)
        | ChainError::MonotonicityViolation(_)
        | ChainError::SnapshotReplayFailed(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(ErrorResponse {
            error: err.to_string(),
        }),
    )
}

fn state_sync_error_to_http(err: StateSyncError) -> (StatusCode, Json<ErrorResponse>) {
    let kind = err.kind.clone();
    let message = err
        .message
        .clone()
        .unwrap_or_else(|| format!("state sync error: {:?}", err.kind));
    let status = match kind {
        StateSyncErrorKind::MissingRuntime
        | StateSyncErrorKind::NoActiveSession
        | StateSyncErrorKind::BuildFailed => StatusCode::SERVICE_UNAVAILABLE,
        StateSyncErrorKind::ChunkIndexOutOfRange { .. } => StatusCode::BAD_REQUEST,
        StateSyncErrorKind::ChunkNotFound { .. } => StatusCode::NOT_FOUND,
        StateSyncErrorKind::Unauthorized => StatusCode::UNAUTHORIZED,
        StateSyncErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(ErrorResponse { error: message }))
}

fn node_error_to_http(error: P2pNodeError) -> (StatusCode, Json<ErrorResponse>) {
    match error {
        P2pNodeError::SnapshotStreamNotFound => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "snapshot stream not found".into(),
            }),
        ),
        P2pNodeError::GossipDisabled => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "gossip propagation disabled".into(),
            }),
        ),
        P2pNodeError::CommandChannelClosed => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                error: "node runtime unavailable".into(),
            }),
        ),
        P2pNodeError::NetworkSetup(err)
        | P2pNodeError::Network(err)
        | P2pNodeError::Peerstore(err) => (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: err.to_string(),
            }),
        ),
        P2pNodeError::Pipeline(err) => (
            StatusCode::BAD_GATEWAY,
            Json(ErrorResponse {
                error: err.to_string(),
            }),
        ),
    }
}

pub(crate) fn snapshot_runtime_error_to_http(
    error: SnapshotStreamRuntimeError,
) -> (StatusCode, Json<ErrorResponse>) {
    match error {
        SnapshotStreamRuntimeError::Runtime(err) => node_error_to_http(err),
        SnapshotStreamRuntimeError::SessionNotFound(session) => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("snapshot session {session} not found"),
            }),
        ),
    }
}

fn bad_request(message: impl Into<String>) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
}

fn unavailable(component: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: format!("{component} runtime disabled"),
        }),
    )
}

fn not_started(component: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: format!(
                "{component} runtime not started; restart with a profile that enables it"
            ),
        }),
    )
}

fn pruning_service_not_configured() -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: "pruning service not configured".into(),
        }),
    )
}

fn pruning_service_error_to_http(error: PruningServiceError) -> (StatusCode, Json<ErrorResponse>) {
    match error {
        PruningServiceError::Unavailable => pruning_service_not_configured(),
        PruningServiceError::InvalidRequest(message) => (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse { error: message }),
        ),
        PruningServiceError::Internal(message) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse { error: message }),
        ),
    }
}

#[cfg(feature = "vendor_electrs")]
fn tracker_sync_pending() -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: "tracker synchronisation pending".to_string(),
        }),
    )
}

fn not_found(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
}

fn chain_error_to_state_sync(err: ChainError) -> StateSyncError {
    match err {
        ChainError::Config(message) => {
            StateSyncError::new(StateSyncErrorKind::MissingRuntime, Some(message))
        }
        ChainError::Unauthorized(message) => {
            StateSyncError::new(StateSyncErrorKind::Unauthorized, Some(message))
        }
        other => StateSyncError::new(StateSyncErrorKind::Internal, Some(other.to_string())),
    }
}

fn verification_error_to_state_sync(kind: Option<&VerificationErrorKind>) -> StateSyncErrorKind {
    match kind {
        Some(VerificationErrorKind::Plan(_))
        | Some(VerificationErrorKind::Encoding(_))
        | Some(VerificationErrorKind::Metadata(_))
        | Some(VerificationErrorKind::Incomplete(_)) => StateSyncErrorKind::BuildFailed,
        Some(VerificationErrorKind::Pipeline(_))
        | Some(VerificationErrorKind::PrunerState(_))
        | Some(VerificationErrorKind::Io(_)) => StateSyncErrorKind::Internal,
        None => StateSyncErrorKind::Internal,
    }
}

fn chunk_error_to_state_sync(err: StateSyncChunkError) -> StateSyncError {
    match err {
        StateSyncChunkError::NoActiveSession => StateSyncError::new(
            StateSyncErrorKind::NoActiveSession,
            Some("state sync session unavailable".into()),
        ),
        StateSyncChunkError::ChunkIndexOutOfRange { index, total } => StateSyncError::new(
            StateSyncErrorKind::ChunkIndexOutOfRange { index, total },
            Some(format!("chunk index {index} out of range (total {total})")),
        ),
        StateSyncChunkError::ChunkNotFound { index, reason } => {
            StateSyncError::new(StateSyncErrorKind::ChunkNotFound { index }, Some(reason))
        }
        StateSyncChunkError::SnapshotRootMismatch { expected, actual } => {
            let expected_hex = hex::encode(expected.as_bytes());
            let actual_hex = hex::encode(actual.as_bytes());
            StateSyncError::new(
                StateSyncErrorKind::Internal,
                Some(format!(
                    "snapshot root mismatch: expected {expected_hex}, found {actual_hex}"
                )),
            )
        }
        StateSyncChunkError::Io(err) => {
            StateSyncError::new(StateSyncErrorKind::Internal, Some(err.to_string()))
        }
        StateSyncChunkError::IoProof { message, .. } => {
            StateSyncError::new(StateSyncErrorKind::Internal, Some(message))
        }
        StateSyncChunkError::Internal(message) => {
            StateSyncError::new(StateSyncErrorKind::Internal, Some(message))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_error_to_state_sync_preserves_io_classification() {
        let io_kind = VerificationErrorKind::Io("ProofError::IO(failure)".into());
        assert_eq!(
            super::verification_error_to_state_sync(Some(&io_kind)),
            StateSyncErrorKind::Internal
        );

        let build_kind = VerificationErrorKind::Metadata("mismatch".into());
        assert_eq!(
            super::verification_error_to_state_sync(Some(&build_kind)),
            StateSyncErrorKind::BuildFailed
        );
    }
}

#[async_trait]
impl StateSyncApi for NodeHandle {
    fn watch_light_client_heads(
        &self,
    ) -> Result<watch::Receiver<Option<LightClientHead>>, StateSyncError> {
        self.subscribe_light_client_heads()
            .map_err(chain_error_to_state_sync)
    }

    fn latest_light_client_head(&self) -> Result<Option<LightClientHead>, StateSyncError> {
        self.latest_light_client_head()
            .map_err(chain_error_to_state_sync)
    }

    fn ensure_state_sync_session(&self) -> Result<(), StateSyncError> {
        match self
            .prepare_state_sync_session(DEFAULT_STATE_SYNC_CHUNK)
            .map_err(chain_error_to_state_sync)?
        {
            StateSyncVerificationStatus::Verified => Ok(()),
            StateSyncVerificationStatus::Failed => {
                let cache = self.state_sync_session_snapshot();
                let message = cache
                    .report
                    .as_ref()
                    .and_then(|report| report.summary.failure.clone())
                    .or(cache.error.clone())
                    .unwrap_or_else(|| "state sync verification failed".to_string());
                let kind = verification_error_to_state_sync(cache.error_kind.as_ref());
                Err(StateSyncError::new(kind, Some(message)))
            }
            _ => Err(StateSyncError::new(
                StateSyncErrorKind::Internal,
                Some("state sync verification ended in unexpected state".into()),
            )),
        }
    }

    fn reset_state_sync_session(&self, root: Blake3Hash, chunk_size: usize, total_chunks: usize) {
        self.maybe_reset_state_sync_session(&root, chunk_size, total_chunks);
    }

    fn state_sync_active_session(&self) -> Result<StateSyncSessionInfo, StateSyncError> {
        let cache = self.state_sync_session_snapshot();
        let has_session_data = cache.snapshot_root.is_some()
            || cache.total_chunks.is_some()
            || cache.report.is_some()
            || cache.error.is_some()
            || cache.last_completed_step.is_some()
            || !cache.progress_log.is_empty()
            || !cache.served_chunks.is_empty()
            || cache.status != StateSyncVerificationStatus::Idle;

        if !has_session_data {
            return Err(StateSyncError::new(
                StateSyncErrorKind::NoActiveSession,
                Some("state sync session unavailable".into()),
            ));
        }

        let total_chunks = match cache.total_chunks {
            Some(total) => Some(u32::try_from(total).map_err(|_| {
                StateSyncError::new(
                    StateSyncErrorKind::Internal,
                    Some("state sync chunk count exceeds supported range".into()),
                )
            })?),
            None => None,
        };

        let mut served_chunks: Vec<u64> = cache.served_chunks.iter().copied().collect();
        served_chunks.sort_unstable();

        let message = cache
            .report
            .as_ref()
            .and_then(|report| report.summary.failure.clone())
            .or_else(|| cache.error.clone());

        Ok(StateSyncSessionInfo {
            root: cache.snapshot_root,
            total_chunks,
            verified: cache.status == StateSyncVerificationStatus::Verified,
            last_completed_step: cache.last_completed_step.clone(),
            message,
            served_chunks,
            progress_log: cache.progress_log.clone(),
        })
    }

    async fn state_sync_chunk_by_index(&self, index: u32) -> Result<SnapshotChunk, StateSyncError> {
        self.state_sync_session_chunk(index)
            .map_err(chunk_error_to_state_sync)
    }
}

#[cfg(test)]
mod telemetry_tests {
    use super::*;
    use axum::http::{Method, Request as HttpRequest};
    use axum::routing::get;
    use opentelemetry::Value;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
    use opentelemetry_sdk::metrics::{
        InMemoryMetricExporter, MetricError, PeriodicReader, SdkMeterProvider,
    };
    use parking_lot::RwLock;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn setup_metrics() -> (
        Arc<RuntimeMetrics>,
        InMemoryMetricExporter,
        Arc<SdkMeterProvider>,
    ) {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = Arc::new(SdkMeterProvider::builder().with_reader(reader).build());
        let meter = provider.meter("rpc-test");
        let metrics = Arc::new(RuntimeMetrics::from_meter(&meter));
        (metrics, exporter, provider)
    }

    fn metric_has_attributes(
        exported: &[ResourceMetrics],
        name: &str,
        method: &str,
        result: &str,
    ) -> bool {
        exported
            .iter()
            .flat_map(|resource| resource.scope_metrics())
            .flat_map(|scope| scope.metrics())
            .filter(|metric| metric.name() == name)
            .any(|metric| match metric.data() {
                AggregatedMetrics::F64(MetricData::Histogram(histogram)) => histogram
                    .data_points()
                    .any(|point| data_point_matches(point.attributes(), method, result)),
                AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
                    .data_points()
                    .any(|point| data_point_matches(point.attributes(), method, result)),
                _ => false,
            })
    }

    fn data_point_matches<'a>(
        attrs: impl Iterator<Item = &'a opentelemetry::KeyValue>,
        method: &str,
        result: &str,
    ) -> bool {
        let mut method_match = false;
        let mut result_match = false;

        for attr in attrs {
            match attr.key.as_str() {
                "method" => {
                    if let Value::String(value) = &attr.value {
                        method_match = value.as_str() == method;
                    }
                }
                "result" => {
                    if let Value::String(value) = &attr.value {
                        result_match = value.as_str() == result;
                    }
                }
                _ => {}
            }
        }

        method_match && result_match
    }

    #[tokio::test]
    async fn wallet_requests_emit_metrics() -> Result<(), MetricError> {
        let (metrics, exporter, provider) = setup_metrics();
        let context = ApiContext::new(
            Arc::new(RwLock::new(RuntimeMode::Wallet)),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            false,
        )
        .with_metrics(metrics.clone());

        let app = Router::new()
            .route("/wallet/history", get(wallet_history))
            .layer(RpcMetricsLayer::new(metrics))
            .with_state(context);

        let request = HttpRequest::builder()
            .uri("/wallet/history")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        provider.force_flush()?;
        let exported = exporter.get_finished_metrics()?;

        assert!(metric_has_attributes(
            &exported,
            "rpp.runtime.rpc.request.latency",
            "get_history",
            "server_error",
        ));
        assert!(metric_has_attributes(
            &exported,
            "rpp.runtime.rpc.request.total",
            "get_history",
            "server_error",
        ));

        Ok(())
    }

    #[tokio::test]
    async fn proof_requests_emit_metrics() -> Result<(), MetricError> {
        let (metrics, exporter, provider) = setup_metrics();
        let context = ApiContext::new(
            Arc::new(RwLock::new(RuntimeMode::Node)),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            false,
        )
        .with_metrics(metrics.clone());

        let app = Router::new()
            .route("/proofs/block/:height", get(block_proofs))
            .layer(RpcMetricsLayer::new(metrics))
            .with_state(context);

        let request = HttpRequest::builder()
            .uri("/proofs/block/1")
            .method(Method::GET)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        provider.force_flush()?;
        let exported = exporter.get_finished_metrics()?;

        assert!(metric_has_attributes(
            &exported,
            "rpp.runtime.rpc.request.latency",
            "block_proof",
            "server_error",
        ));
        assert!(metric_has_attributes(
            &exported,
            "rpp.runtime.rpc.request.total",
            "block_proof",
            "server_error",
        ));

        Ok(())
    }
}

#[cfg(test)]
mod interface_schemas {
    use super::{
        ErrorResponse, PipelineWaitRequest, PipelineWaitResponse, RuntimeModeResponse,
        SignTxRequest, SignTxResponse,
    };
    use jsonschema::{Draft, JSONSchema};
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn interfaces_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/interfaces")
    }

    fn load_json(path: &Path) -> Value {
        let raw = fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("unable to read {}: {err}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|err| panic!("invalid JSON in {}: {err}", path.display()))
    }

    fn resolve_refs(value: &mut Value, base: &Path) {
        match value {
            Value::Object(map) => {
                if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                    let target_path = base.join(reference);
                    let mut target = load_json(&target_path);
                    let target_base = target_path
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| base.to_path_buf());
                    resolve_refs(&mut target, &target_base);
                    *value = target;
                } else {
                    for sub in map.values_mut() {
                        resolve_refs(sub, base);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    resolve_refs(item, base);
                }
            }
            _ => {}
        }
    }

    fn load_schema(segment: &str) -> Value {
        let path = interfaces_dir().join(segment);
        let mut schema = load_json(&path);
        let base = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| interfaces_dir());
        resolve_refs(&mut schema, &base);
        schema
    }

    fn load_example(segment: &str) -> Value {
        load_json(&interfaces_dir().join(segment))
    }

    fn assert_roundtrip<T>(schema_file: &str, example_file: &str)
    where
        T: Serialize + DeserializeOwned,
    {
        let schema = load_schema(schema_file);
        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .expect("schema compiles");
        let example = load_example(example_file);
        compiled.validate(&example).expect("example matches schema");
        let typed: T = serde_json::from_value(example.clone()).expect("deserialize example");
        let roundtrip = serde_json::to_value(&typed).expect("serialize payload");
        assert_eq!(roundtrip, example);
    }

    #[test]
    fn runtime_mode_response_schema_roundtrip() {
        assert_roundtrip::<RuntimeModeResponse>(
            "rpc/runtime_mode_response.jsonschema",
            "rpc/examples/runtime_mode_response.json",
        );
    }

    #[test]
    fn sign_tx_request_schema_roundtrip() {
        assert_roundtrip::<SignTxRequest>(
            "rpc/sign_tx_request.jsonschema",
            "rpc/examples/sign_tx_request.json",
        );
    }

    #[test]
    fn sign_tx_response_schema_roundtrip() {
        assert_roundtrip::<SignTxResponse>(
            "rpc/sign_tx_response.jsonschema",
            "rpc/examples/sign_tx_response.json",
        );
    }

    #[test]
    fn pipeline_wait_request_schema_roundtrip() {
        assert_roundtrip::<PipelineWaitRequest>(
            "rpc/pipeline_wait_request.jsonschema",
            "rpc/examples/pipeline_wait_request.json",
        );
    }

    #[test]
    fn pipeline_wait_response_schema_roundtrip() {
        assert_roundtrip::<PipelineWaitResponse>(
            "rpc/pipeline_wait_response.jsonschema",
            "rpc/examples/pipeline_wait_response.json",
        );
    }

    #[test]
    fn error_response_schema_roundtrip() {
        assert_roundtrip::<ErrorResponse>(
            "rpc/error_response.jsonschema",
            "rpc/examples/error_response.json",
        );
    }
}
