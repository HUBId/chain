use std::collections::HashSet;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::error_handling::HandleErrorLayer;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{BoxError, Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower::limit::RateLimitLayer;
use tower::ServiceBuilder;
use tracing::info;

use crate::consensus::SignedBftVote;
use crate::crypto::{
    generate_vrf_keypair, vrf_public_key_to_hex, vrf_secret_key_to_hex, DynVrfKeyStore,
    VrfKeyIdentifier, VrfKeypair,
};
use crate::errors::{ChainError, ChainResult};
#[cfg(feature = "vendor_electrs")]
use crate::interfaces::WalletTrackerSnapshot;
use crate::interfaces::{WalletBalanceResponse, WalletHistoryResponse};
use crate::ledger::{ReputationAudit, SlashingEvent};
use crate::node::{
    BftMembership, BlockProofArtifactsView, ConsensusStatus, MempoolStatus, NodeHandle, NodeStatus,
    NodeTelemetrySnapshot, PendingUptimeSummary, PruningJobStatus, RolloutStatus,
    UptimeSchedulerRun, UptimeSchedulerStatus, VrfStatus, DEFAULT_STATE_SYNC_CHUNK,
};
use crate::orchestration::{PipelineDashboardSnapshot, PipelineOrchestrator, PipelineStage};
use crate::reputation::Tier;
use crate::rpp::TimetokeRecord;
use crate::runtime::config::{
    P2pAllowlistEntry, QueueWeightsConfig, SecretsBackendConfig, SecretsConfig,
};
use crate::runtime::RuntimeMode;
use crate::sync::ReconstructionPlan;
use crate::types::{
    Account, Address, AttestedIdentityRequest, Block, SignedTransaction, Transaction,
    TransactionProofBundle, UptimeProof,
};
use crate::wallet::{
    ConsensusReceipt, NodeTabMetrics, ReceiveTabAddress, SendPreview, Wallet, WalletAccountSummary,
};
#[cfg(feature = "vendor_electrs")]
use crate::wallet::{TrackerState, WalletTrackerHandle};
use parking_lot::RwLock;
use rpp_p2p::vendor::PeerId as NetworkPeerId;
use rpp_p2p::{
    AllowlistedPeer, NetworkMetaTelemetryReport, NetworkPeerTelemetry, NetworkStateSyncChunk,
    NetworkStateSyncPlan,
};

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
}

impl ApiContext {
    pub fn new(
        mode: Arc<RwLock<RuntimeMode>>,
        node: Option<NodeHandle>,
        wallet: Option<Arc<Wallet>>,
        orchestrator: Option<Arc<PipelineOrchestrator>>,
        request_limit_per_minute: Option<NonZeroU64>,
        auth_token_enabled: bool,
    ) -> Self {
        #[cfg(feature = "vendor_electrs")]
        let tracker = wallet.as_ref().and_then(|wallet| wallet.tracker_handle());

        Self {
            mode,
            node,
            wallet,
            #[cfg(feature = "vendor_electrs")]
            tracker,
            orchestrator,
            request_limit_per_minute,
            auth_token_enabled,
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
        self.wallet.is_some()
    }

    fn node_enabled(&self) -> bool {
        self.node_available() && self.current_mode().includes_node()
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
struct UptimeResponse {
    credited_hours: u64,
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
    local_peer_id: String,
    peer_count: usize,
    peers: Vec<NetworkPeerTelemetry>,
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

pub async fn serve(
    context: ApiContext,
    addr: SocketAddr,
    auth_token: Option<String>,
    allowed_origin: Option<String>,
) -> ChainResult<()> {
    let security = ApiSecurity::new(auth_token, allowed_origin)?;
    let request_limit_per_minute = context.request_limit_per_minute();

    let mut router = Router::new()
        .route("/health", get(health))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/runtime/mode", get(runtime_mode).post(update_runtime_mode))
        .route("/ui/history", get(ui_history))
        .route("/ui/send/preview", post(ui_send_preview))
        .route("/ui/receive", get(ui_receive))
        .route("/ui/node", get(ui_node_status))
        .route("/ui/reputation", get(ui_reputation))
        .route("/ui/bft/membership", get(ui_bft_membership))
        .route("/proofs/block/:height", get(block_proofs))
        .route("/snapshots/plan", get(snapshot_plan))
        .route("/snapshots/jobs", get(snapshot_jobs))
        .route("/state-sync/plan", get(state_sync_plan))
        .route("/state-sync/chunk", get(state_sync_chunk))
        .route("/validator/status", get(validator_status))
        .route("/validator/proofs", get(validator_proofs))
        .route("/validator/peers", get(validator_peers))
        .route("/validator/telemetry", get(validator_telemetry))
        .route("/validator/vrf", get(validator_vrf))
        .route("/validator/vrf/rotate", post(validator_rotate_vrf))
        .route("/validator/uptime", post(validator_submit_uptime))
        .route("/p2p/peers", get(p2p_meta_telemetry))
        .route("/p2p/access-lists", post(update_access_lists))
        .route("/status/node", get(node_status))
        .route("/status/mempool", get(mempool_status))
        .route("/control/mempool", post(update_mempool_limits))
        .route("/status/consensus", get(consensus_status))
        .route("/status/rollout", get(rollout_status))
        .route("/consensus/vrf/:address", get(vrf_status))
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
        .route("/wallet/state/root", get(wallet_state_root))
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
        .route("/wallet/pipeline/wait", post(wallet_pipeline_wait))
        .route("/wallet/pipeline/shutdown", post(wallet_pipeline_shutdown));

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

    let router = router.with_state(context);

    let listener = TcpListener::bind(addr).await?;
    info!(?addr, "RPC server listening");
    axum::serve(listener, router)
        .await
        .map_err(|err| ChainError::Io(std::io::Error::new(std::io::ErrorKind::Other, err)))
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

fn wallet_history_payload(
    state: &ApiContext,
    wallet: &Wallet,
) -> Result<WalletHistoryResponse, (StatusCode, Json<ErrorResponse>)> {
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

    Ok(WalletHistoryResponse {
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
    wallet_history_payload(&state, wallet.as_ref()).map(Json)
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
    state
        .require_node()?
        .network_state_sync_plan(DEFAULT_STATE_SYNC_CHUNK)
        .map(Json)
        .map_err(to_http_error)
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
    let report = state
        .require_node()?
        .meta_telemetry_snapshot()
        .await
        .map_err(to_http_error)?;
    let network = NetworkMetaTelemetryReport::from(&report);
    Ok(Json(ValidatorTelemetryResponse {
        local_peer_id: network.local_peer_id,
        peer_count: network.peer_count,
        peers: network.peers,
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

    node.reload_access_lists(allowlist, blocklist)
        .await
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
    wallet_history_payload(&state, wallet.as_ref()).map(Json)
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

async fn wallet_pipeline_dashboard(
    State(state): State<ApiContext>,
) -> Result<Json<PipelineDashboardSnapshot>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let orchestrator = state.require_orchestrator()?;
    Ok(Json(wallet.pipeline_dashboard(orchestrator.as_ref())))
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
    let status = match err {
        ChainError::Transaction(_) => StatusCode::BAD_REQUEST,
        ChainError::Config(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(ErrorResponse {
            error: err.to_string(),
        }),
    )
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
