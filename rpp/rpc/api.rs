use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::info;

use crate::consensus::SignedBftVote;
use crate::errors::{ChainError, ChainResult};
use crate::ledger::{ReputationAudit, SlashingEvent};
use crate::node::{
    BftMembership, BlockProofArtifactsView, ConsensusStatus, MempoolStatus, NodeHandle, NodeStatus,
    NodeTelemetrySnapshot, RolloutStatus, VrfStatus,
};
use crate::orchestration::{PipelineDashboardSnapshot, PipelineOrchestrator, PipelineStage};
use crate::reputation::Tier;
use crate::rpp::TimetokeRecord;
use crate::runtime::RuntimeMode;
use crate::sync::ReconstructionPlan;
use crate::types::{
    Account, Address, AttestedIdentityRequest, Block, SignedTransaction, Transaction,
    TransactionProofBundle, UptimeProof,
};
use crate::wallet::{
    ConsensusReceipt, HistoryEntry, NodeTabMetrics, ReceiveTabAddress, SendPreview, Wallet,
    WalletAccountSummary,
};
use parking_lot::RwLock;

#[derive(Clone)]
pub struct ApiContext {
    mode: Arc<RwLock<RuntimeMode>>,
    node: Option<NodeHandle>,
    wallet: Option<Arc<Wallet>>,
    orchestrator: Option<Arc<PipelineOrchestrator>>,
}

impl ApiContext {
    pub fn new(
        mode: Arc<RwLock<RuntimeMode>>,
        node: Option<NodeHandle>,
        wallet: Option<Arc<Wallet>>,
        orchestrator: Option<Arc<PipelineOrchestrator>>,
    ) -> Self {
        Self {
            mode,
            node,
            wallet,
            orchestrator,
        }
    }

    fn current_mode(&self) -> RuntimeMode {
        *self.mode.read()
    }

    fn node_available(&self) -> bool {
        self.node.is_some()
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
        self.node.clone()
    }

    fn wallet_handle(&self) -> Option<Arc<Wallet>> {
        self.wallet.as_ref().map(Arc::clone)
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
}

#[derive(Serialize)]
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

#[derive(Serialize)]
struct RuntimeModeResponse {
    mode: RuntimeMode,
    node_available: bool,
    wallet_available: bool,
    node_enabled: bool,
    wallet_enabled: bool,
    orchestrator_available: bool,
    orchestrator_enabled: bool,
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

#[derive(Deserialize)]
struct SignTxRequest {
    transaction: Transaction,
}

#[derive(Serialize)]
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

#[derive(Serialize)]
struct BalanceResponse {
    address: Address,
    balance: u128,
    nonce: u64,
}

#[derive(Serialize)]
struct WalletHistoryResponse {
    entries: Vec<HistoryEntry>,
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
struct SubmitUptimeRequest {
    proof: Option<UptimeProof>,
}

#[derive(Deserialize)]
struct PipelineWaitRequest {
    hash: String,
    stage: PipelineStage,
    timeout_ms: Option<u64>,
}

#[derive(Serialize)]
struct PipelineWaitResponse {
    hash: String,
    stage: PipelineStage,
    completed: bool,
}

#[derive(Serialize)]
struct PipelineShutdownResponse {
    status: &'static str,
}

pub async fn serve(context: ApiContext, addr: SocketAddr) -> ChainResult<()> {
    let router = Router::new()
        .route("/health", get(health))
        .route("/runtime/mode", get(runtime_mode).post(update_runtime_mode))
        .route("/ui/history", get(ui_history))
        .route("/ui/send/preview", post(ui_send_preview))
        .route("/ui/receive", get(ui_receive))
        .route("/ui/node", get(ui_node_status))
        .route("/ui/reputation", get(ui_reputation))
        .route("/ui/bft/membership", get(ui_bft_membership))
        .route("/proofs/block/:height", get(block_proofs))
        .route("/snapshots/plan", get(snapshot_plan))
        .route("/validator/telemetry", get(validator_telemetry))
        .route("/validator/vrf", get(validator_vrf))
        .route("/validator/uptime", post(validator_submit_uptime))
        .route("/status/node", get(node_status))
        .route("/status/mempool", get(mempool_status))
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
        .route("/wallet/uptime/proof", post(wallet_generate_uptime))
        .route("/wallet/uptime/submit", post(wallet_submit_uptime))
        .route("/wallet/pipeline/dashboard", get(wallet_pipeline_dashboard))
        .route("/wallet/pipeline/wait", post(wallet_pipeline_wait))
        .route("/wallet/pipeline/shutdown", post(wallet_pipeline_shutdown))
        .with_state(context);

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

async fn ui_history(
    State(state): State<ApiContext>,
) -> Result<Json<WalletHistoryResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    wallet
        .history()
        .map(|entries| Json(WalletHistoryResponse { entries }))
        .map_err(to_http_error)
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

async fn validator_telemetry(
    State(state): State<ApiContext>,
) -> Result<Json<NodeTelemetrySnapshot>, (StatusCode, Json<ErrorResponse>)> {
    state
        .require_node()?
        .telemetry_snapshot()
        .map(Json)
        .map_err(to_http_error)
}

async fn validator_vrf(
    State(state): State<ApiContext>,
) -> Result<Json<VrfStatus>, (StatusCode, Json<ErrorResponse>)> {
    let node = state.require_node()?;
    let address = node.address().to_string();
    node.vrf_status(&address).map(Json).map_err(to_http_error)
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
) -> Result<Json<BalanceResponse>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let account = wallet.account_by_address(&address).map_err(to_http_error)?;
    match account {
        Some(account) => Ok(Json(BalanceResponse {
            address: account.address,
            balance: account.balance,
            nonce: account.nonce,
        })),
        None => Err(not_found("account not found")),
    }
}

async fn wallet_reputation(
    State(state): State<ApiContext>,
    Path(address): Path<String>,
) -> Result<Json<Option<WalletAccountSummary>>, (StatusCode, Json<ErrorResponse>)> {
    let wallet = state.require_wallet()?;
    let account = wallet.account_by_address(&address).map_err(to_http_error)?;
    Ok(Json(account.map(|account| summarize_account(&account))))
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
    wallet
        .history()
        .map(|entries| Json(WalletHistoryResponse { entries }))
        .map_err(to_http_error)
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

fn not_found(message: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
}

fn summarize_account(account: &Account) -> WalletAccountSummary {
    WalletAccountSummary {
        address: account.address.clone(),
        balance: account.balance,
        nonce: account.nonce,
        reputation_score: account.reputation.score,
        tier: account.reputation.tier.clone(),
        uptime_hours: account.reputation.timetokes.hours_online,
    }
}
