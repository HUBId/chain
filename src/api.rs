use std::net::SocketAddr;

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
use crate::node::{ConsensusStatus, MempoolStatus, NodeHandle, NodeStatus, VrfStatus};
use crate::types::{Account, Block, IdentityDeclaration, TransactionProofBundle, UptimeProof};

#[derive(Clone)]
struct AppState {
    node: NodeHandle,
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
    total_hours: u64,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    address: String,
}

#[derive(Deserialize)]
struct SlashingQuery {
    limit: Option<usize>,
}

pub async fn serve(node: NodeHandle, addr: SocketAddr) -> ChainResult<()> {
    let state = AppState { node: node.clone() };
    let router = Router::new()
        .route("/health", get(health))
        .route("/status/node", get(node_status))
        .route("/status/mempool", get(mempool_status))
        .route("/status/consensus", get(consensus_status))
        .route("/consensus/vrf/:address", get(vrf_status))
        .route("/transactions", post(submit_transaction))
        .route("/identities", post(submit_identity))
        .route("/consensus/votes", post(submit_vote))
        .route("/uptime/proofs", post(submit_uptime_proof))
        .route("/ledger/slashing", get(slashing_events))
        .route("/ledger/reputation/:address", get(reputation_audit))
        .route("/blocks/latest", get(latest_block))
        .route("/blocks/:height", get(block_by_height))
        .route("/accounts/:address", get(account_info))
        .with_state(state);

    let listener = TcpListener::bind(addr).await?;
    info!(?addr, "RPC server listening");
    axum::serve(listener, router)
        .await
        .map_err(|err| ChainError::Io(std::io::Error::new(std::io::ErrorKind::Other, err)))
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        address: state.node.address().to_string(),
    })
}

async fn submit_transaction(
    State(state): State<AppState>,
    Json(bundle): Json<TransactionProofBundle>,
) -> Result<Json<SubmitResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .node
        .submit_transaction(bundle)
        .map(|hash| Json(SubmitResponse { hash }))
        .map_err(to_http_error)
}

async fn submit_identity(
    State(state): State<AppState>,
    Json(declaration): Json<IdentityDeclaration>,
) -> Result<Json<SubmitResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .node
        .submit_identity(declaration)
        .map(|hash| Json(SubmitResponse { hash }))
        .map_err(to_http_error)
}

async fn submit_vote(
    State(state): State<AppState>,
    Json(vote): Json<SignedBftVote>,
) -> Result<Json<SubmitResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .node
        .submit_vote(vote)
        .map(|hash| Json(SubmitResponse { hash }))
        .map_err(to_http_error)
}

async fn submit_uptime_proof(
    State(state): State<AppState>,
    Json(proof): Json<UptimeProof>,
) -> Result<Json<UptimeResponse>, (StatusCode, Json<ErrorResponse>)> {
    state
        .node
        .submit_uptime_proof(proof)
        .map(|total_hours| Json(UptimeResponse { total_hours }))
        .map_err(to_http_error)
}

async fn latest_block(
    State(state): State<AppState>,
) -> Result<Json<Option<Block>>, (StatusCode, Json<ErrorResponse>)> {
    state.node.latest_block().map(Json).map_err(to_http_error)
}

async fn block_by_height(
    State(state): State<AppState>,
    Path(height): Path<u64>,
) -> Result<Json<Option<Block>>, (StatusCode, Json<ErrorResponse>)> {
    state
        .node
        .get_block(height)
        .map(Json)
        .map_err(to_http_error)
}

async fn account_info(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<Option<Account>>, (StatusCode, Json<ErrorResponse>)> {
    state
        .node
        .get_account(&address)
        .map(Json)
        .map_err(to_http_error)
}

async fn node_status(
    State(state): State<AppState>,
) -> Result<Json<NodeStatus>, (StatusCode, Json<ErrorResponse>)> {
    state.node.node_status().map(Json).map_err(to_http_error)
}

async fn mempool_status(
    State(state): State<AppState>,
) -> Result<Json<MempoolStatus>, (StatusCode, Json<ErrorResponse>)> {
    state.node.mempool_status().map(Json).map_err(to_http_error)
}

async fn consensus_status(
    State(state): State<AppState>,
) -> Result<Json<ConsensusStatus>, (StatusCode, Json<ErrorResponse>)> {
    state
        .node
        .consensus_status()
        .map(Json)
        .map_err(to_http_error)
}

async fn vrf_status(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<VrfStatus>, (StatusCode, Json<ErrorResponse>)> {
    state
        .node
        .vrf_status(&address)
        .map(Json)
        .map_err(to_http_error)
}

async fn slashing_events(
    State(state): State<AppState>,
    Query(query): Query<SlashingQuery>,
) -> Result<Json<Vec<SlashingEvent>>, (StatusCode, Json<ErrorResponse>)> {
    let limit = query.limit.unwrap_or(50).min(500);
    state
        .node
        .slashing_events(limit)
        .map(Json)
        .map_err(to_http_error)
}

async fn reputation_audit(
    State(state): State<AppState>,
    Path(address): Path<String>,
) -> Result<Json<Option<ReputationAudit>>, (StatusCode, Json<ErrorResponse>)> {
    state
        .node
        .reputation_audit(&address)
        .map(Json)
        .map_err(to_http_error)
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
