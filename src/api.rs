use std::net::SocketAddr;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::info;

use crate::errors::{ChainError, ChainResult};
use crate::node::NodeHandle;
use crate::types::{Account, Block, TransactionProofBundle};

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
struct HealthResponse {
    status: &'static str,
    address: String,
}

pub async fn serve(node: NodeHandle, addr: SocketAddr) -> ChainResult<()> {
    let state = AppState { node: node.clone() };
    let router = Router::new()
        .route("/health", get(health))
        .route("/transactions", post(submit_transaction))
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
