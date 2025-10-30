use std::str::FromStr;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::super::{
    snapshot_runtime_error_to_http, ApiContext, ErrorResponse, SnapshotStreamRuntimeError,
};
use crate::runtime::node_runtime::node::SnapshotStreamStatus;
use rpp_p2p::vendor::PeerId as NetworkPeerId;

#[derive(Debug, Deserialize)]
pub struct StartSnapshotStreamRequest {
    pub peer: String,
    pub chunk_size: u32,
    #[serde(default)]
    pub resume: Option<ResumeMarker>,
}

#[derive(Debug, Deserialize)]
pub struct ResumeMarker {
    pub session: u64,
}

#[derive(Debug, Serialize)]
pub struct SnapshotStreamStatusResponse {
    pub session: u64,
    pub peer: String,
    pub root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_chunk_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_update_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_update_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl From<SnapshotStreamStatus> for SnapshotStreamStatusResponse {
    fn from(status: SnapshotStreamStatus) -> Self {
        Self {
            session: status.session.get(),
            peer: status.peer.to_string(),
            root: status.root,
            last_chunk_index: status.last_chunk_index,
            last_update_index: status.last_update_index,
            last_update_height: status.last_update_height,
            verified: status.verified,
            error: status.error,
        }
    }
}

fn next_session_id() -> u64 {
    let uuid = Uuid::new_v4().as_u128();
    (uuid & u64::MAX as u128) as u64
}

pub(super) async fn start_snapshot_stream(
    State(state): State<ApiContext>,
    Json(request): Json<StartSnapshotStreamRequest>,
) -> Result<Json<SnapshotStreamStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    if request.chunk_size == 0 {
        return Err(super::super::bad_request(
            "chunk_size must be greater than zero",
        ));
    }

    let peer = NetworkPeerId::from_str(request.peer.trim())
        .map_err(|err| super::super::bad_request(format!("invalid peer id: {err}")))?;

    let session = request
        .resume
        .as_ref()
        .map(|marker| marker.session)
        .unwrap_or_else(next_session_id);

    let runtime = state.require_snapshot_runtime()?;
    let status = runtime
        .start_snapshot_stream(session, peer, String::new())
        .await
        .map_err(snapshot_runtime_error_to_http)?;

    Ok(Json(SnapshotStreamStatusResponse::from(status)))
}

pub(super) async fn snapshot_stream_status(
    State(state): State<ApiContext>,
    Path(id): Path<String>,
) -> Result<Json<SnapshotStreamStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let session = id
        .parse::<u64>()
        .map_err(|err| super::super::bad_request(format!("invalid snapshot session id: {err}")))?;

    let runtime = state.require_snapshot_runtime()?;
    let status = runtime.snapshot_stream_status(session).ok_or_else(|| {
        snapshot_runtime_error_to_http(SnapshotStreamRuntimeError::SessionNotFound(session))
    })?;

    Ok(Json(SnapshotStreamStatusResponse::from(status)))
}
