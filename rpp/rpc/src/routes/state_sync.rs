use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine as _;
use blake3::Hash as Blake3Hash;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio_stream::wrappers::WatchStream;
use tokio_stream::{Stream, StreamExt};
use tracing::warn;

use super::super::{
    chunk_error_to_state_sync, state_sync_error_to_http, ApiContext, ErrorResponse, LightHeadSse,
    StateSyncApi, StateSyncError, StateSyncSessionInfo,
};
use crate::node::LightClientVerificationEvent;
use rpp_p2p::SnapshotChunk;

#[derive(Clone, Debug, Serialize)]
pub struct StateSyncStatusResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_chunks: Option<u32>,
    pub completed_chunks: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_chunks: Option<u32>,
    pub verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_completed_step: Option<String>,
    #[serde(default)]
    pub served_chunks: Vec<u64>,
    #[serde(default)]
    pub progress_log: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl From<&StateSyncSessionInfo> for StateSyncStatusResponse {
    fn from(session: &StateSyncSessionInfo) -> Self {
        let completed_chunks = session.served_chunks.len();
        let completed_as_u32 = u32::try_from(completed_chunks).ok();
        let remaining_chunks = session
            .total_chunks
            .and_then(|total| completed_as_u32.and_then(|done| total.checked_sub(done)));

        Self {
            root: session.root.map(format_root),
            total_chunks: session.total_chunks,
            completed_chunks,
            remaining_chunks,
            verified: session.verified,
            last_completed_step: session.last_completed_step.as_ref().map(describe_event),
            served_chunks: session.served_chunks.clone(),
            progress_log: session.progress_log.clone(),
            last_error: session.message.clone(),
            request_id: session.request_id.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotChunkJson {
    pub root: String,
    pub index: u32,
    pub total: u32,
    pub length: u32,
    pub payload: String,
    pub sha256: String,
}

impl SnapshotChunkJson {
    fn from_chunk(chunk: SnapshotChunk) -> Self {
        let index = u32::try_from(chunk.index).unwrap_or(u32::MAX);
        let total = u32::try_from(chunk.total).unwrap_or(u32::MAX);
        let length = u32::try_from(chunk.data.len()).unwrap_or(u32::MAX);
        let payload = BASE64_ENGINE.encode(&chunk.data);
        let sha256 = Sha256::digest(&chunk.data);
        Self {
            root: format!("0x{}", hex::encode(chunk.root.as_bytes())),
            index,
            total,
            length,
            payload,
            sha256: format!("0x{}", hex::encode(sha256)),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StateSyncChunkResponse {
    pub chunk: SnapshotChunkJson,
    pub status: StateSyncStatusResponse,
}

pub(super) async fn session_status(
    State(state): State<ApiContext>,
) -> Result<Json<StateSyncStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let api = state.require_state_sync_api()?;
    let session = api
        .state_sync_active_session()
        .map_err(state_sync_error_to_http)?;
    Ok(Json(StateSyncStatusResponse::from(&session)))
}

pub(super) async fn head_stream(
    State(state): State<ApiContext>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, Json<ErrorResponse>)> {
    let api = state.require_state_sync_api()?;
    let receiver = api
        .watch_light_client_heads()
        .map_err(state_sync_error_to_http)?;

    let stream = WatchStream::new(receiver)
        .filter_map(|head| async move { head.map(LightHeadSse::from) })
        .map(
            |payload| match Event::default().event("head").json_data(&payload) {
                Ok(event) => Ok(event),
                Err(err) => {
                    warn!(?err, "failed to encode light client head for SSE");
                    Ok(Event::default().event("head"))
                }
            },
        );

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .comment("hb"),
    ))
}

pub(super) async fn session_stream(
    State(state): State<ApiContext>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, Json<ErrorResponse>)> {
    let api = state.require_state_sync_api()?;
    api.ensure_state_sync_session()
        .map_err(state_sync_error_to_http)?;
    let server = state.require_state_sync_server()?;

    let session = api
        .state_sync_active_session()
        .map_err(state_sync_error_to_http)?;
    let status = StateSyncStatusResponse::from(&session);
    let initial = tokio_stream::once(Result::<Event, Infallible>::Ok(json_event(
        "status", &status,
    )));

    let chunk_stream = server
        .stream_session()
        .await
        .map_err(chunk_error_to_state_sync)
        .map_err(state_sync_error_to_http)?;

    let api = Arc::clone(&api);
    let chunk_events = chunk_stream.scan(false, move |errored, result| {
        let api = Arc::clone(&api);
        async move {
            if *errored {
                return None;
            }

            match result {
                Ok(chunk) => {
                    let payload = SnapshotChunkJson::from_chunk(chunk);
                    let status = match api.state_sync_active_session() {
                        Ok(session) => StateSyncStatusResponse::from(&session),
                        Err(err) => {
                            *errored = true;
                            let error = error_event(err);
                            return Some(Ok(error));
                        }
                    };
                    let response = StateSyncChunkResponse {
                        chunk: payload,
                        status,
                    };
                    Some(Ok(json_event("chunk", &response)))
                }
                Err(err) => {
                    *errored = true;
                    let error = chunk_error_to_state_sync(err);
                    Some(Ok(error_event(error)))
                }
            }
        }
    });

    let stream = initial.chain(chunk_events);

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .comment("hb"),
    ))
}

#[derive(Deserialize)]
pub(super) struct ChunkIdPath {
    pub id: u32,
}

pub(super) async fn chunk_by_id(
    State(state): State<ApiContext>,
    Path(path): Path<ChunkIdPath>,
) -> Result<Json<StateSyncChunkResponse>, (StatusCode, Json<ErrorResponse>)> {
    let api = state.require_state_sync_api()?;
    api.ensure_state_sync_session()
        .map_err(state_sync_error_to_http)?;

    let chunk = api
        .state_sync_chunk_by_index(path.id)
        .await
        .map_err(state_sync_error_to_http)?;
    let session = api
        .state_sync_active_session()
        .map_err(state_sync_error_to_http)?;
    let status = StateSyncStatusResponse::from(&session);

    Ok(Json(StateSyncChunkResponse {
        chunk: SnapshotChunkJson::from_chunk(chunk),
        status,
    }))
}

fn format_root(root: Blake3Hash) -> String {
    format!("0x{}", hex::encode(root.as_bytes()))
}

fn describe_event(event: &LightClientVerificationEvent) -> String {
    match event {
        LightClientVerificationEvent::PlanLoaded {
            snapshot_height,
            chunk_count,
            update_count,
        } => format!(
            "plan loaded: snapshot height {snapshot_height}, {chunk_count} chunks, {update_count} updates"
        ),
        LightClientVerificationEvent::PlanIngested {
            chunk_count,
            update_count,
        } => format!(
            "plan ingested: {chunk_count} chunks, {update_count} updates"
        ),
        LightClientVerificationEvent::SnapshotMetadataValidated {
            dataset_label,
            state_root,
            state_commitment,
        } => format!(
            "snapshot metadata validated: dataset {dataset_label}, root {state_root}, commitment {state_commitment}"
        ),
        LightClientVerificationEvent::ReceiptsMatched {
            dataset_label,
            snapshot_count,
        } => format!(
            "receipts matched: dataset {dataset_label}, {snapshot_count} snapshots"
        ),
        LightClientVerificationEvent::MerkleRootConfirmed {
            start_height,
            end_height,
        } => format!(
            "merkle root confirmed: blocks {start_height}-{end_height}"
        ),
        LightClientVerificationEvent::RecursiveProofVerified { height } => {
            format!("recursive proof verified at height {height}")
        }
        LightClientVerificationEvent::VerificationCompleted { snapshot_root } => {
            format!("verification completed for snapshot root {snapshot_root}")
        }
    }
}

fn json_event<T>(event: &'static str, payload: &T) -> Event
where
    T: Serialize,
{
    match Event::default().event(event).json_data(payload) {
        Ok(event) => event,
        Err(err) => {
            warn!(?err, "failed to encode state sync SSE payload");
            Event::default().event(event)
        }
    }
}

fn error_event(error: StateSyncError) -> Event {
    let (_, Json(body)) = state_sync_error_to_http(error.clone());
    json_event("error", &body)
}
