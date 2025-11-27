use std::convert::Infallible;
use std::time::Duration;

use axum::{
    extract::State,
    http::StatusCode,
    response::sse::{Event, KeepAlive, Sse},
    Json,
};
use serde::Serialize;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::{Stream, StreamExt};

use super::super::{pruning_service_error_to_http, ApiContext, ErrorResponse};
use crate::{
    node::PruningJobStatus,
    storage::pruner::receipt::{
        SnapshotCancelReceipt, SnapshotRebuildReceipt, SnapshotTriggerReceipt,
    },
};

#[derive(Clone, Debug, Serialize)]
pub struct PruningStatusResponse {
    pub status: Option<PruningJobStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_ms: Option<u64>,
}

impl PruningStatusResponse {
    fn from_status(status: Option<PruningJobStatus>) -> Self {
        let progress = status.as_ref().map(|status| {
            let total = status.missing_heights.len().max(status.stored_proofs.len()) as f64;

            if total == 0.0 {
                1.0
            } else {
                (status.stored_proofs.len() as f64 / total).min(1.0)
            }
        });

        let eta_ms = status
            .as_ref()
            .and_then(|status| status.estimated_time_remaining_ms);

        Self {
            status,
            progress,
            eta_ms,
        }
    }
}

pub(super) async fn rebuild_snapshots(
    State(state): State<ApiContext>,
) -> Result<Json<SnapshotRebuildReceipt>, (StatusCode, Json<ErrorResponse>)> {
    let service = state.require_pruning_service()?;
    service
        .rebuild_snapshots()
        .await
        .map(Json)
        .map_err(pruning_service_error_to_http)
}

pub(super) async fn trigger_snapshot(
    State(state): State<ApiContext>,
) -> Result<Json<SnapshotTriggerReceipt>, (StatusCode, Json<ErrorResponse>)> {
    let service = state.require_pruning_service()?;
    service
        .trigger_snapshot()
        .await
        .map(Json)
        .map_err(pruning_service_error_to_http)
}

pub(super) async fn cancel_pruning(
    State(state): State<ApiContext>,
) -> Result<Json<SnapshotCancelReceipt>, (StatusCode, Json<ErrorResponse>)> {
    let service = state.require_pruning_service()?;
    service
        .cancel_pruning()
        .await
        .map(Json)
        .map_err(pruning_service_error_to_http)
}

pub(super) async fn pruning_status(
    State(state): State<ApiContext>,
) -> Result<Json<PruningStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut receiver = state.require_pruning_status_stream()?;
    let snapshot = receiver.borrow_and_update().clone();
    Ok(Json(PruningStatusResponse::from_status(snapshot)))
}

pub(super) async fn pruning_status_stream(
    State(state): State<ApiContext>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, Json<ErrorResponse>)> {
    let receiver = state.require_pruning_status_stream()?;
    let stream = WatchStream::new(receiver).map(|status| {
        let response = PruningStatusResponse::from_status(status);
        match Event::default().event("pruning").json_data(&response) {
            Ok(event) => Ok(event),
            Err(_) => Ok(Event::default().event("pruning")),
        }
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .comment("hb"),
    ))
}
