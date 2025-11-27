use axum::{extract::State, http::StatusCode, Json};

use super::super::{pruning_service_error_to_http, ApiContext, ErrorResponse};
use crate::storage::pruner::receipt::{
    SnapshotCancelReceipt, SnapshotRebuildReceipt, SnapshotTriggerReceipt,
};

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
