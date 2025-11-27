use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Router,
};
use hyper::body::to_bytes;
use parking_lot::RwLock;
use rpp_chain::api::{self, ApiContext, PruningServiceApi, PruningServiceError};
use rpp_chain::runtime::RuntimeMode;
use rpp_chain::storage::pruner::receipt::{
    SnapshotCancelReceipt, SnapshotRebuildReceipt, SnapshotTriggerReceipt,
};
use serde_json::Value;
use tower::ServiceExt;

struct FakePruningService {
    rebuild: Mutex<Result<SnapshotRebuildReceipt, PruningServiceError>>,
    snapshot: Mutex<Result<SnapshotTriggerReceipt, PruningServiceError>>,
    cancel: Mutex<Result<SnapshotCancelReceipt, PruningServiceError>>,
}

impl FakePruningService {
    fn new(
        rebuild: Result<SnapshotRebuildReceipt, PruningServiceError>,
        snapshot: Result<SnapshotTriggerReceipt, PruningServiceError>,
        cancel: Result<SnapshotCancelReceipt, PruningServiceError>,
    ) -> Self {
        Self {
            rebuild: Mutex::new(rebuild),
            snapshot: Mutex::new(snapshot),
            cancel: Mutex::new(cancel),
        }
    }
}

impl PruningServiceApi for FakePruningService {
    fn rebuild_snapshots(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<SnapshotRebuildReceipt, PruningServiceError>>
                + Send
                + 'static,
        >,
    > {
        let result = self.rebuild.lock().expect("rebuild lock poisoned").clone();
        Box::pin(async move { result })
    }

    fn trigger_snapshot(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<SnapshotTriggerReceipt, PruningServiceError>>
                + Send
                + 'static,
        >,
    > {
        let result = self
            .snapshot
            .lock()
            .expect("snapshot lock poisoned")
            .clone();
        Box::pin(async move { result })
    }

    fn cancel_pruning(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<SnapshotCancelReceipt, PruningServiceError>>
                + Send
                + 'static,
        >,
    > {
        let result = self.cancel.lock().expect("cancel lock poisoned").clone();
        Box::pin(async move { result })
    }
}

fn test_context(service: Arc<dyn PruningServiceApi>) -> ApiContext {
    ApiContext::new(
        Arc::new(RwLock::new(RuntimeMode::Node)),
        None,
        None,
        None,
        None,
        false,
        None,
        Some(service),
        false,
    )
}

#[tokio::test]
async fn rebuild_snapshots_returns_receipt() {
    let service: Arc<dyn PruningServiceApi> = Arc::new(FakePruningService::new(
        Ok(SnapshotRebuildReceipt::accepted()),
        Ok(SnapshotTriggerReceipt::accepted()),
        Ok(SnapshotCancelReceipt::accepted()),
    ));
    let app = Router::new()
        .route("/snapshots/rebuild", post(api::rebuild_snapshots))
        .with_state(test_context(service));

    let request = Request::builder()
        .method("POST")
        .uri("/snapshots/rebuild")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body()).await.unwrap();
    let receipt: SnapshotRebuildReceipt = serde_json::from_slice(&body).unwrap();
    assert!(receipt.accepted);
    assert!(receipt.detail.is_none());
}

#[tokio::test]
async fn snapshot_endpoint_propagates_error() {
    let service: Arc<dyn PruningServiceApi> = Arc::new(FakePruningService::new(
        Ok(SnapshotRebuildReceipt::accepted()),
        Err(PruningServiceError::Unavailable),
        Ok(SnapshotCancelReceipt::accepted()),
    ));
    let app = Router::new()
        .route("/snapshots/snapshot", post(api::trigger_snapshot))
        .with_state(test_context(service));

    let request = Request::builder()
        .method("POST")
        .uri("/snapshots/snapshot")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body()).await.unwrap();
    let payload: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "pruning service not configured");
}

#[tokio::test]
async fn cancel_endpoint_returns_receipt() {
    let service: Arc<dyn PruningServiceApi> = Arc::new(FakePruningService::new(
        Ok(SnapshotRebuildReceipt::accepted()),
        Ok(SnapshotTriggerReceipt::accepted()),
        Ok(SnapshotCancelReceipt::accepted()),
    ));
    let app = Router::new()
        .route("/snapshots/cancel", post(api::cancel_pruning))
        .with_state(test_context(service));

    let request = Request::builder()
        .method("POST")
        .uri("/snapshots/cancel")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body()).await.unwrap();
    let receipt: SnapshotCancelReceipt = serde_json::from_slice(&body).unwrap();
    assert!(receipt.accepted);
    assert!(receipt.detail.is_none());
}
