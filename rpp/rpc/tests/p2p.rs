use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
};
use hyper::body::to_bytes;
use parking_lot::RwLock;
use rpp_chain::api::{
    self,
    ApiContext,
    SnapshotStreamRuntime,
    SnapshotStreamRuntimeError,
};
use rpp_chain::runtime::RuntimeMode;
use rpp_chain::runtime::node_runtime::node::{NodeError as P2pNodeError, SnapshotStreamStatus};
use rpp_p2p::{vendor::PeerId as NetworkPeerId, SnapshotSessionId};
use serde_json::json;
use tower::ServiceExt;

struct FakeSnapshotRuntime {
    start_result: Mutex<Option<Result<SnapshotStreamStatus, SnapshotStreamRuntimeError>>>,
    statuses: Mutex<HashMap<u64, SnapshotStreamStatus>>,
    started: Mutex<Vec<(u64, NetworkPeerId)>>,
}

impl FakeSnapshotRuntime {
    fn new(
        start: Result<SnapshotStreamStatus, SnapshotStreamRuntimeError>,
        statuses: HashMap<u64, SnapshotStreamStatus>,
    ) -> Self {
        Self {
            start_result: Mutex::new(Some(start)),
            statuses: Mutex::new(statuses),
            started: Mutex::new(Vec::new()),
        }
    }

    fn record(&self) -> Vec<(u64, NetworkPeerId)> {
        self.started.lock().expect("start log lock").clone()
    }
}

#[async_trait]
impl SnapshotStreamRuntime for FakeSnapshotRuntime {
    async fn start_snapshot_stream(
        &self,
        session: u64,
        peer: NetworkPeerId,
        _root: String,
    ) -> Result<SnapshotStreamStatus, SnapshotStreamRuntimeError> {
        self.started
            .lock()
            .expect("start log lock")
            .push((session, peer.clone()));
        let mut result = self.start_result.lock().expect("start result lock");
        if let Some(outcome) = result.take() {
            outcome
        } else {
            self.statuses
                .lock()
                .expect("status lock")
                .get(&session)
                .cloned()
                .ok_or(SnapshotStreamRuntimeError::SessionNotFound(session))
        }
    }

    fn snapshot_stream_status(
        &self,
        session: u64,
    ) -> Option<SnapshotStreamStatus> {
        self.statuses
            .lock()
            .expect("status lock")
            .get(&session)
            .cloned()
    }
}

fn test_context(runtime: Arc<dyn SnapshotStreamRuntime>) -> ApiContext {
    ApiContext::new(
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
    .with_snapshot_runtime(runtime)
}

fn sample_status(session: u64, peer: &NetworkPeerId) -> SnapshotStreamStatus {
    SnapshotStreamStatus {
        session: SnapshotSessionId::new(session),
        peer: peer.clone(),
        root: "root-hash".to_string(),
        last_chunk_index: Some(4),
        last_update_index: Some(7),
        last_update_height: Some(128),
        verified: Some(true),
        error: None,
    }
}

#[tokio::test]
async fn start_snapshot_stream_returns_status() {
    let peer = NetworkPeerId::random();
    let session = 42u64;
    let status = sample_status(session, &peer);
    let runtime = Arc::new(FakeSnapshotRuntime::new(
        Ok(status.clone()),
        HashMap::from([(session, status.clone())]),
    ));
    let context = test_context(runtime.clone());
    let app = Router::new()
        .route("/p2p/snapshots", post(api::start_snapshot_stream))
        .with_state(context);

    let request = Request::builder()
        .method("POST")
        .uri("/p2p/snapshots")
        .header("content-type", "application/json")
        .body(
            Body::from(
                json!({
                    "peer": peer.to_string(),
                    "chunk_size": 16,
                })
                .to_string(),
            ),
        )
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body()).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["session"], session);
    assert_eq!(payload["peer"], peer.to_string());
    assert_eq!(payload["root"], status.root);
    assert_eq!(payload["last_chunk_index"], 4);
    assert_eq!(payload["last_update_index"], 7);
    assert_eq!(payload["last_update_height"], 128);
    assert_eq!(payload["verified"], true);
    assert!(payload["error"].is_null());

    let starts = runtime.record();
    assert_eq!(starts.len(), 1);
    assert_eq!(starts[0].0, session);
    assert_eq!(starts[0].1, peer);
}

#[tokio::test]
async fn start_snapshot_stream_propagates_error() {
    let peer = NetworkPeerId::random();
    let runtime = Arc::new(FakeSnapshotRuntime::new(
        Err(SnapshotStreamRuntimeError::Runtime(
            P2pNodeError::GossipDisabled,
        )),
        HashMap::new(),
    ));
    let context = test_context(runtime);
    let app = Router::new()
        .route("/p2p/snapshots", post(api::start_snapshot_stream))
        .with_state(context);

    let request = Request::builder()
        .method("POST")
        .uri("/p2p/snapshots")
        .header("content-type", "application/json")
        .body(
            Body::from(
                json!({
                    "peer": peer.to_string(),
                    "chunk_size": 32,
                })
                .to_string(),
            ),
        )
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body()).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "gossip propagation disabled");
}

#[tokio::test]
async fn snapshot_stream_status_returns_not_found() {
    let runtime = Arc::new(FakeSnapshotRuntime::new(Err(
        SnapshotStreamRuntimeError::SessionNotFound(7),
    ), HashMap::new()));
    let context = test_context(runtime);
    let app = Router::new()
        .route(
            "/p2p/snapshots/:id",
            get(api::snapshot_stream_status),
        )
        .with_state(context);

    let request = Request::builder()
        .uri("/p2p/snapshots/7")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = to_bytes(response.into_body()).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "snapshot session 7 not found");
}
