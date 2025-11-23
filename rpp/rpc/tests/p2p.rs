use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{delete, get, post},
    Router,
};
use hyper::body::to_bytes;
use parking_lot::RwLock;
use rpp_chain::api::{self, ApiContext, SnapshotStreamRuntime, SnapshotStreamRuntimeError};
use rpp_chain::runtime::config::DEFAULT_SNAPSHOT_MAX_CONCURRENT_CHUNK_DOWNLOADS;
use rpp_chain::runtime::node_runtime::node::{NodeError as P2pNodeError, SnapshotStreamStatus};
use rpp_chain::runtime::RuntimeMode;
use rpp_p2p::{vendor::PeerId as NetworkPeerId, PipelineError, SnapshotSessionId};
use serde_json::json;
use tower::ServiceExt;

struct FakeSnapshotRuntime {
    start_result: Mutex<Option<Result<SnapshotStreamStatus, SnapshotStreamRuntimeError>>>,
    resume_result: Mutex<Option<Result<SnapshotStreamStatus, SnapshotStreamRuntimeError>>>,
    statuses: Mutex<HashMap<u64, SnapshotStreamStatus>>,
    started: Mutex<Vec<(u64, NetworkPeerId, u64, usize)>>,
    resumed: Mutex<Vec<(u64, String)>>,
}

impl FakeSnapshotRuntime {
    fn new(
        start: Result<SnapshotStreamStatus, SnapshotStreamRuntimeError>,
        statuses: HashMap<u64, SnapshotStreamStatus>,
    ) -> Self {
        Self {
            start_result: Mutex::new(Some(start)),
            resume_result: Mutex::new(None),
            statuses: Mutex::new(statuses),
            started: Mutex::new(Vec::new()),
            resumed: Mutex::new(Vec::new()),
        }
    }

    fn record(&self) -> Vec<(u64, NetworkPeerId, u64, usize)> {
        self.started.lock().expect("start log lock").clone()
    }

    fn resume_record(&self) -> Vec<(u64, String)> {
        self.resumed.lock().expect("resume log lock").clone()
    }
}

#[async_trait]
impl SnapshotStreamRuntime for FakeSnapshotRuntime {
    async fn start_snapshot_stream(
        &self,
        session: u64,
        peer: NetworkPeerId,
        _root: String,
        chunk_size: u64,
        max_concurrent_downloads: usize,
    ) -> Result<SnapshotStreamStatus, SnapshotStreamRuntimeError> {
        self.started.lock().expect("start log lock").push((
            session,
            peer.clone(),
            chunk_size,
            max_concurrent_downloads,
        ));
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

    async fn resume_snapshot_stream(
        &self,
        session: u64,
        plan_id: String,
        _chunk_size: Option<u64>,
        _max_concurrent_downloads: usize,
    ) -> Result<SnapshotStreamStatus, SnapshotStreamRuntimeError> {
        self.resumed
            .lock()
            .expect("resume log lock")
            .push((session, plan_id));
        let mut result = self.resume_result.lock().expect("resume result lock");
        if let Some(outcome) = result.take() {
            outcome
        } else {
            self.snapshot_stream_status(session)
                .ok_or(SnapshotStreamRuntimeError::SessionNotFound(session))
        }
    }

    fn snapshot_stream_status(&self, session: u64) -> Option<SnapshotStreamStatus> {
        self.statuses
            .lock()
            .expect("status lock")
            .get(&session)
            .cloned()
    }

    async fn cancel_snapshot_stream(&self, session: u64) -> Result<(), SnapshotStreamRuntimeError> {
        let mut statuses = self.statuses.lock().expect("status lock");
        if statuses.remove(&session).is_some() {
            Ok(())
        } else {
            Err(SnapshotStreamRuntimeError::SessionNotFound(session))
        }
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
        chunk_size: Some(16),
        requested_chunk_size: Some(16),
        min_chunk_size: Some(8),
        max_chunk_size: Some(32),
        plan_id: Some("plan-id".to_string()),
        last_chunk_index: Some(4),
        last_update_index: Some(7),
        last_update_height: Some(128),
        verified: Some(true),
        error_code: None,
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
        .body(Body::from(
            json!({
                "peer": peer.to_string(),
                "requested_chunk_size": 16,
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body()).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["session"], session);
    assert_eq!(payload["peer"], peer.to_string());
    assert_eq!(payload["root"], status.root);
    assert_eq!(payload["chunk_size"], 16);
    assert_eq!(payload["negotiated_chunk_size"], 16);
    assert_eq!(payload["requested_chunk_size"], 16);
    assert_eq!(payload["min_chunk_size"], 8);
    assert_eq!(payload["max_chunk_size"], 32);
    assert_eq!(payload["last_chunk_index"], 4);
    assert_eq!(payload["last_update_index"], 7);
    assert_eq!(payload["last_update_height"], 128);
    assert_eq!(payload["verified"], true);
    assert!(payload["error"].is_null());

    let starts = runtime.record();
    assert_eq!(starts.len(), 1);
    assert_eq!(starts[0].0, session);
    assert_eq!(starts[0].1, peer);
    assert_eq!(starts[0].2, 16);
    assert_eq!(starts[0].3, DEFAULT_SNAPSHOT_MAX_CONCURRENT_CHUNK_DOWNLOADS);
}

#[tokio::test]
async fn snapshot_breaker_routes_require_node() {
    let peer = NetworkPeerId::random();
    let session = 7u64;
    let runtime = Arc::new(FakeSnapshotRuntime::new(
        Ok(sample_status(session, &peer)),
        HashMap::new(),
    ));
    let context = test_context(runtime);
    let app = Router::new()
        .route("/p2p/snapshots/breaker", get(api::snapshot_breaker_status))
        .route(
            "/p2p/snapshots/breaker/reset",
            post(api::reset_snapshot_breaker),
        )
        .with_state(context);

    let status_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/p2p/snapshots/breaker")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status_response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let reset_response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/p2p/snapshots/breaker/reset")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reset_response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn resume_snapshot_stream_returns_status() {
    let peer = NetworkPeerId::random();
    let session = 17u64;
    let status = sample_status(session, &peer);
    let runtime = Arc::new(FakeSnapshotRuntime::new(
        Err(SnapshotStreamRuntimeError::SessionNotFound(session)),
        HashMap::from([(session, status.clone())]),
    ));
    *runtime.resume_result.lock().expect("resume result lock") = Some(Ok(status.clone()));

    let context = test_context(runtime.clone());
    let app = Router::new()
        .route("/p2p/snapshots", post(api::start_snapshot_stream))
        .with_state(context);

    let request = Request::builder()
        .method("POST")
        .uri("/p2p/snapshots")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "peer": peer.to_string(),
                "requested_chunk_size": 16,
                "resume": {
                    "session": session,
                    "plan_id": status.plan_id.clone().unwrap(),
                }
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body()).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["session"], session);
    assert_eq!(payload["peer"], peer.to_string());
    assert_eq!(payload["root"], status.root);
    assert_eq!(payload["plan_id"], status.plan_id.unwrap());
    assert_eq!(payload["negotiated_chunk_size"], 16);
    assert_eq!(payload["requested_chunk_size"], 16);
    assert_eq!(payload["last_chunk_index"], 4);
    assert_eq!(payload["last_update_index"], 7);
    assert_eq!(payload["last_update_height"], 128);
    assert_eq!(payload["verified"], true);
    assert!(payload["error"].is_null());

    let starts = runtime.record();
    assert!(starts.is_empty(), "start should not be invoked for resume");
    let resumes = runtime.resume_record();
    assert_eq!(resumes, vec![(session, "plan-id".to_string())]);
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
        .body(Body::from(
            json!({
                "peer": peer.to_string(),
                "chunk_size": 32,
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body()).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["error"], "gossip propagation disabled");
}

#[tokio::test]
async fn start_snapshot_stream_sets_download_error_codes() {
    let peer = NetworkPeerId::random();
    let checksum_runtime = Arc::new(FakeSnapshotRuntime::new(
        Err(SnapshotStreamRuntimeError::Runtime(P2pNodeError::Pipeline(
            PipelineError::SnapshotVerification("checksum mismatch".into()),
        ))),
        HashMap::new(),
    ));
    let resume_runtime = Arc::new(FakeSnapshotRuntime::new(
        Err(SnapshotStreamRuntimeError::Runtime(P2pNodeError::Pipeline(
            PipelineError::SnapshotVerification(
                "resume plan id abc does not match persisted plan def".into(),
            ),
        ))),
        HashMap::new(),
    ));

    let checksum_app = Router::new()
        .route("/p2p/snapshots", post(api::start_snapshot_stream))
        .with_state(test_context(checksum_runtime));
    let resume_app = Router::new()
        .route("/p2p/snapshots", post(api::start_snapshot_stream))
        .with_state(test_context(resume_runtime));

    let checksum_request = Request::builder()
        .method("POST")
        .uri("/p2p/snapshots")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "peer": peer.to_string(),
                "chunk_size": 32,
            })
            .to_string(),
        ))
        .unwrap();

    let resume_request = Request::builder()
        .method("POST")
        .uri("/p2p/snapshots")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "peer": peer.to_string(),
                "chunk_size": 32,
            })
            .to_string(),
        ))
        .unwrap();

    let checksum_response = checksum_app.oneshot(checksum_request).await.unwrap();
    assert_eq!(checksum_response.status(), StatusCode::BAD_GATEWAY);
    let checksum_body = to_bytes(checksum_response.into_body()).await.unwrap();
    let checksum_payload: serde_json::Value = serde_json::from_slice(&checksum_body).unwrap();
    assert_eq!(checksum_payload["download_error"], "checksum");
    assert_eq!(
        checksum_payload["code"],
        serde_json::Value::String("state_sync_pipeline_error".to_string())
    );

    let resume_response = resume_app.oneshot(resume_request).await.unwrap();
    assert_eq!(resume_response.status(), StatusCode::BAD_GATEWAY);
    let resume_body = to_bytes(resume_response.into_body()).await.unwrap();
    let resume_payload: serde_json::Value = serde_json::from_slice(&resume_body).unwrap();
    assert_eq!(resume_payload["download_error"], "resume_mismatch");
}

#[tokio::test]
async fn snapshot_stream_status_returns_not_found() {
    let runtime = Arc::new(FakeSnapshotRuntime::new(
        Err(SnapshotStreamRuntimeError::SessionNotFound(7)),
        HashMap::new(),
    ));
    let context = test_context(runtime);
    let app = Router::new()
        .route("/p2p/snapshots/:id", get(api::snapshot_stream_status))
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

#[tokio::test]
async fn cancel_snapshot_stream_removes_session() {
    let peer = NetworkPeerId::random();
    let session = 11u64;
    let status = sample_status(session, &peer);
    let runtime = Arc::new(FakeSnapshotRuntime::new(
        Ok(status.clone()),
        HashMap::from([(session, status)]),
    ));
    let context = test_context(runtime);
    let app = Router::new()
        .route("/p2p/snapshots/:id", delete(api::cancel_snapshot_stream))
        .with_state(context);

    let request = Request::builder()
        .method("DELETE")
        .uri("/p2p/snapshots/11")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}
