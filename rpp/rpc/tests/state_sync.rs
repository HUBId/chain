use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine as _;
use hex::encode;
use hyper::body::HttpBody;
use parking_lot::RwLock;
use rpp_chain::api::{
    state_sync_chunk_by_id, state_sync_head_stream, state_sync_session_status, ApiContext,
    StateSyncApi, StateSyncError, StateSyncErrorKind, StateSyncSessionInfo,
};
use rpp_chain::node::{LightClientVerificationEvent, DEFAULT_STATE_SYNC_CHUNK};
use blake3::Hash as Blake3Hash;
use rpp_chain::runtime::RuntimeMode;
use rpp_p2p::{LightClientHead, SnapshotChunk};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tower::ServiceExt;

struct FakeStateSyncApi {
    sender: watch::Sender<Option<LightClientHead>>,
    receiver: watch::Receiver<Option<LightClientHead>>,
    session: RwLock<Option<StateSyncSessionInfo>>,
    chunk_size: RwLock<Option<usize>>,
    chunks: HashMap<u32, SnapshotChunk>,
}

impl FakeStateSyncApi {
    fn new(
        sender: watch::Sender<Option<LightClientHead>>,
        receiver: watch::Receiver<Option<LightClientHead>>,
        session: Option<StateSyncSessionInfo>,
        chunk_size: Option<usize>,
        chunks: HashMap<u32, SnapshotChunk>,
    ) -> Self {
        Self {
            sender,
            receiver,
            session: RwLock::new(session),
            chunk_size: RwLock::new(chunk_size),
            chunks,
        }
    }

    fn sender(&self) -> watch::Sender<Option<LightClientHead>> {
        self.sender.clone()
    }
}

#[async_trait]
impl StateSyncApi for FakeStateSyncApi {
    fn watch_light_client_heads(
        &self,
    ) -> Result<watch::Receiver<Option<LightClientHead>>, StateSyncError> {
        Ok(self.receiver.clone())
    }

    fn latest_light_client_head(&self) -> Result<Option<LightClientHead>, StateSyncError> {
        Ok(self.receiver.borrow().clone())
    }

    fn ensure_state_sync_session(&self) -> Result<(), StateSyncError> {
        if self
            .session
            .read()
            .as_ref()
            .map(|session| session.verified)
            .unwrap_or(false)
        {
            Ok(())
        } else {
            Err(StateSyncError::new(
                StateSyncErrorKind::NoActiveSession,
                Some("no active session".into()),
            ))
        }
    }

    fn reset_state_sync_session(
        &self,
        root: Blake3Hash,
        chunk_size: usize,
        total_chunks: usize,
    ) {
        let mut session = self.session.write();
        let mut cached_size = self.chunk_size.write();
        let root_diverged = session
            .as_ref()
            .and_then(|info| info.root)
            .map(|current| current != root)
            .unwrap_or(false);
        let chunk_count_diverged = session
            .as_ref()
            .and_then(|info| info.total_chunks)
            .map(|count| count != total_chunks as u32)
            .unwrap_or(false);
        let chunk_size_diverged = cached_size
            .map(|size| size != chunk_size)
            .unwrap_or(false);

        if root_diverged || chunk_count_diverged || chunk_size_diverged {
            *session = None;
        }

        *cached_size = Some(chunk_size);
    }

    fn state_sync_active_session(&self) -> Result<StateSyncSessionInfo, StateSyncError> {
        self.session.read().clone().ok_or_else(|| {
            StateSyncError::new(
                StateSyncErrorKind::NoActiveSession,
                Some("no active session".into()),
            )
        })
    }

    async fn state_sync_chunk_by_index(&self, index: u32) -> Result<SnapshotChunk, StateSyncError> {
        self.chunks.get(&index).cloned().ok_or_else(|| {
            StateSyncError::new(
                StateSyncErrorKind::ChunkNotFound { index },
                Some(format!("chunk {index} missing")),
            )
        })
    }
}

fn test_context(api: Arc<dyn StateSyncApi>) -> ApiContext {
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
    .with_state_sync_api(api)
}

#[tokio::test]
async fn state_sync_head_stream_emits_events() {
    let (sender, receiver) = watch::channel::<Option<LightClientHead>>(None);
    let api = Arc::new(FakeStateSyncApi::new(
        sender.clone(),
        receiver,
        None,
        None,
        HashMap::new(),
    ));
    let context = test_context(api.clone());
    let app = Router::new()
        .route("/state-sync/head/stream", get(state_sync_head_stream))
        .with_state(context);

    let head = LightClientHead {
        height: 42,
        block_hash: "0xdeadbeef".to_string(),
        state_root: "0xabc".to_string(),
        proof_commitment: "0xdef".to_string(),
    };
    api.sender().send_replace(Some(head.clone()));

    let request = Request::builder()
        .uri("/state-sync/head/stream")
        .header("accept", "text/event-stream")
        .body(Body::empty())
        .unwrap();
    let mut response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.starts_with("text/event-stream"));

    let mut body = response.into_body();
    let first = body.data().await.unwrap().unwrap();
    let payload = std::str::from_utf8(&first).unwrap();
    assert!(payload.contains("\"height\":42"));
    assert!(payload.contains("head"));

    let next_head = LightClientHead { height: 43, ..head };
    api.sender().send_replace(Some(next_head));
    let second = body.data().await.unwrap().unwrap();
    let payload = std::str::from_utf8(&second).unwrap();
    assert!(payload.contains("\"height\":43"));
}

#[tokio::test]
async fn state_sync_chunk_by_id_returns_payload() {
    let payload = vec![1u8, 2, 3, 4];
    let root = blake3::hash(&payload);
    let progress_log = vec![
        "Loaded plan".to_string(),
        "Verification complete".to_string(),
    ];
    let chunk = SnapshotChunk {
        root,
        index: 0,
        total: 1,
        data: payload.clone(),
    };
    let mut chunks = HashMap::new();
    chunks.insert(0, chunk);
    let session = StateSyncSessionInfo {
        root: Some(root),
        total_chunks: Some(1),
        verified: true,
        last_completed_step: None,
        message: Some("verification complete".to_string()),
        served_chunks: vec![0],
        progress_log: progress_log.clone(),
    };
    let (sender, receiver) = watch::channel::<Option<LightClientHead>>(None);
    let api = Arc::new(FakeStateSyncApi::new(
        sender,
        receiver,
        Some(session),
        None,
        chunks,
    ));
    let context = test_context(api.clone());
    let app = Router::new()
        .route("/state-sync/chunk/:id", get(state_sync_chunk_by_id))
        .with_state(context);

    let request = Request::builder()
        .uri("/state-sync/chunk/0")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let chunk_json = json.get("chunk").unwrap();
    assert_eq!(chunk_json["index"], 0);
    assert_eq!(chunk_json["total"], 1);
    let encoded = chunk_json["payload"].as_str().unwrap();
    let decoded = BASE64_ENGINE.decode(encoded).unwrap();
    assert_eq!(decoded, payload);
    assert_eq!(chunk_json["length"], Value::from(payload.len() as u32));
    let expected_sha = format!("0x{}", encode(Sha256::digest(&payload)));
    assert_eq!(chunk_json["sha256"], Value::String(expected_sha));

    let status = json.get("status").unwrap();
    assert_eq!(
        status["root"],
        Value::String(format!("0x{}", encode(root.as_bytes())))
    );
    assert_eq!(status["total_chunks"], 1);
    assert_eq!(status["completed_chunks"], 1);
    assert_eq!(status["remaining_chunks"], 0);
    assert!(status["verified"].as_bool().unwrap());
    assert!(status["last_completed_step"].is_null());
    assert_eq!(status["last_error"], Value::String("verification complete".into()));
    assert_eq!(status["served_chunks"], Value::Array(vec![Value::from(0)]));
    let expected_log: Vec<Value> =
        progress_log.iter().cloned().map(Value::String).collect();
    assert_eq!(status["progress_log"], Value::Array(expected_log));

    let session_info = api.state_sync_active_session().unwrap();
    assert_eq!(session_info.root, Some(root));
    assert_eq!(session_info.total_chunks, Some(1));
    assert!(session_info.verified);
    assert_eq!(session_info.served_chunks, vec![0]);
    assert_eq!(session_info.progress_log, progress_log);
    assert_eq!(
        session_info.message.as_deref(),
        Some("verification complete")
    );
}

#[tokio::test]
async fn state_sync_session_status_returns_details() {
    let root = blake3::hash(b"session-root");
    let progress_log = vec!["Plan loaded".to_string(), "Chunks served".to_string()];
    let session = StateSyncSessionInfo {
        root: Some(root),
        total_chunks: Some(4),
        verified: true,
        last_completed_step: Some(LightClientVerificationEvent::PlanLoaded {
            snapshot_height: 42,
            chunk_count: 4,
            update_count: 2,
        }),
        message: Some("ready".to_string()),
        served_chunks: vec![0, 1],
        progress_log: progress_log.clone(),
    };
    let (sender, receiver) = watch::channel::<Option<LightClientHead>>(None);
    let api = Arc::new(FakeStateSyncApi::new(
        sender,
        receiver,
        Some(session),
        None,
        HashMap::new(),
    ));
    let context = test_context(api);
    let app = Router::new()
        .route("/state-sync/session", get(state_sync_session_status))
        .with_state(context);

    let request = Request::builder()
        .uri("/state-sync/session")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["total_chunks"], 4);
    assert_eq!(json["completed_chunks"], 2);
    assert_eq!(json["remaining_chunks"], 2);
    assert!(json["verified"].as_bool().unwrap());
    assert_eq!(
        json["root"],
        Value::String(format!("0x{}", encode(root.as_bytes())))
    );
    assert_eq!(json["last_error"], Value::String("ready".into()));
    assert_eq!(json["served_chunks"], Value::Array(vec![Value::from(0), Value::from(1)]));
    let expected_log: Vec<Value> =
        progress_log.iter().cloned().map(Value::String).collect();
    assert_eq!(json["progress_log"], Value::Array(expected_log));
    assert_eq!(
        json["last_completed_step"],
        Value::String(
            "plan loaded: snapshot height 42, 4 chunks, 2 updates".to_string(),
        )
    );
}

#[tokio::test]
async fn state_sync_session_status_returns_service_unavailable_without_session() {
    let (sender, receiver) = watch::channel::<Option<LightClientHead>>(None);
    let api = Arc::new(FakeStateSyncApi::new(
        sender,
        receiver,
        None,
        None,
        HashMap::new(),
    ));
    let context = test_context(api);
    let app = Router::new()
        .route("/state-sync/session", get(state_sync_session_status))
        .with_state(context);

    let request = Request::builder()
        .uri("/state-sync/session")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], Value::String("no active session".into()));
}

#[tokio::test]
async fn state_sync_chunk_by_id_out_of_range_returns_400() {
    let (sender, receiver) = watch::channel::<Option<LightClientHead>>(None);
    let session = StateSyncSessionInfo {
        root: Some(blake3::hash(&[0u8])),
        total_chunks: Some(1),
        verified: true,
        last_completed_step: None,
        message: None,
        served_chunks: Vec::new(),
        progress_log: Vec::new(),
    };
    let api = Arc::new(FakeStateSyncApi::new(
        sender,
        receiver,
        Some(session),
        None,
        HashMap::new(),
    ));
    let context = test_context(api.clone());
    let app = Router::new()
        .route("/state-sync/chunk/:id", get(state_sync_chunk_by_id))
        .with_state(context);

    let request = Request::builder()
        .uri("/state-sync/chunk/5")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let info = api.state_sync_active_session().unwrap();
    assert!(info.verified);
    assert_eq!(info.total_chunks, Some(1));
}

#[tokio::test]
async fn state_sync_session_reset_on_new_plan_metadata() {
    let root = blake3::hash(b"initial");
    let session = StateSyncSessionInfo {
        root: Some(root),
        total_chunks: Some(1),
        verified: true,
        last_completed_step: None,
        message: Some("verified".into()),
        served_chunks: vec![0],
        progress_log: vec!["complete".into()],
    };
    let (sender, receiver) = watch::channel::<Option<LightClientHead>>(None);
    let api = Arc::new(FakeStateSyncApi::new(
        sender,
        receiver,
        Some(session),
        Some(DEFAULT_STATE_SYNC_CHUNK),
        HashMap::new(),
    ));

    assert!(api.ensure_state_sync_session().is_ok());

    let new_root = blake3::hash(b"next");
    api.reset_state_sync_session(new_root, DEFAULT_STATE_SYNC_CHUNK, 2);

    let err = api.ensure_state_sync_session().unwrap_err();
    assert!(matches!(err.kind, StateSyncErrorKind::NoActiveSession));
    assert!(api.state_sync_active_session().is_err());
}
