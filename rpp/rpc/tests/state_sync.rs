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
use hyper::body::HttpBody;
use parking_lot::RwLock;
use rpp_chain::api::{
    state_sync_chunk_by_id, state_sync_head_stream, ApiContext, StateSyncApi, StateSyncError,
    StateSyncErrorKind, StateSyncSessionInfo,
};
use rpp_chain::runtime::RuntimeMode;
use rpp_p2p::{LightClientHead, SnapshotChunk};
use serde_json::Value;
use tokio::sync::watch;
use tower::ServiceExt;

struct FakeStateSyncApi {
    sender: watch::Sender<Option<LightClientHead>>,
    receiver: watch::Receiver<Option<LightClientHead>>,
    session: Option<StateSyncSessionInfo>,
    chunks: HashMap<u32, SnapshotChunk>,
}

impl FakeStateSyncApi {
    fn new(
        sender: watch::Sender<Option<LightClientHead>>,
        receiver: watch::Receiver<Option<LightClientHead>>,
        session: Option<StateSyncSessionInfo>,
        chunks: HashMap<u32, SnapshotChunk>,
    ) -> Self {
        Self {
            sender,
            receiver,
            session,
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

    fn state_sync_active_session(&self) -> Result<StateSyncSessionInfo, StateSyncError> {
        self.session.clone().ok_or_else(|| {
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
    assert_eq!(json["index"], 0);
    assert_eq!(json["total"], 1);
    let encoded = json["payload"].as_str().unwrap();
    let decoded = BASE64_ENGINE.decode(encoded).unwrap();
    assert_eq!(decoded, payload);

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
