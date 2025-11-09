use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Once};

use axum::body::Body;
use axum::extract::{Path as AxumPath, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::fs;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

const WORM_EXPORT_FAILURE_METRIC: &str = "worm_export_failures_total";
static WORM_FAILURE_REGISTER: Once = Once::new();

fn record_worm_export_failure(reason: &'static str) {
    WORM_FAILURE_REGISTER.call_once(|| {
        metrics::describe_counter!(
            WORM_EXPORT_FAILURE_METRIC,
            "Total number of WORM export stub failures observed during nightly verification",
        );
    });

    metrics::counter!(WORM_EXPORT_FAILURE_METRIC, "reason" => reason).increment(1);
}

#[derive(Parser, Debug)]
#[command(
    name = "worm-export-stub",
    version,
    about = "Append-only WORM export stub"
)]
struct Args {
    /// Listen address for the HTTP endpoint
    #[arg(long = "listen", default_value = "127.0.0.1:9700")]
    listen: SocketAddr,

    /// Directory for persisted objects and metadata
    #[arg(long = "storage", default_value = "./target/worm-export-stub")]
    storage: PathBuf,
}

#[derive(Clone)]
struct AppState {
    root: PathBuf,
    index: Arc<RwLock<Index>>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct Index {
    objects: BTreeMap<String, StoredObject>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StoredObject {
    bucket: String,
    key: String,
    stored_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retain_until: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retention_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    size_bytes: u64,
    sha256: String,
}

impl StoredObject {
    fn identifier(&self) -> String {
        format!("{}/{}", self.bucket, self.key)
    }
}

#[derive(Debug, Error)]
enum StubError {
    #[error("{0}")]
    Message(String),
    #[error("{0}")]
    NotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl StubError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Message(_) => StatusCode::BAD_REQUEST,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Io(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                StatusCode::CONFLICT
            }
            Self::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Serialization(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for StubError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = Json(serde_json::json!({
            "error": self.to_string(),
        }));
        (status, body).into_response()
    }
}

#[derive(Debug, Deserialize)]
struct ObjectPath {
    bucket: String,
    #[serde(default)]
    key: String,
}

struct NormalisedPath {
    identifier: String,
    relative: PathBuf,
    key: String,
}

#[tokio::main]
async fn main() -> Result<(), StubError> {
    let args = Args::parse();
    fs::create_dir_all(&args.storage).await?;
    let index = load_index(&args.storage).await?;
    let state = AppState {
        root: args.storage.clone(),
        index: Arc::new(RwLock::new(index)),
    };

    let app = Router::new()
        .route("/healthz", get(health))
        .route("/_objects", get(list_objects))
        .route("/:bucket/*key", put(put_object).get(get_object))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .map_err(|err| StubError::Message(format!("failed to bind {}: {err}", args.listen)))?;
    println!(
        "worm-export-stub listening on http://{} (storage: {})",
        args.listen,
        args.storage.display()
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|err| StubError::Message(format!("server error: {err}")))
}

async fn health() -> &'static str {
    "ok"
}

async fn list_objects(State(state): State<AppState>) -> Result<impl IntoResponse, StubError> {
    let index = state.index.read().await;
    let mut objects: Vec<StoredObject> = index.objects.values().cloned().collect();
    objects.sort_by(|a, b| a.identifier().cmp(&b.identifier()));
    Ok(Json(objects))
}

async fn get_object(
    AxumPath(ObjectPath { bucket, key }): AxumPath<ObjectPath>,
    State(state): State<AppState>,
) -> Result<Response, StubError> {
    let normalised = normalise(&bucket, &key).map_err(|err| {
        record_worm_export_failure("invalid_path");
        err
    })?;
    let absolute = state.root.join(&normalised.relative);
    let bytes = fs::read(&absolute).await.map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => {
            StubError::NotFound(format!("object {}/{} not found", bucket, normalised.key))
        }
        _ => StubError::Io(err),
    })?;

    let index = state.index.read().await;
    let metadata = index.objects.get(&normalised.identifier);
    let mut response = Response::builder().status(StatusCode::OK);
    if let Some(meta) = metadata {
        if let Some(content_type) = &meta.content_type {
            if let Ok(value) = HeaderValue::from_str(content_type) {
                response
                    .headers_mut()
                    .unwrap()
                    .insert("Content-Type", value);
            }
        }
        if let Ok(value) = HeaderValue::from_str(&format!("\"{}\"", meta.sha256)) {
            response.headers_mut().unwrap().insert("ETag", value);
        }
    }
    response
        .body(Body::from(bytes))
        .map_err(|err| StubError::Message(format!("build response: {err}")))
}

async fn put_object(
    AxumPath(ObjectPath { bucket, key }): AxumPath<ObjectPath>,
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Response, StubError> {
    let normalised = normalise(&bucket, &key)?;
    let absolute = state.root.join(&normalised.relative);
    if let Some(parent) = absolute.parent() {
        fs::create_dir_all(parent).await.map_err(|err| {
            record_worm_export_failure("create_dir");
            err
        })?;
    }

    let mut hasher = Sha256::new();
    hasher.update(&body);
    let digest = hex::encode(hasher.finalize());
    let size_bytes = body.len() as u64;

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&absolute)
        .await
        .map_err(|err| {
            record_worm_export_failure("open_file");
            err
        })?;
    file.write_all(&body).await.map_err(|err| {
        record_worm_export_failure("write_body");
        err
    })?;
    file.flush().await.map_err(|err| {
        record_worm_export_failure("flush_body");
        err
    })?;

    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|err| StubError::Message(format!("format timestamp: {err}")))?;
    let retain_until = headers
        .get("x-amz-object-lock-retain-until-date")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let retention_mode = headers
        .get("x-amz-object-lock-mode")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string());

    let stored = StoredObject {
        bucket: bucket.clone(),
        key: normalised.key.clone(),
        stored_at: now,
        retain_until,
        retention_mode,
        content_type,
        size_bytes,
        sha256: digest,
    };

    persist_object(&state, stored.clone()).await?;

    let mut response = Response::builder().status(StatusCode::CREATED);
    if let Ok(value) = HeaderValue::from_str(&format!("\"{}\"", stored.sha256)) {
        response.headers_mut().unwrap().insert("ETag", value);
    }
    response.headers_mut().unwrap().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let payload = serde_json::to_vec(&stored).map_err(|err| {
        record_worm_export_failure("serialize_response");
        err
    })?;
    response
        .body(Body::from(payload))
        .map_err(|err| StubError::Message(format!("build response: {err}")))
}

async fn persist_object(state: &AppState, object: StoredObject) -> Result<(), StubError> {
    let mut index = state.index.write().await;
    index.objects.insert(object.identifier(), object.clone());
    let snapshot = index.clone();
    drop(index);

    let serialized = serde_json::to_vec_pretty(&snapshot).map_err(|err| {
        record_worm_export_failure("serialize_index");
        err
    })?;
    let tmp = state.root.join("index.json.tmp");
    let target = state.root.join("index.json");
    fs::write(&tmp, &serialized).await.map_err(|err| {
        record_worm_export_failure("write_index");
        err
    })?;
    fs::rename(tmp, target).await.map_err(|err| {
        record_worm_export_failure("rotate_index");
        err
    })?;
    Ok(())
}

async fn load_index(root: &Path) -> Result<Index, StubError> {
    let path = root.join("index.json");
    if !path.exists() {
        return Ok(Index::default());
    }
    let bytes = fs::read(path).await.map_err(|err| {
        record_worm_export_failure("read_index");
        err
    })?;
    if bytes.is_empty() {
        return Ok(Index::default());
    }
    let index: Index = serde_json::from_slice(&bytes).map_err(|err| {
        record_worm_export_failure("parse_index");
        err
    })?;
    Ok(index)
}

fn normalise(bucket: &str, raw_key: &str) -> Result<NormalisedPath, StubError> {
    let trimmed_bucket = bucket.trim();
    if trimmed_bucket.is_empty() {
        return Err(StubError::Message("bucket must not be empty".into()));
    }
    if trimmed_bucket.contains('/') || trimmed_bucket.contains('\\') {
        return Err(StubError::Message(
            "bucket name must not contain path separators".into(),
        ));
    }

    let mut relative = PathBuf::new();
    relative.push(trimmed_bucket);

    let mut segments: Vec<String> = Vec::new();
    for segment in raw_key.split('/') {
        if segment.is_empty() {
            continue;
        }
        if matches!(segment, "." | "..") {
            return Err(StubError::Message(
                "object key must not contain '.' or '..' segments".into(),
            ));
        }
        if segment.contains('\\') {
            return Err(StubError::Message(
                "object key must not contain backslashes".into(),
            ));
        }
        segments.push(segment.to_string());
        relative.push(segment);
    }

    if segments.is_empty() {
        return Err(StubError::Message("object key must not be empty".into()));
    }

    if !is_safe_relative_path(&relative) {
        return Err(StubError::Message(
            "object path escapes storage root".into(),
        ));
    }

    let key = segments.join("/");
    let identifier = format!("{}/{}", trimmed_bucket, key);
    Ok(NormalisedPath {
        identifier,
        relative,
        key,
    })
}

fn is_safe_relative_path(path: &Path) -> bool {
    path.components()
        .all(|component| matches!(component, Component::Normal(_)))
}
