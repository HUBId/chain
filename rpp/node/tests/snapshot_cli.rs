use std::collections::HashMap;
use std::net::TcpListener;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use assert_cmd::Command as AssertCommand;
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router, Server,
};
use predicates::str::contains;
use rpp_chain::config::NodeConfig;
use rpp_node::RuntimeMode;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

const TEST_TOKEN: &str = "test-token";
const SESSION_ID: u64 = 42;
const SNAPSHOT_ROOT: &str = "deadbeefcafebabe";

#[derive(Clone)]
struct SnapshotServerState {
    expected_token: String,
    statuses: Arc<Mutex<HashMap<u64, SnapshotStatusPayload>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SnapshotStatusPayload {
    session: u64,
    peer: String,
    root: String,
    #[serde(default)]
    last_chunk_index: Option<u64>,
    #[serde(default)]
    last_update_index: Option<u64>,
    #[serde(default)]
    last_update_height: Option<u64>,
    #[serde(default)]
    verified: Option<bool>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StartRequest {
    peer: String,
    chunk_size: u32,
    #[serde(default)]
    resume: Option<ResumeMarker>,
}

#[derive(Debug, Deserialize)]
struct ResumeMarker {
    session: u64,
}

struct SnapshotTestServer {
    addr: std::net::SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl SnapshotTestServer {
    fn port(&self) -> u16 {
        self.addr.port()
    }

    async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.task.await;
    }
}

static INIT_LOGGER: OnceLock<()> = OnceLock::new();

#[tokio::test]
async fn snapshot_cli_happy_path() -> Result<()> {
    init_logger();
    let server = spawn_snapshot_server().context("failed to launch snapshot test server")?;
    let temp = TempDir::new().context("failed to create temp directory")?;
    let config_path = temp.path().join("validator.toml");
    write_validator_config(&config_path, server.port())?;

    let peer = "12D3KooWE6snapshotPeer";

    AssertCommand::cargo_bin("rpp-node")?
        .arg("validator")
        .arg("snapshot")
        .arg("start")
        .arg("--config")
        .arg(&config_path)
        .arg("--peer")
        .arg(peer)
        .assert()
        .success()
        .stdout(contains("snapshot session started:"))
        .stdout(contains(format!("session: {SESSION_ID}")))
        .stdout(contains(format!("peer: {peer}")))
        .stdout(contains(format!("root: {SNAPSHOT_ROOT}")))
        .stdout(contains("last_chunk_index: none"))
        .stdout(contains("last_update_index: none"))
        .stdout(contains("verified: unknown"))
        .stdout(contains("error: none"));

    AssertCommand::cargo_bin("rpp-node")?
        .arg("validator")
        .arg("snapshot")
        .arg("status")
        .arg("--config")
        .arg(&config_path)
        .arg("--session")
        .arg(SESSION_ID.to_string())
        .assert()
        .success()
        .stdout(contains("snapshot status:"))
        .stdout(contains("last_chunk_index: none"));

    AssertCommand::cargo_bin("rpp-node")?
        .arg("validator")
        .arg("snapshot")
        .arg("resume")
        .arg("--config")
        .arg(&config_path)
        .arg("--session")
        .arg(SESSION_ID.to_string())
        .arg("--peer")
        .arg(peer)
        .arg("--chunk-size")
        .arg("4096")
        .assert()
        .success()
        .stdout(contains("snapshot session resumed:"))
        .stdout(contains("last_chunk_index: 12"))
        .stdout(contains("last_update_index: 3"))
        .stdout(contains("verified: false"));

    AssertCommand::cargo_bin("rpp-node")?
        .arg("validator")
        .arg("snapshot")
        .arg("cancel")
        .arg("--config")
        .arg(&config_path)
        .arg("--session")
        .arg(SESSION_ID.to_string())
        .assert()
        .success()
        .stdout(contains(format!("snapshot session {SESSION_ID} cancelled")));

    server.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn snapshot_cli_propagates_errors() -> Result<()> {
    init_logger();
    let server = spawn_error_server().context("failed to launch error server")?;
    let temp = TempDir::new().context("failed to create temp directory")?;
    let config_path = temp.path().join("validator.toml");
    write_validator_config(&config_path, server.port())?;

    AssertCommand::cargo_bin("rpp-node")?
        .arg("validator")
        .arg("snapshot")
        .arg("start")
        .arg("--config")
        .arg(&config_path)
        .arg("--peer")
        .arg("12D3errorPeer")
        .assert()
        .failure()
        .stderr(contains("RPC returned 500"));

    server.shutdown().await;
    Ok(())
}

fn init_logger() {
    let _ = INIT_LOGGER.get_or_init(|| {
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter("info")
            .try_init();
    });
}

fn write_validator_config(path: &Path, port: u16) -> Result<()> {
    let mut config = NodeConfig::for_mode(RuntimeMode::Validator);
    config.network.rpc.listen = format!("127.0.0.1:{port}")
        .parse()
        .context("failed to parse RPC listen address")?;
    config.network.rpc.auth_token = Some(TEST_TOKEN.to_string());
    config
        .save(path)
        .with_context(|| format!("failed to persist validator config to {}", path.display()))
}

fn authorize(headers: &HeaderMap, token: &str) {
    let expected = format!("Bearer {token}");
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    assert_eq!(
        header.as_deref(),
        Some(expected.as_str()),
        "missing authorization header"
    );
}

fn spawn_snapshot_server() -> Result<SnapshotTestServer> {
    let state = SnapshotServerState {
        expected_token: TEST_TOKEN.to_string(),
        statuses: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/p2p/snapshots", post(start_snapshot))
        .route(
            "/p2p/snapshots/:id",
            get(snapshot_status).delete(cancel_snapshot),
        )
        .with_state(state);

    launch_server(app)
}

fn spawn_error_server() -> Result<SnapshotTestServer> {
    let app = Router::new()
        .route("/p2p/snapshots", post(start_snapshot_error))
        .route(
            "/p2p/snapshots/:id",
            get(snapshot_status_error).delete(cancel_snapshot_error),
        );
    launch_server(app)
}

fn launch_server(app: Router) -> Result<SnapshotTestServer> {
    let listener = TcpListener::bind("127.0.0.1:0").context("failed to bind test listener")?;
    listener
        .set_nonblocking(true)
        .context("failed to enable non-blocking listener")?;
    let addr = listener
        .local_addr()
        .context("failed to read listener address")?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = Server::from_tcp(listener)
        .context("failed to build axum server")?
        .serve(app.into_make_service())
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        });
    let task = tokio::spawn(async move {
        let _ = server.await;
    });
    Ok(SnapshotTestServer {
        addr,
        shutdown: shutdown_tx,
        task,
    })
}

async fn start_snapshot(
    State(state): State<SnapshotServerState>,
    headers: HeaderMap,
    Json(request): Json<StartRequest>,
) -> Result<Json<SnapshotStatusPayload>, StatusCode> {
    authorize(&headers, &state.expected_token);
    let session = request
        .resume
        .as_ref()
        .map(|marker| marker.session)
        .unwrap_or(SESSION_ID);
    let mut statuses = state.statuses.lock().await;
    let status = if let Some(resume) = request.resume {
        let entry = statuses
            .get_mut(&resume.session)
            .ok_or(StatusCode::NOT_FOUND)?;
        entry.last_chunk_index = Some(12);
        entry.last_update_index = Some(3);
        entry.last_update_height = Some(256);
        entry.verified = Some(false);
        entry.clone()
    } else {
        let status = SnapshotStatusPayload {
            session,
            peer: request.peer,
            root: SNAPSHOT_ROOT.to_string(),
            last_chunk_index: None,
            last_update_index: None,
            last_update_height: None,
            verified: None,
            error: None,
        };
        statuses.insert(session, status.clone());
        status
    };
    Ok(Json(status))
}

async fn snapshot_status(
    State(state): State<SnapshotServerState>,
    AxumPath(id): AxumPath<u64>,
    headers: HeaderMap,
) -> Result<Json<SnapshotStatusPayload>, StatusCode> {
    authorize(&headers, &state.expected_token);
    let statuses = state.statuses.lock().await;
    let status = statuses.get(&id).cloned().ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(status))
}

async fn cancel_snapshot(
    State(state): State<SnapshotServerState>,
    AxumPath(id): AxumPath<u64>,
    headers: HeaderMap,
) -> Result<StatusCode, StatusCode> {
    authorize(&headers, &state.expected_token);
    let mut statuses = state.statuses.lock().await;
    if statuses.remove(&id).is_some() {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn start_snapshot_error(
    headers: HeaderMap,
    Json(_): Json<StartRequest>,
) -> (StatusCode, &'static str) {
    authorize(&headers, TEST_TOKEN);
    (StatusCode::INTERNAL_SERVER_ERROR, "intentional failure")
}

async fn snapshot_status_error(
    headers: HeaderMap,
    AxumPath(_): AxumPath<u64>,
) -> Result<Json<SnapshotStatusPayload>, StatusCode> {
    authorize(&headers, TEST_TOKEN);
    Err(StatusCode::NOT_FOUND)
}

async fn cancel_snapshot_error(
    headers: HeaderMap,
    AxumPath(_): AxumPath<u64>,
) -> Result<StatusCode, StatusCode> {
    authorize(&headers, TEST_TOKEN);
    Ok(StatusCode::NO_CONTENT)
}
