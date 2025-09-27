use std::time::{Duration, SystemTime};

use log::{error, info, warn};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use serde_json::json;
use tokio::sync::mpsc;

use crate::config::TelemetryConfig;

const TELEMETRY_CHANNEL_CAPACITY: usize = 128;

/// Snapshot of runtime telemetry data that is exported to remote collectors.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TelemetrySnapshot {
    /// Current block height of the node.
    pub block_height: u64,
    /// Hash of the latest block.
    pub block_hash: String,
    /// Total number of transactions seen within the current reporting window.
    pub transaction_count: usize,
    /// Number of currently connected peers.
    pub peer_count: usize,
    /// Identifier of the node emitting the snapshot (usually the libp2p peer id).
    pub node_id: String,
    /// Reputation score of the node as calculated by the local reputation subsystem.
    pub reputation_score: f64,
    /// Timestamp of the snapshot on the local node.
    pub timestamp: SystemTime,
}

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("telemetry channel closed")]
    ChannelClosed,
}

#[derive(Debug)]
enum TelemetryMessage {
    Snapshot(TelemetrySnapshot),
    Shutdown,
}

/// Handle that allows producers to submit telemetry snapshots.
#[derive(Clone)]
pub struct TelemetryHandle {
    sender: mpsc::Sender<TelemetryMessage>,
}

impl TelemetryHandle {
    /// Spawns a telemetry worker and returns a handle for submitting snapshots.
    pub fn spawn(config: TelemetryConfig) -> Self {
        let (sender, receiver) = mpsc::channel(TELEMETRY_CHANNEL_CAPACITY);
        let worker = TelemetryWorker::new(config, receiver);
        tokio::spawn(async move {
            worker.run().await;
        });
        Self { sender }
    }

    /// Sends a snapshot to the telemetry worker.
    pub async fn send(&self, snapshot: TelemetrySnapshot) -> Result<(), TelemetryError> {
        self.sender
            .send(TelemetryMessage::Snapshot(snapshot))
            .await
            .map_err(|_| TelemetryError::ChannelClosed)
    }

    /// Gracefully shuts down the telemetry worker.
    pub async fn shutdown(&self) -> Result<(), TelemetryError> {
        self.sender
            .send(TelemetryMessage::Shutdown)
            .await
            .map_err(|_| TelemetryError::ChannelClosed)
    }
}

struct TelemetryWorker {
    config: TelemetryConfig,
    client: Client,
    receiver: mpsc::Receiver<TelemetryMessage>,
}

impl TelemetryWorker {
    fn new(config: TelemetryConfig, receiver: mpsc::Receiver<TelemetryMessage>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms.max(1)))
            .build()
            .expect("reqwest client");
        Self {
            config,
            client,
            receiver,
        }
    }

    async fn run(mut self) {
        while let Some(message) = self.receiver.recv().await {
            match message {
                TelemetryMessage::Snapshot(snapshot) => {
                    self.process_snapshot(snapshot).await;
                }
                TelemetryMessage::Shutdown => break,
            }
        }
    }

    async fn process_snapshot(&self, snapshot: TelemetrySnapshot) {
        if !self.config.enabled {
            self.log_minimal_snapshot("telemetry disabled", &snapshot);
            return;
        }

        match self.config.endpoint.as_deref() {
            Some(endpoint) if !endpoint.is_empty() => {
                if let Err(err) = self.dispatch_http(endpoint, &snapshot).await {
                    warn!(
                        target: "telemetry",
                        "telemetry HTTP dispatch failed: {err}"
                    );
                    self.log_snapshot("http dispatch failed", &snapshot);
                }
            }
            _ => {
                self.log_snapshot("no endpoint configured", &snapshot);
            }
        }
    }

    fn log_snapshot(&self, reason: &str, snapshot: &TelemetrySnapshot) {
        self.log_snapshot_internal(reason, snapshot, self.config.redact_logs);
    }

    fn log_minimal_snapshot(&self, reason: &str, snapshot: &TelemetrySnapshot) {
        self.log_snapshot_internal(reason, snapshot, true);
    }

    fn log_snapshot_internal(&self, reason: &str, snapshot: &TelemetrySnapshot, redacted: bool) {
        let payload = if redacted {
            json!({
                "reason": reason,
                "telemetry": {
                    "block_height": snapshot.block_height,
                    "transaction_count": snapshot.transaction_count,
                    "peer_count": snapshot.peer_count,
                }
            })
        } else {
            json!({
                "reason": reason,
                "telemetry": snapshot,
            })
        };

        match serde_json::to_string(&payload) {
            Ok(payload) => {
                info!(
                    target: "telemetry",
                    "{payload}"
                );
            }
            Err(err) => {
                error!(target: "telemetry", "failed to encode telemetry snapshot: {err}");
            }
        }
    }

    async fn dispatch_http(
        &self,
        endpoint: &str,
        snapshot: &TelemetrySnapshot,
    ) -> Result<(), TelemetryDispatchError> {
        let mut last_err = None;
        for attempt in 0..=self.config.retry_max {
            let mut request = self.client.post(endpoint).json(snapshot);
            if let Some(token) = &self.config.auth_token {
                request = request.header("Authorization", format!("Bearer {token}"));
            }
            match request.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        return Ok(());
                    }
                    let status = response.status();
                    let body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "<body unavailable>".to_string());
                    last_err = Some(TelemetryDispatchError::Status(status, body));
                }
                Err(err) => last_err = Some(TelemetryDispatchError::Request(err)),
            }

            if attempt < self.config.retry_max {
                let exponent = attempt.min(16); // prevent overflow on very high retry counts
                let multiplier = 1u64 << exponent;
                let delay_ms = self.config.timeout_ms.saturating_mul(multiplier).max(1);
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
        }

        Err(last_err.unwrap_or_else(|| {
            TelemetryDispatchError::Status(StatusCode::INTERNAL_SERVER_ERROR, "unknown".into())
        }))
    }
}

#[derive(Debug, thiserror::Error)]
enum TelemetryDispatchError {
    #[error("request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("endpoint responded with {0}: {1}")]
    Status(StatusCode, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::routing::post;
    use axum::{Json, Router};
    use serde_json::Value;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::OnceLock;
    use tokio::sync::oneshot;
    use tokio::time::{Duration as TokioDuration, sleep};

    #[tokio::test]
    async fn disabled_configuration_only_logs() {
        let logger = init_test_logger();
        logger.drain();
        let (addr, counter, shutdown) = spawn_test_server().await;
        let config = TelemetryConfig {
            enabled: false,
            endpoint: Some(format!("http://{addr}")),
            auth_token: None,
            timeout_ms: 50,
            retry_max: 2,
            sample_interval_secs: 1,
            redact_logs: true,
        };
        let handle = TelemetryHandle::spawn(config);
        let snapshot = sample_snapshot();

        handle.send(snapshot).await.expect("snapshot queued");
        sleep(TokioDuration::from_millis(200)).await;

        assert_eq!(counter.lock().unwrap().len(), 0);
        let logs = logger.drain().join("\n");
        assert!(logs.contains("\"reason\":\"telemetry disabled\""));
        assert!(!logs.contains("node-1"));
        assert!(!logs.contains("0xdeadbeef"));
        assert!(!logs.contains("block_hash"));
        handle.shutdown().await.expect("shutdown");
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn enabled_configuration_posts_json_payload() {
        let (addr, counter, shutdown) = spawn_test_server().await;
        let endpoint = format!("http://{addr}");
        let config = TelemetryConfig {
            enabled: true,
            endpoint: Some(endpoint.clone()),
            auth_token: Some("token-123".into()),
            timeout_ms: 100,
            retry_max: 1,
            sample_interval_secs: 1,
            redact_logs: false,
        };
        let handle = TelemetryHandle::spawn(config);
        let snapshot = sample_snapshot();

        handle
            .send(snapshot.clone())
            .await
            .expect("snapshot queued");

        tokio::time::timeout(TokioDuration::from_secs(2), async {
            loop {
                if !counter.lock().unwrap().is_empty() {
                    break;
                }
                sleep(TokioDuration::from_millis(20)).await;
            }
        })
        .await
        .expect("received payload");

        let payloads = counter.lock().unwrap().clone();
        assert_eq!(payloads.len(), 1);
        let json: Value = serde_json::from_str(&payloads[0]).expect("json payload");
        assert_eq!(json["block_height"], 42);
        assert_eq!(json["node_id"], "node-1");
        handle.shutdown().await.expect("shutdown");
        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn failed_endpoint_retries_and_logs() {
        let logger = init_test_logger();
        let port = find_unused_port();
        let endpoint = format!("http://127.0.0.1:{port}");
        let config = TelemetryConfig {
            enabled: true,
            endpoint: Some(endpoint),
            auth_token: None,
            timeout_ms: 50,
            retry_max: 2,
            sample_interval_secs: 1,
            redact_logs: true,
        };
        let handle = TelemetryHandle::spawn(config);
        let snapshot = sample_snapshot();

        handle.send(snapshot).await.expect("snapshot queued");
        sleep(TokioDuration::from_millis(400)).await;

        let logs = logger.drain();
        assert!(
            logs.iter()
                .any(|entry| entry.contains("telemetry HTTP dispatch failed"))
        );
        handle.shutdown().await.expect("shutdown");
    }

    fn sample_snapshot() -> TelemetrySnapshot {
        TelemetrySnapshot {
            block_height: 42,
            block_hash: "0xdeadbeef".into(),
            transaction_count: 7,
            peer_count: 3,
            node_id: "node-1".into(),
            reputation_score: 0.75,
            timestamp: SystemTime::now(),
        }
    }

    async fn spawn_test_server() -> (
        std::net::SocketAddr,
        Arc<Mutex<VecDeque<String>>>,
        oneshot::Sender<()>,
    ) {
        let storage = Arc::new(Mutex::new(VecDeque::new()));
        let storage_clone = storage.clone();
        let app = Router::new()
            .route(
                "/",
                post(
                    move |State(state): State<Arc<Mutex<VecDeque<String>>>>,
                          Json(payload): Json<Value>| async move {
                        state.lock().unwrap().push_back(payload.to_string());
                        Result::<(), axum::http::StatusCode>::Ok(())
                    },
                ),
            )
            .with_state(storage_clone);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let state = storage.clone();

        tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });

        (addr, state, shutdown_tx)
    }

    fn find_unused_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind random port")
            .local_addr()
            .expect("local addr")
            .port()
    }

    #[derive(Default)]
    struct TestLogger {
        records: Mutex<Vec<String>>,
    }

    impl TestLogger {
        fn drain(&self) -> Vec<String> {
            std::mem::take(&mut *self.records.lock().unwrap())
        }
    }

    impl log::Log for TestLogger {
        fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            if self.enabled(record.metadata()) {
                self.records
                    .lock()
                    .unwrap()
                    .push(format!("{}", record.args()));
            }
        }

        fn flush(&self) {}
    }

    static LOGGER: OnceLock<Arc<TestLogger>> = OnceLock::new();

    fn init_test_logger() -> Arc<TestLogger> {
        LOGGER
            .get_or_init(|| {
                let logger = Arc::new(TestLogger::default());
                log::set_boxed_logger(Box::new(logger.clone())).ok();
                log::set_max_level(log::LevelFilter::Trace);
                logger
            })
            .clone()
    }
}
