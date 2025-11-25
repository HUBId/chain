use std::fmt;
use std::time::Duration;

use reqwest::{Response, StatusCode};
use serde::Deserialize;

use crate::rate_limit::compute_retry_delay;

/// Structured snapshot RPC error codes surfaced by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotErrorKind {
    PlanInvalid,
    MetadataMismatch,
    ProofEncodingInvalid,
    VerificationIncomplete,
    VerifierIo,
    PipelineError,
    PrunerStateError,
    Transport,
    Unknown(String),
}

impl SnapshotErrorKind {
    fn from_code(code: Option<String>) -> Self {
        match code.as_deref() {
            Some("state_sync_plan_invalid") => SnapshotErrorKind::PlanInvalid,
            Some("state_sync_metadata_mismatch") => SnapshotErrorKind::MetadataMismatch,
            Some("state_sync_proof_encoding_invalid") => SnapshotErrorKind::ProofEncodingInvalid,
            Some("state_sync_verification_incomplete") => SnapshotErrorKind::VerificationIncomplete,
            Some("state_sync_verifier_io") => SnapshotErrorKind::VerifierIo,
            Some("state_sync_pipeline_error") => SnapshotErrorKind::PipelineError,
            Some("state_sync_pruner_state_error") => SnapshotErrorKind::PrunerStateError,
            Some(other) => SnapshotErrorKind::Unknown(other.to_owned()),
            None => SnapshotErrorKind::Unknown(String::new()),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ErrorEnvelope {
    error: String,
    code: Option<String>,
}

/// Typed wrapper for snapshot RPC failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotError {
    pub status: StatusCode,
    pub message: String,
    pub kind: SnapshotErrorKind,
    pub retry_after: Duration,
}

impl SnapshotError {
    fn new(status: StatusCode, envelope: Option<ErrorEnvelope>, retry_after: Duration) -> Self {
        let kind = SnapshotErrorKind::from_code(envelope.as_ref().and_then(|e| e.code.clone()));
        let message = envelope
            .map(|e| e.error)
            .unwrap_or_else(|| "snapshot RPC failed".to_string());
        SnapshotError {
            status,
            message,
            kind,
            retry_after,
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind,
            SnapshotErrorKind::ProofEncodingInvalid
                | SnapshotErrorKind::VerificationIncomplete
                | SnapshotErrorKind::VerifierIo
                | SnapshotErrorKind::PipelineError
        )
    }
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}: {}", self.status, self.kind_label(), self.message)
    }
}

impl std::error::Error for SnapshotError {}

impl SnapshotError {
    fn kind_label(&self) -> &str {
        match &self.kind {
            SnapshotErrorKind::PlanInvalid => "state_sync_plan_invalid",
            SnapshotErrorKind::MetadataMismatch => "state_sync_metadata_mismatch",
            SnapshotErrorKind::ProofEncodingInvalid => "state_sync_proof_encoding_invalid",
            SnapshotErrorKind::VerificationIncomplete => "state_sync_verification_incomplete",
            SnapshotErrorKind::VerifierIo => "state_sync_verifier_io",
            SnapshotErrorKind::PipelineError => "state_sync_pipeline_error",
            SnapshotErrorKind::PrunerStateError => "state_sync_pruner_state_error",
            SnapshotErrorKind::Transport => "transport",
            SnapshotErrorKind::Unknown(label) => label.as_str(),
        }
    }
}

/// Map an RPC response to a typed `SnapshotError` so callers can react programmatically.
///
/// The `min_backoff` parameter clamps retry computations when rate-limit headers are
/// missing or when the advertised window is zero.
pub async fn classify_snapshot_error(
    response: Result<Response, reqwest::Error>,
    min_backoff: Duration,
) -> Result<Response, SnapshotError> {
    match response {
        Ok(resp) => {
            if resp.status().is_success() {
                return Ok(resp);
            }

            let status = resp.status();
            let headers = resp.headers().clone();
            let body = resp.text().await.unwrap_or_default();
            let envelope: Option<ErrorEnvelope> = serde_json::from_str(&body).ok();
            let retry_after = compute_retry_delay(status, &headers, min_backoff);
            Err(SnapshotError::new(status, envelope, retry_after))
        }
        Err(err) => Err(SnapshotError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: err.to_string(),
            kind: SnapshotErrorKind::Transport,
            retry_after: min_backoff,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Bytes;
    use hyper::service::{make_service_fn, service_fn};
    use hyper::{Body, Request, Response as HyperResponse, Server, StatusCode as HyperStatus};
    use tokio::sync::oneshot;

    async fn run_mock_server(
        response_body: &'static str,
        status: HyperStatus,
    ) -> (String, oneshot::Sender<()>) {
        let make_service = make_service_fn(move |_| {
            let body = response_body;
            async move {
                Ok::<_, hyper::Error>(service_fn(move |_req: Request<Body>| {
                    let body = body;
                    async move {
                        Ok::<_, hyper::Error>(
                            HyperResponse::builder()
                                .status(status)
                                .header("Content-Type", "application/json")
                                .header("X-RateLimit-Reset", "1")
                                .body(Body::from(Bytes::from(body)))
                                .unwrap(),
                        )
                    }
                }))
            }
        });

        let server = Server::try_bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let graceful = server.with_graceful_shutdown(async {
            let _ = shutdown_rx.await;
        });
        tokio::spawn(graceful);

        (format!("http://{}", addr), shutdown_tx)
    }

    #[tokio::test]
    async fn maps_snapshot_code_to_typed_error() {
        let payload = r#"{"error":"state sync verification failed","code":"state_sync_verification_incomplete"}"#;
        let (server, shutdown) = run_mock_server(payload, HyperStatus::SERVICE_UNAVAILABLE).await;

        let client = reqwest::Client::new();
        let response = client.get(format!("{server}/state-sync")).send().await;

        let err = classify_snapshot_error(response, Duration::from_millis(20))
            .await
            .unwrap_err();

        assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.kind, SnapshotErrorKind::VerificationIncomplete);
        assert!(err.retry_after >= Duration::from_secs(1));

        let _ = shutdown.send(());
    }

    #[tokio::test]
    async fn wraps_transport_error() {
        let response = reqwest::Client::new()
            .get("http://127.0.0.1:9/unreachable")
            .send()
            .await;

        let err = classify_snapshot_error(response, Duration::from_millis(50))
            .await
            .unwrap_err();

        assert_eq!(err.kind, SnapshotErrorKind::Transport);
        assert_eq!(err.retry_after, Duration::from_millis(50));
    }
}
