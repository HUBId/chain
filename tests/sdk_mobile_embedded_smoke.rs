#![cfg(feature = "wallet-integration")]

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{routing::post, Json, Router};
use rpp_chain::runtime::telemetry::metrics::{RuntimeMetrics, WalletRpcMethod};
use rpp_chain::runtime::wallet::rpc::{
    authenticated_handler, AuthenticatedRpcHandler, AuthToken, RateLimitWindow, RpcError, RpcInvocation,
    RpcRequest, StaticAuthenticator, WalletAuditLogger, WalletRoleSet,
};
use rpp_wallet::rpc::client::{RateLimitWindow as ClientRateLimitWindow, WalletRpcClient, WalletRpcClientError};
use rpp_wallet::rpc::dto::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use rpp_wallet::rpc::error::WalletRpcErrorCode;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const AUTH_TOKEN: &str = "sdk-test-token";
const LIMITED_METHOD: &str = "limited.echo";
const SIGNING_METHOD: &str = "signing.error";
const HEALTH_METHOD: &str = "health";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mobile_and_embedded_sdks_cover_auth_limits_and_signing() -> Result<()> {
    let log_dir = sdk_log_dir()?;
    let router = build_router();
    let (addr, shutdown) = spawn_server(router).await?;
    let endpoint = format!("http://{addr}/rpc");

    let mobile_client = WalletRpcClient::from_endpoint(&endpoint, Some(AUTH_TOKEN.into()), None, Duration::from_secs(3))
        .context("build mobile client")?;
    let embedded_client = WalletRpcClient::from_endpoint(&endpoint, Some(AUTH_TOKEN.into()), None, Duration::from_secs(3))
        .context("build embedded client")?;
    let unauthenticated =
        WalletRpcClient::from_endpoint(&endpoint, None, None, Duration::from_secs(3)).context("build unauthenticated client")?;

    let echo = mobile_client
        .request::<Value>(LIMITED_METHOD, Some(json!({ "flow": "mobile" })))
        .await
        .context("mobile echo")?;
    append_log(&log_dir, "mobile", "echo", &echo)?;
    assert_eq!(echo["echo"], LIMITED_METHOD);

    let unauth_error = unauthenticated
        .request::<Value>(LIMITED_METHOD, Option::<Value>::None)
        .await
        .expect_err("missing token should be rejected");
    append_log(&log_dir, "unauthenticated", "error", &json!(format!("{unauth_error}")))?;
    matches!(unauth_error, WalletRpcClientError::HttpStatus(StatusCode::UNAUTHORIZED))
        .then_some(())
        .context("auth guard should return 401")?;

    let first = embedded_client
        .request::<Value>(LIMITED_METHOD, Some(json!({ "flow": "embedded" })))
        .await
        .context("embedded first call")?;
    append_log(&log_dir, "embedded", "limited-ok", &first)?;

    let throttled = embedded_client
        .request::<Value>(LIMITED_METHOD, Option::<Value>::None)
        .await
        .expect_err("second call should be rate limited");
    let window = expect_rate_limit(throttled)?;
    append_log(&log_dir, "embedded", "rate-limited", &json!(window))?;

    let signing_err = mobile_client
        .request::<Value>(SIGNING_METHOD, Some(json!({ "tx": "unsigned" })))
        .await
        .expect_err("signing error should bubble up");
    append_log(
        &log_dir,
        "mobile",
        "signing-error",
        &json!(format!("{signing_err}")),
    )?;
    if let WalletRpcClientError::Rpc { code, .. } = signing_err {
        assert_eq!(code, WalletRpcErrorCode::DraftUnsigned);
    } else {
        anyhow::bail!("unexpected signing error variant: {signing_err}");
    }

    let health = embedded_client
        .request::<Value>(HEALTH_METHOD, Option::<Value>::None)
        .await
        .context("health check")?;
    append_log(&log_dir, "embedded", "health", &health)?;
    assert_eq!(health, json!({ "ok": true }));

    shutdown.send(()).ok();

    Ok(())
}

fn sdk_log_dir() -> Result<PathBuf> {
    let dir = PathBuf::from("logs").join("sdk-smoke");
    fs::create_dir_all(&dir).context("create sdk smoke log dir")?;
    Ok(dir)
}

fn append_log(dir: &Path, prefix: &str, event: &str, payload: &Value) -> Result<()> {
    let path = dir.join(format!("{prefix}.log"));
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open log file {path:?}"))?;
    writeln!(file, "{event}: {payload}").context("write sdk smoke log entry")
}

type TestHandler = AuthenticatedRpcHandler<TestHandlerFn, JsonRpcRequest>;
type TestHandlerFn = Arc<dyn Fn(RpcInvocation<'_, JsonRpcRequest>) -> JsonRpcResponse + Send + Sync>;

#[derive(Clone)]
struct TestRpcServer {
    handlers: HashMap<String, TestHandler>,
    fallback: TestHandler,
}

impl TestRpcServer {
    fn handler_for(&self, method: &str) -> &TestHandler {
        self.handlers.get(method).unwrap_or(&self.fallback)
    }

}

fn build_router() -> Router {
    let metrics = Arc::new(RuntimeMetrics::noop());
    let mut handlers = HashMap::new();
    handlers.insert(LIMITED_METHOD.to_string(), rate_limited_handler(Arc::clone(&metrics)));
    handlers.insert(SIGNING_METHOD.to_string(), signing_error_handler(Arc::clone(&metrics)));
    handlers.insert(HEALTH_METHOD.to_string(), health_handler(Arc::clone(&metrics)));

    let server = Arc::new(TestRpcServer {
        handlers,
        fallback: fallback_handler(metrics.clone()),
    });

    Router::new()
        .route("/rpc", post(test_rpc_handler))
        .with_state(server)
}

fn rate_limited_handler(metrics: Arc<RuntimeMetrics>) -> TestHandler {
    authenticated_handler(
        StaticAuthenticator::new(Some(AuthToken::new(AUTH_TOKEN))),
        Arc::new(|invocation: RpcInvocation<'_, JsonRpcRequest>| {
            JsonRpcResponse::success(
                invocation.payload.id.clone(),
                json!({ "echo": invocation.payload.method }),
            )
        }),
        metrics,
        WalletRpcMethod::RuntimeStatus,
        LIMITED_METHOD,
        NonZeroU64::new(1),
        &[],
        Arc::new(WalletAuditLogger::disabled()),
    )
}

fn signing_error_handler(metrics: Arc<RuntimeMetrics>) -> TestHandler {
    authenticated_handler(
        StaticAuthenticator::new(Some(AuthToken::new(AUTH_TOKEN))),
        Arc::new(|invocation: RpcInvocation<'_, JsonRpcRequest>| {
            let wallet_code = WalletRpcErrorCode::DraftUnsigned;
            let payload = wallet_code.data_payload(Some(json!({ "reason": "missing signature" })));
            JsonRpcResponse::error(
                invocation.payload.id.clone(),
                JsonRpcError::new(wallet_code.as_i32(), "draft unsigned", Some(payload)),
            )
        }),
        metrics,
        WalletRpcMethod::JsonSignTransaction,
        SIGNING_METHOD,
        None,
        &[],
        Arc::new(WalletAuditLogger::disabled()),
    )
}

fn health_handler(metrics: Arc<RuntimeMetrics>) -> TestHandler {
    authenticated_handler(
        StaticAuthenticator::new(Some(AuthToken::new(AUTH_TOKEN))),
        Arc::new(|invocation: RpcInvocation<'_, JsonRpcRequest>| {
            JsonRpcResponse::success(invocation.payload.id.clone(), json!({ "ok": true }))
        }),
        metrics,
        WalletRpcMethod::RuntimeStatus,
        HEALTH_METHOD,
        None,
        &[],
        Arc::new(WalletAuditLogger::disabled()),
    )
}

fn fallback_handler(metrics: Arc<RuntimeMetrics>) -> TestHandler {
    authenticated_handler(
        StaticAuthenticator::new(Some(AuthToken::new(AUTH_TOKEN))),
        Arc::new(|invocation: RpcInvocation<'_, JsonRpcRequest>| {
            JsonRpcResponse::error(
                invocation.payload.id.clone(),
                JsonRpcError::new(
                    WalletRpcErrorCode::MethodNotFound.as_i32(),
                    format!("method {} not found", invocation.payload.method),
                    None,
                ),
            )
        }),
        metrics,
        WalletRpcMethod::Unknown,
        "unknown",
        None,
        &[],
        Arc::new(WalletAuditLogger::disabled()),
    )
}

async fn test_rpc_handler(
    State(server): State<Arc<TestRpcServer>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(err) => {
            return rpc_error_response(
                StatusCode::BAD_REQUEST,
                None,
                JsonRpcError::new(-32700, format!("invalid JSON payload: {err}"), None),
                None,
            )
        }
    };

    let id = request.id.clone();
    let handler = server.handler_for(&request.method);
    let invocation = RpcInvocation {
        request: RpcRequest {
            bearer_token: bearer_token(&headers).as_deref(),
            identities: Vec::new(),
            roles: WalletRoleSet::new(),
        },
        payload: request,
    };

    match handler.call(invocation) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => rpc_error_response(id, Some(err), None, None),
    }
}

fn rpc_error_response(
    id: Option<Value>,
    err: Option<RpcError>,
    override_code: Option<i32>,
    override_details: Option<Value>,
) -> Response {
    if let Some(err) = err {
        let payload = if let Some(wallet_code) = err.wallet_code() {
            let details = wallet_code.data_payload(err.details().cloned());
            JsonRpcError::new(err.code(), err.to_string(), Some(details))
        } else {
            JsonRpcError::new(err.code(), err.to_string(), err.details().cloned())
        };
        let mut response = (err.status(), Json(JsonRpcResponse::error(id, payload))).into_response();
        if let Some(window) = err.rate_limit() {
            apply_rate_limit_headers(response.headers_mut(), window.clone());
        }
        return response;
    }

    let error = JsonRpcError::new(
        override_code.unwrap_or(-32601),
        "method not found",
        override_details,
    );
    (StatusCode::OK, Json(JsonRpcResponse::error(id, error))).into_response()
}

fn apply_rate_limit_headers(headers: &mut HeaderMap<HeaderValue>, window: RateLimitWindow) {
    let reset = window.reset_after.as_secs().max(1);
    headers.insert(
        "x-ratelimit-limit",
        HeaderValue::from_str(&window.limit.get().to_string()).expect("limit header"),
    );
    headers.insert(
        "x-ratelimit-remaining",
        HeaderValue::from_str(&window.remaining.to_string()).expect("remaining header"),
    );
    headers.insert(
        "x-ratelimit-reset",
        HeaderValue::from_str(&reset.to_string()).expect("reset header"),
    );
    headers.insert(
        "retry-after",
        HeaderValue::from_str(&reset.to_string()).expect("retry header"),
    );
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    const PREFIX: &str = "Bearer ";
    value.strip_prefix(PREFIX).map(str::to_string)
}

async fn spawn_server(router: Router) -> Result<(SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind sdk smoke listener")?;
    let addr = listener.local_addr().context("read listener address")?;
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let server = axum::serve(listener, router).with_graceful_shutdown(async move {
            let _ = rx.await;
        });
        if let Err(err) = server.await {
            eprintln!("sdk smoke server error: {err}");
        }
    });

    Ok((addr, tx))
}

fn expect_rate_limit(err: WalletRpcClientError) -> Result<ClientRateLimitWindow> {
    if let WalletRpcClientError::RateLimited(window) = err {
        return Ok(window);
    }

    anyhow::bail!("expected rate limit error, got {err}")
}

