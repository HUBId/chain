#![cfg(feature = "wallet-integration")]

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{routing::post, Json, Router};
use hyper::body::to_bytes;
use rpp_chain::runtime::telemetry::metrics::{RuntimeMetrics, WalletRpcMethod};
use rpp_chain::runtime::wallet::rpc::{
    authenticated_handler, AuthenticatedRpcHandler, RateLimitWindow, RpcError, RpcInvocation,
    RpcRequest, StaticAuthenticator, WalletAuditLogger, WalletRoleSet,
};
use rpp_wallet::rpc::dto::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};
use rpp_wallet::rpc::error::WalletRpcErrorCode;
use serde_json::{json, Value};
use tower::ServiceExt;

const LIMITED_METHOD: &str = "limited.echo";
const SIGNING_METHOD: &str = "signing.error";
const UNKNOWN_METHOD: &str = "unknown";

fn rate_limited_handler(metrics: Arc<RuntimeMetrics>) -> TestHandler {
    authenticated_handler(
        StaticAuthenticator::new(None),
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
        StaticAuthenticator::new(None),
        Arc::new(|invocation: RpcInvocation<'_, JsonRpcRequest>| {
            let wallet_code = WalletRpcErrorCode::DraftUnsigned;
            let payload = wallet_code.data_payload(Some(json!({
                "reason": "missing signature"
            })));
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

fn fallback_handler(metrics: Arc<RuntimeMetrics>) -> TestHandler {
    authenticated_handler(
        StaticAuthenticator::new(None),
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
        UNKNOWN_METHOD,
        None,
        &[],
        Arc::new(WalletAuditLogger::disabled()),
    )
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

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    const PREFIX: &str = "Bearer ";
    value.strip_prefix(PREFIX).map(str::to_string)
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

fn build_router() -> Router {
    let metrics = Arc::new(RuntimeMetrics::noop());
    let mut handlers = HashMap::new();
    handlers.insert(LIMITED_METHOD.to_string(), rate_limited_handler(Arc::clone(&metrics)));
    handlers.insert(SIGNING_METHOD.to_string(), signing_error_handler(Arc::clone(&metrics)));

    let server = Arc::new(TestRpcServer {
        handlers,
        fallback: fallback_handler(metrics),
    });

    Router::new()
        .route("/rpc", post(test_rpc_handler))
        .with_state(server)
}

fn post_request(body: Value) -> Request<Body> {
    Request::builder()
        .uri("/rpc")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

#[tokio::test]
async fn rate_limits_emit_headers_and_retry_after() {
    let app = build_router();

    let first = app
        .clone()
        .oneshot(post_request(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": LIMITED_METHOD,
        })))
        .await
        .expect("first response");
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .clone()
        .oneshot(post_request(json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": LIMITED_METHOD,
        })))
        .await
        .expect("second response");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let headers = second.headers();
    assert_eq!(headers.get("x-ratelimit-limit").and_then(|v| v.to_str().ok()), Some("1"));
    assert_eq!(headers.get("x-ratelimit-remaining").and_then(|v| v.to_str().ok()), Some("0"));
    let reset = headers
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .expect("reset header");
    assert!(reset >= 1 && reset <= 60);
    assert_eq!(headers.get("retry-after").and_then(|v| v.to_str().ok()), Some(&reset.to_string()));

    let body = to_bytes(second.into_body()).await.expect("limit body");
    let response: JsonRpcResponse = serde_json::from_slice(&body).expect("parse response");
    let error = response.error.expect("rate limit error");
    assert_eq!(error.code, -32061);
    assert!(error.message.contains("rate limit"));
}

#[tokio::test]
async fn invalid_requests_report_parse_errors() {
    let app = build_router();
    let request = Request::builder()
        .uri("/rpc")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from("{\"jsonrpc\":\"2.0\""))
        .expect("request");

    let response = app.oneshot(request).await.expect("parse response");
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body()).await.expect("body");
    let parsed: JsonRpcResponse = serde_json::from_slice(&body).expect("jsonrpc response");
    let error = parsed.error.expect("error present");
    assert_eq!(error.code, -32700);
    assert!(error.message.contains("invalid JSON payload"));
}

#[tokio::test]
async fn signing_errors_include_wallet_code_payloads() {
    let app = build_router();
    let response = app
        .oneshot(post_request(json!({
            "jsonrpc": "2.0",
            "id": 99,
            "method": SIGNING_METHOD,
        })))
        .await
        .expect("signing response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body()).await.expect("body");
    let parsed: JsonRpcResponse = serde_json::from_slice(&body).expect("jsonrpc response");
    let error = parsed.error.expect("error");
    assert_eq!(error.code, WalletRpcErrorCode::DraftUnsigned.as_i32());
    let payload = error.data.expect("error payload");
    assert_eq!(payload["code"], Value::String("DRAFT_UNSIGNED".into()));
    assert_eq!(payload["details"]["reason"], Value::String("missing signature".into()));
}
