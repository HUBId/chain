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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tower::ServiceExt;

const LIMITED_METHOD: &str = "limited.echo";
const SIGNING_METHOD: &str = "signing.error";
const UNKNOWN_METHOD: &str = "unknown";
const HISTORY_METHOD: &str = "history.page";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct HistoryEnvelope {
    entries: Vec<HistoryEntry>,
    page_token: Option<String>,
    next_page_token: Option<String>,
    prev_page_token: Option<String>,
    backend: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct HistoryEntry {
    txid: String,
    height: u64,
    status: String,
    backend: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
struct HistoryParams {
    page_token: Option<String>,
    backend: Option<String>,
    reorg_at: Option<u64>,
}

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

fn history_handler(metrics: Arc<RuntimeMetrics>, limit: Option<NonZeroU64>) -> TestHandler {
    authenticated_handler(
        StaticAuthenticator::new(None),
        Arc::new(|invocation: RpcInvocation<'_, JsonRpcRequest>| {
            let params: HistoryParams = invocation
                .payload
                .params
                .clone()
                .and_then(|params| serde_json::from_value(params).ok())
                .unwrap_or_default();
            let backend = params
                .backend
                .clone()
                .unwrap_or_else(|| "rpp-stark".to_string());
            let page_token = params.page_token.clone();
            let entries = paginated_history(&backend, params.reorg_at);

            let (cursor, offset) = match page_token.as_deref() {
                Some(token) => parse_page_token(token),
                None => (None, 0usize),
            };
            let page_size = 2usize;
            let page_entries = entries
                .iter()
                .skip(offset)
                .take(page_size)
                .cloned()
                .collect::<Vec<_>>();
            let next_offset = offset + page_entries.len();
            let next_page_token = if next_offset < entries.len() {
                Some(format!("{}:{}", backend, next_offset))
            } else {
                None
            };
            let prev_page_token = if offset >= page_size {
                Some(format!("{}:{}", backend, offset - page_size))
            } else {
                None
            };

            JsonRpcResponse::success(
                invocation.payload.id.clone(),
                json!(HistoryEnvelope {
                    entries: page_entries,
                    page_token: cursor,
                    next_page_token,
                    prev_page_token,
                    backend,
                }),
            )
        }),
        metrics,
        WalletRpcMethod::RuntimeStatus,
        HISTORY_METHOD,
        limit,
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

fn paginated_history(backend: &str, reorg_at: Option<u64>) -> Vec<HistoryEntry> {
    let mut entries = vec![
        HistoryEntry {
            txid: "tx-0".into(),
            height: 1,
            status: "confirmed".into(),
            backend: backend.to_string(),
        },
        HistoryEntry {
            txid: "tx-1".into(),
            height: 2,
            status: "confirmed".into(),
            backend: backend.to_string(),
        },
        HistoryEntry {
            txid: "tx-2".into(),
            height: 3,
            status: "pending".into(),
            backend: backend.to_string(),
        },
        HistoryEntry {
            txid: "tx-3".into(),
            height: 4,
            status: "pending".into(),
            backend: backend.to_string(),
        },
    ];

    if let Some(height) = reorg_at {
        entries.retain(|entry| entry.height <= height);
        for entry in &mut entries {
            if entry.status == "pending" {
                entry.status = "reorged".into();
            }
        }
    }

    entries
}

fn parse_page_token(token: &str) -> (Option<String>, usize) {
    token
        .split_once(':')
        .and_then(|(backend, offset)| offset.parse::<usize>().ok().map(|idx| (Some(backend.to_string()), idx)))
        .unwrap_or((Some(token.to_string()), 0))
}

type TestHandler = AuthenticatedRpcHandler<TestHandlerFn, JsonRpcRequest>;
type TestHandlerFn =
    Arc<dyn Fn(RpcInvocation<'_, JsonRpcRequest>) -> JsonRpcResponse + Send + Sync>;

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
        let mut response =
            (err.status(), Json(JsonRpcResponse::error(id, payload))).into_response();
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
    handlers.insert(
        LIMITED_METHOD.to_string(),
        rate_limited_handler(Arc::clone(&metrics)),
    );
    handlers.insert(
        SIGNING_METHOD.to_string(),
        signing_error_handler(Arc::clone(&metrics)),
    );
    handlers.insert(
        HISTORY_METHOD.to_string(),
        history_handler(Arc::clone(&metrics), NonZeroU64::new(2)),
    );

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
    assert_eq!(
        headers
            .get("x-ratelimit-limit")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );
    assert_eq!(
        headers
            .get("x-ratelimit-remaining")
            .and_then(|v| v.to_str().ok()),
        Some("0")
    );
    let reset = headers
        .get("x-ratelimit-reset")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .expect("reset header");
    assert!(reset >= 1 && reset <= 60);
    assert_eq!(
        headers.get("retry-after").and_then(|v| v.to_str().ok()),
        Some(&reset.to_string())
    );

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
    assert_eq!(
        payload["details"]["reason"],
        Value::String("missing signature".into())
    );
}

#[tokio::test]
async fn history_pagination_tokens_survive_rate_limits() {
    let app = build_router();

    let first_page = history_page(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": HISTORY_METHOD,
            "params": {},
        }),
    )
    .await;
    assert_eq!(first_page.entries.len(), 2);
    let next_token = first_page.next_page_token.clone().expect("next token");

    let second_page = history_page(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": HISTORY_METHOD,
            "params": {"page_token": next_token},
        }),
    )
    .await;
    assert_eq!(
        second_page
            .entries
            .first()
            .map(|entry| entry.txid.as_str()),
        Some("tx-2"),
    );
    let final_token = second_page.next_page_token.clone().expect("final token");

    let limited_response = app
        .clone()
        .oneshot(post_request(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": HISTORY_METHOD,
            "params": {"page_token": final_token},
        })))
        .await
        .expect("limited response");
    assert_eq!(limited_response.status(), StatusCode::TOO_MANY_REQUESTS);
    let headers = limited_response.headers();
    assert!(headers.contains_key("x-ratelimit-limit"));
    assert!(headers.contains_key("retry-after"));

    let body = to_bytes(limited_response.into_body())
        .await
        .expect("limit body");
    let parsed: JsonRpcResponse = serde_json::from_slice(&body).expect("rpc error");
    assert!(parsed
        .error
        .as_ref()
        .map(|err| err.message.contains("rate limit"))
        .unwrap_or(false));

    let cooled_app = build_router();
    let recovered_page = history_page(
        &cooled_app,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": HISTORY_METHOD,
            "params": {"page_token": final_token},
        }),
    )
    .await;
    assert_eq!(recovered_page.entries.len(), 0);
    assert_eq!(recovered_page.prev_page_token.as_deref(), Some("rpp-stark:2"));
}

#[tokio::test]
async fn history_pagination_tracks_backends_and_reorgs() {
    let app = build_router();

    let stark_page = history_page(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": HISTORY_METHOD,
            "params": {"backend": "rpp-stark"},
        }),
    )
    .await;
    assert!(stark_page
        .entries
        .iter()
        .all(|entry| entry.backend == "rpp-stark"));
    let stark_token = stark_page.next_page_token.clone().expect("stark token");

    let plonky_page = history_page(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": HISTORY_METHOD,
            "params": {"backend": "plonky3", "reorg_at": 2},
        }),
    )
    .await;
    assert!(plonky_page
        .entries
        .iter()
        .all(|entry| entry.backend == "plonky3"));
    assert!(plonky_page.entries.iter().all(|entry| entry.height <= 2));
    assert!(plonky_page
        .entries
        .iter()
        .any(|entry| entry.status == "reorged"));

    let reorged_follow_up = history_page(
        &app,
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": HISTORY_METHOD,
            "params": {"backend": "plonky3", "page_token": stark_token, "reorg_at": 2},
        }),
    )
    .await;
    assert_eq!(reorged_follow_up.entries.len(), 0);
    assert_eq!(reorged_follow_up.next_page_token, None);
}

async fn history_page(app: &Router, request: Value) -> HistoryEnvelope {
    let response = app
        .clone()
        .oneshot(post_request(request))
        .await
        .expect("history response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body()).await.expect("body");
    let parsed: JsonRpcResponse = serde_json::from_slice(&body).expect("jsonrpc response");
    serde_json::from_value(parsed.result.expect("page result")).expect("history payload")
}
