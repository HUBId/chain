use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{routing::post, Json, Router};
use parking_lot::Mutex;
use serde_json::Value;
use tower_http::cors::{Any, CorsLayer};

use crate::errors::ChainError;
use crate::runtime::telemetry::metrics::{RpcMethod, RpcResult, RuntimeMetrics, WalletRpcMethod};
use crate::runtime::wallet::runtime::WalletRuntimeConfig;
use rpp_wallet::rpc::dto::{
    BroadcastResponse, JsonRpcError, JsonRpcRequest, JsonRpcResponse, RescanResponse,
    SignTxResponse,
};
use rpp_wallet::rpc::WalletRpcRouter;

const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const CODE_PARSE_ERROR: i32 = -32700;
const CODE_INVALID_REQUEST: i32 = -32600;
const CODE_METHOD_NOT_FOUND: i32 = -32601;
const CODE_INVALID_PARAMS: i32 = -32602;
const CODE_INTERNAL_ERROR: i32 = -32603;
const CODE_UNAUTHORIZED: i32 = -32060;
const CODE_RATE_LIMITED: i32 = -32061;
const CODE_WALLET_ERROR: i32 = -32010;
const CODE_SYNC_ERROR: i32 = -32020;
const CODE_NODE_ERROR: i32 = -32030;
const CODE_DRAFT_NOT_FOUND: i32 = -32040;
const CODE_DRAFT_UNSIGNED: i32 = -32041;
const CODE_SYNC_UNAVAILABLE: i32 = -32050;
const CODE_RESCAN_OUT_OF_RANGE: i32 = -32051;

/// Wrapper type for wallet RPC authentication tokens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthToken(String);

impl AuthToken {
    /// Constructs a new authentication token from the provided secret string.
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// Returns the raw token secret.
    pub fn secret(&self) -> &str {
        &self.0
    }
}

/// Authentication error surfaced by the RPC layer.
#[derive(Debug)]
pub struct RpcError {
    status: StatusCode,
    code: i32,
    message: String,
}

impl RpcError {
    /// Constructs an unauthorized error with a friendly message.
    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: CODE_UNAUTHORIZED,
            message: "wallet RPC authentication failed".to_string(),
        }
    }

    /// Constructs a rate limiting error when the caller exceeds the allowed
    /// number of invocations.
    pub fn too_many_requests() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: CODE_RATE_LIMITED,
            message: "wallet RPC rate limit exceeded".to_string(),
        }
    }

    /// Status code associated with the error.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// JSON-RPC error code associated with the failure.
    pub fn code(&self) -> i32 {
        self.code
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for RpcError {}

/// Request metadata extracted for authentication purposes.
#[derive(Clone, Debug)]
pub struct RpcRequest<'a> {
    pub bearer_token: Option<&'a str>,
}

#[derive(Clone, Debug)]
pub struct RpcInvocation<'a, P> {
    pub request: RpcRequest<'a>,
    pub payload: P,
}

/// Strategy object responsible for authorizing wallet RPC invocations.
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, token: Option<&str>) -> bool;
}

/// Static authenticator that validates a pre-configured bearer token.
#[derive(Clone, Debug, Default)]
pub struct StaticAuthenticator {
    token: Option<AuthToken>,
}

impl StaticAuthenticator {
    pub fn new(token: Option<AuthToken>) -> Self {
        Self { token }
    }
}

impl Authenticator for StaticAuthenticator {
    fn authenticate(&self, token: Option<&str>) -> bool {
        match (&self.token, token) {
            (None, _) => true,
            (Some(expected), Some(actual)) => expected.secret() == actual,
            _ => false,
        }
    }
}

#[derive(Debug)]
struct RateLimiter {
    capacity: NonZeroU64,
    interval: Duration,
    state: Mutex<RateLimiterState>,
}

#[derive(Debug)]
struct RateLimiterState {
    window_start: Instant,
    count: u64,
}

impl RateLimiter {
    fn new(capacity: NonZeroU64, interval: Duration) -> Self {
        Self {
            capacity,
            interval,
            state: Mutex::new(RateLimiterState {
                window_start: Instant::now(),
                count: 0,
            }),
        }
    }

    fn try_acquire(&self) -> bool {
        let mut state = self.state.lock();
        let now = Instant::now();
        if now.saturating_duration_since(state.window_start) >= self.interval {
            state.window_start = now;
            state.count = 0;
        }

        if state.count < self.capacity.get() {
            state.count += 1;
            true
        } else {
            false
        }
    }
}

/// Wrapper ensuring that RPC handlers are only executed when authorized and
/// within the configured rate limits.
pub struct AuthenticatedRpcHandler<H, P> {
    authenticator: Arc<dyn Authenticator>,
    handler: H,
    metrics: Arc<RuntimeMetrics>,
    method: WalletRpcMethod,
    rate_limiter: Option<RateLimiter>,
    _marker: PhantomData<fn(P)>,
}

impl<H, P> AuthenticatedRpcHandler<H, P>
where
    H: Send + Sync,
{
    pub fn new(
        authenticator: impl Authenticator + 'static,
        handler: H,
        metrics: Arc<RuntimeMetrics>,
        method: WalletRpcMethod,
        rate_limit: Option<NonZeroU64>,
    ) -> Self {
        Self {
            authenticator: Arc::new(authenticator),
            handler,
            metrics,
            method,
            rate_limiter: rate_limit.map(|limit| RateLimiter::new(limit, RATE_LIMIT_WINDOW)),
            _marker: PhantomData,
        }
    }
}

impl<H, R, P> AuthenticatedRpcHandler<H, P>
where
    H: Fn(RpcInvocation<'_, P>) -> R + Send + Sync,
    P: Clone,
{
    pub fn call(&self, invocation: RpcInvocation<'_, P>) -> Result<R, RpcError> {
        let start = Instant::now();
        if !self
            .authenticator
            .authenticate(invocation.request.bearer_token)
        {
            let duration = start.elapsed();
            self.record_outcome(RpcResult::ClientError, duration);
            return Err(RpcError::unauthorized());
        }

        if let Some(limiter) = &self.rate_limiter {
            if !limiter.try_acquire() {
                let duration = start.elapsed();
                self.record_outcome(RpcResult::ClientError, duration);
                return Err(RpcError::too_many_requests());
            }
        }

        let response = (self.handler)(invocation);
        let duration = start.elapsed();
        self.record_outcome(RpcResult::Success, duration);
        Ok(response)
    }

    fn record_outcome(&self, result: RpcResult, duration: Duration) {
        self.metrics
            .record_wallet_rpc_latency(self.method, duration);
        self.metrics
            .record_rpc_request(RpcMethod::Wallet(self.method), result, duration);
    }
}

impl From<RpcError> for ChainError {
    fn from(err: RpcError) -> Self {
        ChainError::Config(err.to_string())
    }
}

/// Convenience helper for constructing an authenticated handler from a closure.
pub fn authenticated_handler<H, P, R>(
    authenticator: impl Authenticator + 'static,
    handler: H,
    metrics: Arc<RuntimeMetrics>,
    method: WalletRpcMethod,
    rate_limit: Option<NonZeroU64>,
) -> AuthenticatedRpcHandler<H, P>
where
    H: Fn(RpcInvocation<'_, P>) -> R + Send + Sync,
    P: Clone,
{
    AuthenticatedRpcHandler::new(authenticator, handler, metrics, method, rate_limit)
}

type RpcHandlerFn = Arc<dyn Fn(RpcInvocation<'_, JsonRpcRequest>) -> JsonRpcResponse + Send + Sync>;
type JsonRpcHandler = AuthenticatedRpcHandler<RpcHandlerFn, JsonRpcRequest>;

fn determine_rate_limit(limit_hint: Option<u64>, global: Option<NonZeroU64>) -> Option<NonZeroU64> {
    let method_limit = limit_hint.and_then(NonZeroU64::new);
    match (method_limit, global) {
        (Some(method), Some(global)) => {
            if method.get() <= global.get() {
                Some(method)
            } else {
                Some(global)
            }
        }
        (Some(method), None) => Some(method),
        (None, Some(global)) => Some(global),
        (None, None) => None,
    }
}

fn wallet_prover_metrics_enabled() -> bool {
    cfg!(feature = "prover-mock")
        || cfg!(feature = "prover-stwo")
        || cfg!(feature = "prover-stwo-simd")
}

fn extract_prover_job_metrics(response: &JsonRpcResponse) -> Option<(String, bool, Duration)> {
    let result = response.result.as_ref()?;
    let parsed: SignTxResponse = serde_json::from_value(result.clone()).ok()?;
    Some((
        parsed.backend,
        parsed.proof_generated,
        Duration::from_millis(parsed.duration_ms),
    ))
}

fn extract_rescan_scheduled(response: &JsonRpcResponse) -> Option<bool> {
    let result = response.result.as_ref()?;
    let parsed: RescanResponse = serde_json::from_value(result.clone()).ok()?;
    Some(parsed.scheduled)
}

fn extract_broadcast_rejection_reason(response: &JsonRpcResponse) -> Option<String> {
    if let Some(result) = response.result.as_ref() {
        if let Ok(parsed) = serde_json::from_value::<BroadcastResponse>(result.clone()) {
            if !parsed.accepted {
                return Some("NOT_ACCEPTED".to_string());
            }
        }
        return None;
    }

    let error = response.error.as_ref()?;
    Some(broadcast_reason_from_error(error))
}

fn broadcast_reason_from_error(error: &JsonRpcError) -> String {
    match error.code {
        CODE_NODE_ERROR => {
            phase2_code_from_error(error).unwrap_or_else(|| "NODE_ERROR".to_string())
        }
        CODE_WALLET_ERROR => "WALLET_ERROR".to_string(),
        CODE_SYNC_ERROR => "SYNC_ERROR".to_string(),
        CODE_DRAFT_NOT_FOUND => "MISSING_DRAFT".to_string(),
        CODE_DRAFT_UNSIGNED => "DRAFT_UNSIGNED".to_string(),
        CODE_INVALID_PARAMS => "INVALID_PARAMS".to_string(),
        CODE_INVALID_REQUEST => "INVALID_REQUEST".to_string(),
        CODE_METHOD_NOT_FOUND => "METHOD_NOT_FOUND".to_string(),
        CODE_INTERNAL_ERROR => "INTERNAL_ERROR".to_string(),
        CODE_RATE_LIMITED => "RATE_LIMITED".to_string(),
        CODE_UNAUTHORIZED => "UNAUTHORIZED".to_string(),
        CODE_PARSE_ERROR => "PARSE_ERROR".to_string(),
        CODE_SYNC_UNAVAILABLE => "SYNC_UNAVAILABLE".to_string(),
        CODE_RESCAN_OUT_OF_RANGE => "RESCAN_OUT_OF_RANGE".to_string(),
        _ => "UNKNOWN".to_string(),
    }
}

fn phase2_code_from_error(error: &JsonRpcError) -> Option<String> {
    match &error.data {
        Some(Value::Object(map)) => map
            .get("phase2_code")
            .and_then(|value| value.as_str().map(ToString::to_string)),
        _ => None,
    }
}

const JSON_RPC_METHODS: &[(&str, WalletRpcMethod, Option<u64>)] = &[
    ("get_balance", WalletRpcMethod::JsonGetBalance, Some(120)),
    ("list_utxos", WalletRpcMethod::JsonListUtxos, Some(120)),
    ("list_txs", WalletRpcMethod::JsonListTransactions, Some(60)),
    (
        "derive_address",
        WalletRpcMethod::JsonDeriveAddress,
        Some(60),
    ),
    (
        "create_tx",
        WalletRpcMethod::JsonCreateTransaction,
        Some(30),
    ),
    ("sign_tx", WalletRpcMethod::JsonSignTransaction, Some(20)),
    ("broadcast", WalletRpcMethod::JsonBroadcast, Some(20)),
    (
        "policy_preview",
        WalletRpcMethod::JsonPolicyPreview,
        Some(30),
    ),
    ("get_policy", WalletRpcMethod::JsonGetPolicy, Some(30)),
    ("set_policy", WalletRpcMethod::JsonSetPolicy, Some(10)),
    ("estimate_fee", WalletRpcMethod::JsonEstimateFee, Some(120)),
    (
        "list_pending_locks",
        WalletRpcMethod::JsonListPendingLocks,
        Some(60),
    ),
    (
        "release_pending_locks",
        WalletRpcMethod::JsonReleasePendingLocks,
        Some(30),
    ),
    ("sync_status", WalletRpcMethod::JsonSyncStatus, Some(60)),
    ("rescan", WalletRpcMethod::JsonRescan, Some(6)),
];

struct WalletRpcServer {
    handlers: HashMap<&'static str, JsonRpcHandler>,
    fallback: JsonRpcHandler,
}

impl WalletRpcServer {
    fn new(
        router: Arc<WalletRpcRouter>,
        metrics: Arc<RuntimeMetrics>,
        config: &WalletRuntimeConfig,
    ) -> Self {
        let mut handlers = HashMap::new();
        for (name, method, limit) in JSON_RPC_METHODS {
            let handler = Self::build_handler(
                Arc::clone(&router),
                Arc::clone(&metrics),
                config,
                *method,
                *limit,
            );
            handlers.insert(*name, handler);
        }
        let fallback = Self::build_handler(router, metrics, config, WalletRpcMethod::Unknown, None);
        Self { handlers, fallback }
    }

    fn build_handler(
        router: Arc<WalletRpcRouter>,
        metrics: Arc<RuntimeMetrics>,
        config: &WalletRuntimeConfig,
        method: WalletRpcMethod,
        limit_hint: Option<u64>,
    ) -> JsonRpcHandler {
        let router_for_handler = Arc::clone(&router);
        let metrics_for_handler = Arc::clone(&metrics);
        let method_label = method;
        let prover_metrics_enabled = wallet_prover_metrics_enabled();
        let closure: RpcHandlerFn =
            Arc::new(move |invocation: RpcInvocation<'_, JsonRpcRequest>| {
                let payload = invocation.payload;
                match method_label {
                    WalletRpcMethod::JsonEstimateFee => {
                        let start = Instant::now();
                        let response = router_for_handler.handle(payload);
                        let duration = start.elapsed();
                        metrics_for_handler.record_wallet_fee_estimate_latency(duration);
                        response
                    }
                    WalletRpcMethod::JsonSignTransaction => {
                        let response = router_for_handler.handle(payload);
                        if prover_metrics_enabled {
                            if let Some((backend, proof_generated, duration)) =
                                extract_prover_job_metrics(&response)
                            {
                                metrics_for_handler.record_wallet_prover_job_duration(
                                    &backend,
                                    proof_generated,
                                    duration,
                                );
                            }
                        }
                        response
                    }
                    WalletRpcMethod::JsonRescan => {
                        let start = Instant::now();
                        let response = router_for_handler.handle(payload);
                        let duration = start.elapsed();
                        if let Some(scheduled) = extract_rescan_scheduled(&response) {
                            metrics_for_handler.record_wallet_rescan_duration(scheduled, duration);
                        }
                        response
                    }
                    WalletRpcMethod::JsonBroadcast => {
                        let response = router_for_handler.handle(payload);
                        if let Some(reason) = extract_broadcast_rejection_reason(&response) {
                            metrics_for_handler.record_wallet_broadcast_rejected(&reason);
                        }
                        response
                    }
                    _ => router_for_handler.handle(payload),
                }
            });
        let rate_limit = determine_rate_limit(limit_hint, config.requests_per_minute);
        authenticated_handler::<_, JsonRpcRequest, _>(
            StaticAuthenticator::new(config.auth_token.clone()),
            closure,
            metrics,
            method,
            rate_limit,
        )
    }

    fn handler_for(&self, method: &str) -> &JsonRpcHandler {
        self.handlers.get(method).unwrap_or(&self.fallback)
    }
}

pub fn json_rpc_router(
    wallet_router: Arc<WalletRpcRouter>,
    metrics: Arc<RuntimeMetrics>,
    config: &WalletRuntimeConfig,
) -> Result<Router, ChainError> {
    let server = Arc::new(WalletRpcServer::new(
        wallet_router,
        Arc::clone(&metrics),
        config,
    ));
    let cors = build_cors_layer(config)?;
    Ok(Router::new()
        .route("/rpc", post(wallet_rpc_handler))
        .with_state(server)
        .layer(cors))
}

async fn wallet_rpc_handler(
    State(server): State<Arc<WalletRpcServer>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(err) => {
            return rpc_error_response(
                StatusCode::BAD_REQUEST,
                None,
                CODE_PARSE_ERROR,
                format!("invalid JSON payload: {err}"),
            );
        }
    };

    let id = request.id.clone();
    let method = request.method.clone();
    let token_owned = bearer_token(&headers);
    let invocation = RpcInvocation {
        request: RpcRequest {
            bearer_token: token_owned.as_deref(),
        },
        payload: request,
    };

    let handler = server.handler_for(method.as_str());
    match handler.call(invocation) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => rpc_error_response(err.status(), id, err.code(), err.to_string()),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    let prefix = "Bearer ";
    if value.starts_with(prefix) {
        Some(value[prefix.len()..].to_string())
    } else {
        None
    }
}

fn rpc_error_response(
    status: StatusCode,
    id: Option<Value>,
    code: i32,
    message: impl Into<String>,
) -> Response {
    let error = JsonRpcError::new(code, message, None);
    (status, Json(JsonRpcResponse::error(id, error))).into_response()
}

fn build_cors_layer(config: &WalletRuntimeConfig) -> Result<CorsLayer, ChainError> {
    let layer = CorsLayer::new()
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .allow_methods([Method::POST, Method::OPTIONS]);
    if let Some(origin) = &config.allowed_origin {
        let value = origin.parse::<HeaderValue>().map_err(|err| {
            ChainError::Config(format!("invalid wallet RPC allowed origin: {err}"))
        })?;
        Ok(layer.allow_origin(value))
    } else {
        Ok(layer.allow_origin(Any))
    }
}
