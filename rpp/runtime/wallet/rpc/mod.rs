use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::num::NonZeroU64;
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{routing::post, Json, Router};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tower_http::cors::{Any, CorsLayer};

use crate::errors::{ChainError, ChainResult};
use crate::runtime::telemetry::metrics::{RpcMethod, RpcResult, RuntimeMetrics, WalletRpcMethod};
use crate::runtime::wallet::runtime::WalletRuntimeConfig;
use rpp_wallet::rpc::dto::{
    BroadcastResponse, JsonRpcError, JsonRpcRequest, JsonRpcResponse, RescanResponse,
    SignTxResponse,
};
use rpp_wallet::rpc::error::WalletRpcErrorCode;
use rpp_wallet::rpc::WalletRpcRouter;

mod audit;
mod security;

pub use audit::WalletAuditLogger;
pub use security::{
    WalletClientCertificates, WalletIdentity, WalletRbacStore, WalletRole, WalletRoleSet,
    WalletSecurityContext, WalletSecurityPaths,
};

const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const CODE_PARSE_ERROR: i32 = -32700;
const CODE_UNAUTHORIZED: i32 = -32060;
const CODE_RATE_LIMITED: i32 = -32061;
const CODE_RBAC_FORBIDDEN: i32 = -32062;
const AUDIT_SUCCESS_CODE: i32 = 0;

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
    wallet_code: Option<WalletRpcErrorCode>,
    details: Option<Value>,
}

impl RpcError {
    /// Constructs an unauthorized error with a friendly message.
    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: CODE_UNAUTHORIZED,
            message: "wallet RPC authentication failed".to_string(),
            wallet_code: None,
            details: None,
        }
    }

    /// Constructs a rate limiting error when the caller exceeds the allowed
    /// number of invocations.
    pub fn too_many_requests() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: CODE_RATE_LIMITED,
            message: "wallet RPC rate limit exceeded".to_string(),
            wallet_code: None,
            details: None,
        }
    }

    pub fn rbac_forbidden(required: &'static [WalletRole], granted: &WalletRoleSet) -> Self {
        let required_names = required.iter().map(WalletRole::as_str).collect::<Vec<_>>();
        let granted_names = granted.iter().map(WalletRole::as_str).collect::<Vec<_>>();
        let message = if required_names.is_empty() {
            "wallet RBAC forbids this method".to_string()
        } else {
            format!(
                "wallet RBAC forbids this method (requires one of: {}; granted: {})",
                required_names.join(", "),
                if granted_names.is_empty() {
                    "none".to_string()
                } else {
                    granted_names.join(", ")
                }
            )
        };
        let details = json!({
            "required_roles": required_names,
            "granted_roles": granted_names,
        });
        Self {
            status: StatusCode::FORBIDDEN,
            code: CODE_RBAC_FORBIDDEN,
            message,
            wallet_code: Some(WalletRpcErrorCode::RbacForbidden),
            details: Some(details),
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

    pub fn wallet_code(&self) -> Option<&WalletRpcErrorCode> {
        self.wallet_code.as_ref()
    }

    pub fn details(&self) -> Option<&Value> {
        self.details.as_ref()
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
    pub identities: Vec<WalletIdentity>,
    pub roles: WalletRoleSet,
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

pub trait WalletAuditResult {
    fn audit_result_code(&self) -> i32 {
        AUDIT_SUCCESS_CODE
    }
}

impl WalletAuditResult for JsonRpcResponse {
    fn audit_result_code(&self) -> i32 {
        self.error
            .as_ref()
            .map(|err| err.code)
            .unwrap_or(AUDIT_SUCCESS_CODE)
    }
}

impl WalletAuditResult for String {}

/// Wrapper ensuring that RPC handlers are only executed when authorized and
/// within the configured rate limits.
pub struct AuthenticatedRpcHandler<H, P> {
    authenticator: Arc<dyn Authenticator>,
    handler: H,
    metrics: Arc<RuntimeMetrics>,
    method: WalletRpcMethod,
    method_name: &'static str,
    rate_limiter: Option<RateLimiter>,
    required_roles: &'static [WalletRole],
    audit: Arc<WalletAuditLogger>,
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
        method_name: &'static str,
        rate_limit: Option<NonZeroU64>,
        required_roles: &'static [WalletRole],
        audit: Arc<WalletAuditLogger>,
    ) -> Self {
        Self {
            authenticator: Arc::new(authenticator),
            handler,
            metrics,
            method,
            method_name,
            rate_limiter: rate_limit.map(|limit| RateLimiter::new(limit, RATE_LIMIT_WINDOW)),
            required_roles,
            audit,
            _marker: PhantomData,
        }
    }
}

impl<H, R, P> AuthenticatedRpcHandler<H, P>
where
    H: Fn(RpcInvocation<'_, P>) -> R + Send + Sync,
    P: Clone,
    R: WalletAuditResult,
{
    pub fn call(&self, invocation: RpcInvocation<'_, P>) -> Result<R, RpcError> {
        let start = Instant::now();
        let audit_context = if self.should_audit() {
            Some(AuditContext::from_invocation(self.method_name, &invocation))
        } else {
            None
        };

        if !self
            .authenticator
            .authenticate(invocation.request.bearer_token)
        {
            let duration = start.elapsed();
            self.record_outcome(
                audit_context.as_ref(),
                CODE_UNAUTHORIZED,
                RpcResult::ClientError,
                duration,
            );
            return Err(RpcError::unauthorized());
        }

        if let Some(limiter) = &self.rate_limiter {
            if !limiter.try_acquire() {
                let duration = start.elapsed();
                self.record_outcome(
                    audit_context.as_ref(),
                    CODE_RATE_LIMITED,
                    RpcResult::ClientError,
                    duration,
                );
                return Err(RpcError::too_many_requests());
            }
        }

        if !self.required_roles.is_empty()
            && !self
                .required_roles
                .iter()
                .any(|role| invocation.request.roles.contains(role))
        {
            let duration = start.elapsed();
            self.record_outcome(
                audit_context.as_ref(),
                CODE_RBAC_FORBIDDEN,
                RpcResult::ClientError,
                duration,
            );
            return Err(RpcError::rbac_forbidden(
                self.required_roles,
                &invocation.request.roles,
            ));
        }

        let response = (self.handler)(invocation);
        let duration = start.elapsed();
        let result_code = audit_context
            .as_ref()
            .map_or(AUDIT_SUCCESS_CODE, |_| response.audit_result_code());
        self.record_outcome(
            audit_context.as_ref(),
            result_code,
            RpcResult::Success,
            duration,
        );
        Ok(response)
    }

    fn record_outcome(
        &self,
        context: Option<&AuditContext>,
        result_code: i32,
        result: RpcResult,
        duration: Duration,
    ) {
        self.metrics
            .record_wallet_rpc_latency(self.method, duration);
        self.metrics
            .record_rpc_request(RpcMethod::Wallet(self.method), result, duration);
        if let Some(context) = context {
            self.audit.log(
                context.method,
                &context.identities,
                &context.roles,
                result_code,
            );
        }
    }

    fn should_audit(&self) -> bool {
        ptr::eq(self.required_roles, ROLES_OPERATOR) || ptr::eq(self.required_roles, ROLES_ADMIN)
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
    method_name: &'static str,
    rate_limit: Option<NonZeroU64>,
    required_roles: &'static [WalletRole],
    audit: Arc<WalletAuditLogger>,
) -> AuthenticatedRpcHandler<H, P>
where
    H: Fn(RpcInvocation<'_, P>) -> R + Send + Sync,
    P: Clone,
    R: WalletAuditResult,
{
    AuthenticatedRpcHandler::new(
        authenticator,
        handler,
        metrics,
        method,
        method_name,
        rate_limit,
        required_roles,
        audit,
    )
}

type RpcHandlerFn = Arc<dyn Fn(RpcInvocation<'_, JsonRpcRequest>) -> JsonRpcResponse + Send + Sync>;
type JsonRpcHandler = AuthenticatedRpcHandler<RpcHandlerFn, JsonRpcRequest>;

struct AuditContext {
    method: &'static str,
    identities: Vec<WalletIdentity>,
    roles: WalletRoleSet,
}

impl AuditContext {
    fn from_invocation<P>(method: &'static str, invocation: &RpcInvocation<'_, P>) -> Self {
        Self {
            method,
            identities: invocation.request.identities.clone(),
            roles: invocation.request.roles.clone(),
        }
    }
}

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
    if let Some(code) = rpc_error_code_from_error(error) {
        return code.as_str().into_owned();
    }
    match error.code {
        CODE_RATE_LIMITED => "RATE_LIMITED".to_string(),
        CODE_UNAUTHORIZED => "UNAUTHORIZED".to_string(),
        CODE_PARSE_ERROR => "PARSE_ERROR".to_string(),
        other => format!("JSON_RPC_{other}"),
    }
}

fn phase2_code_from_error(error: &JsonRpcError) -> Option<String> {
    error
        .data
        .as_ref()
        .and_then(|value| value.get("details"))
        .or_else(|| error.data.as_ref())
        .and_then(|value| value.get("phase2_code"))
        .and_then(|value| value.as_str().map(ToString::to_string))
}

fn rpc_error_code_from_error(error: &JsonRpcError) -> Option<WalletRpcErrorCode> {
    error
        .data
        .as_ref()
        .and_then(|value| value.get("code"))
        .and_then(|value| value.as_str())
        .map(WalletRpcErrorCode::from)
}

const ROLES_ANY: &[WalletRole] = &[];
const ROLES_ADMIN: &[WalletRole] = &[WalletRole::Admin];
const ROLES_OPERATOR: &[WalletRole] = &[WalletRole::Operator, WalletRole::Admin];
const ROLES_VIEWER: &[WalletRole] = &[WalletRole::Viewer, WalletRole::Operator, WalletRole::Admin];

const JSON_RPC_METHODS: &[(&str, WalletRpcMethod, Option<u64>, &'static [WalletRole])] = &[
    (
        "get_balance",
        WalletRpcMethod::JsonGetBalance,
        Some(120),
        ROLES_VIEWER,
    ),
    (
        "list_utxos",
        WalletRpcMethod::JsonListUtxos,
        Some(120),
        ROLES_VIEWER,
    ),
    (
        "list_txs",
        WalletRpcMethod::JsonListTransactions,
        Some(60),
        ROLES_VIEWER,
    ),
    (
        "derive_address",
        WalletRpcMethod::JsonDeriveAddress,
        Some(60),
        ROLES_OPERATOR,
    ),
    (
        "create_tx",
        WalletRpcMethod::JsonCreateTransaction,
        Some(30),
        ROLES_OPERATOR,
    ),
    (
        "sign_tx",
        WalletRpcMethod::JsonSignTransaction,
        Some(20),
        ROLES_OPERATOR,
    ),
    (
        "hw.enumerate",
        WalletRpcMethod::JsonHwEnumerate,
        Some(30),
        ROLES_OPERATOR,
    ),
    (
        "hw.sign",
        WalletRpcMethod::JsonHwSign,
        Some(20),
        ROLES_OPERATOR,
    ),
    (
        "backup.export",
        WalletRpcMethod::JsonBackupExport,
        Some(6),
        ROLES_ADMIN,
    ),
    (
        "backup.validate",
        WalletRpcMethod::JsonBackupValidate,
        Some(6),
        ROLES_OPERATOR,
    ),
    (
        "backup.import",
        WalletRpcMethod::JsonBackupImport,
        Some(6),
        ROLES_ADMIN,
    ),
    (
        "broadcast",
        WalletRpcMethod::JsonBroadcast,
        Some(20),
        ROLES_OPERATOR,
    ),
    (
        "policy_preview",
        WalletRpcMethod::JsonPolicyPreview,
        Some(30),
        ROLES_VIEWER,
    ),
    (
        "get_policy",
        WalletRpcMethod::JsonGetPolicy,
        Some(30),
        ROLES_VIEWER,
    ),
    (
        "set_policy",
        WalletRpcMethod::JsonSetPolicy,
        Some(10),
        ROLES_ADMIN,
    ),
    (
        "multisig.get_scope",
        WalletRpcMethod::JsonMultisigGetScope,
        Some(30),
        ROLES_VIEWER,
    ),
    (
        "multisig.set_scope",
        WalletRpcMethod::JsonMultisigSetScope,
        Some(10),
        ROLES_ADMIN,
    ),
    (
        "multisig.get_cosigners",
        WalletRpcMethod::JsonMultisigGetCosigners,
        Some(30),
        ROLES_VIEWER,
    ),
    (
        "multisig.set_cosigners",
        WalletRpcMethod::JsonMultisigSetCosigners,
        Some(10),
        ROLES_ADMIN,
    ),
    (
        "multisig.export",
        WalletRpcMethod::JsonMultisigExport,
        Some(10),
        ROLES_OPERATOR,
    ),
    (
        "estimate_fee",
        WalletRpcMethod::JsonEstimateFee,
        Some(120),
        ROLES_VIEWER,
    ),
    (
        "list_pending_locks",
        WalletRpcMethod::JsonListPendingLocks,
        Some(60),
        ROLES_VIEWER,
    ),
    (
        "release_pending_locks",
        WalletRpcMethod::JsonReleasePendingLocks,
        Some(30),
        ROLES_OPERATOR,
    ),
    (
        "sync_status",
        WalletRpcMethod::JsonSyncStatus,
        Some(60),
        ROLES_VIEWER,
    ),
    (
        "watch_only.status",
        WalletRpcMethod::JsonWatchOnlyStatus,
        Some(60),
        ROLES_VIEWER,
    ),
    (
        "watch_only.enable",
        WalletRpcMethod::JsonWatchOnlyEnable,
        Some(6),
        ROLES_ADMIN,
    ),
    (
        "watch_only.disable",
        WalletRpcMethod::JsonWatchOnlyDisable,
        Some(6),
        ROLES_ADMIN,
    ),
    (
        "rescan",
        WalletRpcMethod::JsonRescan,
        Some(6),
        ROLES_OPERATOR,
    ),
    (
        "zsi.prove",
        WalletRpcMethod::JsonZsiProve,
        Some(10),
        ROLES_OPERATOR,
    ),
    (
        "zsi.verify",
        WalletRpcMethod::JsonZsiVerify,
        Some(60),
        ROLES_VIEWER,
    ),
    (
        "zsi.bind_account",
        WalletRpcMethod::JsonZsiBindAccount,
        Some(10),
        ROLES_OPERATOR,
    ),
    (
        "zsi.list",
        WalletRpcMethod::JsonZsiList,
        Some(60),
        ROLES_VIEWER,
    ),
    (
        "zsi.delete",
        WalletRpcMethod::JsonZsiDelete,
        Some(30),
        ROLES_OPERATOR,
    ),
];

struct WalletRpcServer {
    handlers: HashMap<&'static str, JsonRpcHandler>,
    fallback: JsonRpcHandler,
    security: Arc<WalletSecurityContext>,
}

impl WalletRpcServer {
    fn new(
        router: Arc<WalletRpcRouter>,
        metrics: Arc<RuntimeMetrics>,
        config: &WalletRuntimeConfig,
    ) -> ChainResult<Self> {
        let security = config.security_context();
        let audit = Arc::new(WalletAuditLogger::from_config(config.audit_settings())?);
        let mut handlers = HashMap::new();
        for (name, method, limit, roles) in JSON_RPC_METHODS {
            let handler = Self::build_handler(
                Arc::clone(&router),
                Arc::clone(&metrics),
                config,
                *name,
                *method,
                *limit,
                roles,
                Arc::clone(&audit),
            );
            handlers.insert(*name, handler);
        }
        let fallback = Self::build_handler(
            router,
            metrics,
            config,
            "unknown",
            WalletRpcMethod::Unknown,
            None,
            ROLES_ANY,
            audit,
        );
        Ok(Self {
            handlers,
            fallback,
            security,
        })
    }

    fn build_handler(
        router: Arc<WalletRpcRouter>,
        metrics: Arc<RuntimeMetrics>,
        config: &WalletRuntimeConfig,
        method_name: &'static str,
        method: WalletRpcMethod,
        limit_hint: Option<u64>,
        required_roles: &'static [WalletRole],
        audit: Arc<WalletAuditLogger>,
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
            method_name,
            rate_limit,
            required_roles,
            audit,
        )
    }

    fn handler_for(&self, method: &str) -> &JsonRpcHandler {
        self.handlers.get(method).unwrap_or(&self.fallback)
    }
}

pub fn json_rpc_router(
    wallet_router: Arc<WalletRpcRouter>,
    metrics: Arc<RuntimeMetrics>,
    config: &mut WalletRuntimeConfig,
) -> Result<Router, ChainError> {
    config.ensure_security_context()?;
    let server = Arc::new(WalletRpcServer::new(
        wallet_router,
        Arc::clone(&metrics),
        config,
    )?);
    let cors = build_cors_layer(config)?;
    Ok(Router::new()
        .route("/rpc", post(wallet_rpc_handler))
        .with_state(server)
        .layer(cors))
}

async fn wallet_rpc_handler(
    State(server): State<Arc<WalletRpcServer>>,
    client_certs: Option<Extension<Arc<WalletClientCertificates>>>,
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
                None,
                None,
            );
        }
    };

    let id = request.id.clone();
    let method = request.method.clone();
    let token_owned = bearer_token(&headers);
    let certificate_view = client_certs
        .as_ref()
        .map(|Extension(certs)| Arc::as_ref(certs));
    let identities = request_identities(&headers, token_owned.as_deref(), certificate_view);
    let roles = server.security.resolve_roles(&identities);
    let invocation = RpcInvocation {
        request: RpcRequest {
            bearer_token: token_owned.as_deref(),
            identities,
            roles,
        },
        payload: request,
    };

    let handler = server.handler_for(method.as_str());
    match handler.call(invocation) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(err) => rpc_error_response(
            err.status(),
            id,
            err.code(),
            err.to_string(),
            err.wallet_code().cloned(),
            err.details().cloned(),
        ),
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
    wallet_code: Option<WalletRpcErrorCode>,
    details: Option<Value>,
) -> Response {
    let message = message.into();
    let error = if let Some(wallet_code) = wallet_code {
        let payload = wallet_code.data_payload(details);
        JsonRpcError::new(code, message, Some(payload))
    } else {
        JsonRpcError::new(code, message, details)
    };
    (status, Json(JsonRpcResponse::error(id, error))).into_response()
}

fn request_identities(
    headers: &HeaderMap,
    bearer: Option<&str>,
    client_certs: Option<&WalletClientCertificates>,
) -> Vec<WalletIdentity> {
    let mut identities = Vec::new();
    if let Some(token) = bearer {
        identities.push(WalletIdentity::from_bearer_token(token));
    }
    if let Some(certs) = client_certs {
        identities.extend(certs.identities());
    }
    if let Some(identity) = certificate_identity(headers) {
        identities.push(identity);
    }
    identities
}

fn certificate_identity(headers: &HeaderMap) -> Option<WalletIdentity> {
    const HEADER_PEM: &str = "x-client-cert";
    const HEADER_FINGERPRINT: &str = "x-client-cert-sha256";

    if let Some(value) = headers.get(HEADER_FINGERPRINT) {
        let fingerprint = value.to_str().ok()?;
        return WalletIdentity::from_certificate_fingerprint(fingerprint).ok();
    }

    if let Some(value) = headers.get(HEADER_PEM) {
        let pem = value.to_str().ok()?;
        return WalletIdentity::from_certificate_pem(pem).ok();
    }

    None
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
