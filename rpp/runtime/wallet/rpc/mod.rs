use std::fmt;
use std::sync::Arc;
use std::time::Instant;

use http::StatusCode;

use crate::errors::ChainError;
use crate::runtime::telemetry::metrics::{RpcMethod, RpcResult, RuntimeMetrics, WalletRpcMethod};

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
    message: String,
}

impl RpcError {
    /// Constructs an unauthorized error with a friendly message.
    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "wallet RPC authentication failed".to_string(),
        }
    }

    /// Status code associated with the error.
    pub fn status(&self) -> StatusCode {
        self.status
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

/// Wrapper ensuring that RPC handlers are only executed when authorized.
pub struct AuthenticatedRpcHandler<H> {
    authenticator: Arc<dyn Authenticator>,
    handler: H,
    metrics: Arc<RuntimeMetrics>,
    method: WalletRpcMethod,
}

impl<H> AuthenticatedRpcHandler<H> {
    pub fn new(
        authenticator: impl Authenticator + 'static,
        handler: H,
        metrics: Arc<RuntimeMetrics>,
        method: WalletRpcMethod,
    ) -> Self {
        Self {
            authenticator: Arc::new(authenticator),
            handler,
            metrics,
            method,
        }
    }
}

impl<H, R> AuthenticatedRpcHandler<H>
where
    H: Fn(RpcRequest<'_>) -> R + Send + Sync,
{
    pub fn call(&self, request: RpcRequest<'_>) -> Result<R, RpcError> {
        let start = Instant::now();
        if !self.authenticator.authenticate(request.bearer_token) {
            let duration = start.elapsed();
            self.metrics
                .record_wallet_rpc_latency(self.method, duration);
            self.metrics.record_rpc_request(
                RpcMethod::Wallet(self.method),
                RpcResult::ClientError,
                duration,
            );
            return Err(RpcError::unauthorized());
        }
        let response = (self.handler)(request.clone());
        let duration = start.elapsed();
        self.metrics
            .record_wallet_rpc_latency(self.method, duration);
        self.metrics.record_rpc_request(
            RpcMethod::Wallet(self.method),
            RpcResult::Success,
            duration,
        );
        Ok(response)
    }
}

impl From<RpcError> for ChainError {
    fn from(err: RpcError) -> Self {
        ChainError::Config(err.to_string())
    }
}

/// Convenience helper for constructing an authenticated handler from a closure.
pub fn authenticated_handler<H, R>(
    authenticator: impl Authenticator + 'static,
    handler: H,
    metrics: Arc<RuntimeMetrics>,
    method: WalletRpcMethod,
) -> AuthenticatedRpcHandler<H>
where
    H: Fn(RpcRequest<'_>) -> R + Send + Sync,
{
    AuthenticatedRpcHandler::new(authenticator, handler, metrics, method)
}
