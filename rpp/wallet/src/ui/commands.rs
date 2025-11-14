use std::future::Future;
use std::time::{Duration, Instant};

use iced::Command;
use tokio::time;

use crate::rpc::client::{WalletRpcClient, WalletRpcClientError};

use super::telemetry;

/// Default timeout applied to wallet RPC calls triggered from the UI.
pub const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(15);

/// Error surfaced by the RPC command helpers.
#[derive(Debug, Clone)]
pub enum RpcCallError {
    /// The request future timed out.
    Timeout(Duration),
    /// The underlying RPC client returned an error.
    Client(WalletRpcClientError),
}

impl From<WalletRpcClientError> for RpcCallError {
    fn from(value: WalletRpcClientError) -> Self {
        Self::Client(value)
    }
}

/// Spawns an RPC call wrapped into an [`iced::Command`], enforcing a timeout and converting
/// the result into [`RpcCallError`] on failure.
pub fn rpc<Message, F, Fut, T>(
    method: &'static str,
    client: WalletRpcClient,
    action: F,
    map: fn(Result<T, RpcCallError>) -> Message,
) -> Command<Message>
where
    Message: 'static,
    F: FnOnce(WalletRpcClient) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, WalletRpcClientError>> + Send + 'static,
    T: Send + 'static,
{
    rpc_with_timeout(method, client, DEFAULT_RPC_TIMEOUT, action, map)
}

/// Variant of [`rpc`] allowing the timeout to be customised per call.
pub fn rpc_with_timeout<Message, F, Fut, T>(
    method: &'static str,
    client: WalletRpcClient,
    timeout: Duration,
    action: F,
    map: fn(Result<T, RpcCallError>) -> Message,
) -> Command<Message>
where
    Message: 'static,
    F: FnOnce(WalletRpcClient) -> Fut + Send + 'static,
    Fut: Future<Output = Result<T, WalletRpcClientError>> + Send + 'static,
    T: Send + 'static,
{
    let telemetry = telemetry::global();
    Command::perform(
        async move {
            let started = Instant::now();
            match time::timeout(timeout, action(client)).await {
                Ok(Ok(value)) => {
                    telemetry.record_rpc_success(method, started.elapsed());
                    Ok(value)
                }
                Ok(Err(error)) => {
                    telemetry.record_rpc_client_error(method, started.elapsed(), &error);
                    Err(RpcCallError::from(error))
                }
                Err(_) => {
                    telemetry.record_rpc_timeout(method, timeout);
                    Err(RpcCallError::Timeout(timeout))
                }
            }
        },
        map,
    )
}
