use std::future::Future;
use std::time::Duration;

use iced::Command;
use tokio::time;

use crate::rpc::client::{WalletRpcClient, WalletRpcClientError};

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
    rpc_with_timeout(client, DEFAULT_RPC_TIMEOUT, action, map)
}

/// Variant of [`rpc`] allowing the timeout to be customised per call.
pub fn rpc_with_timeout<Message, F, Fut, T>(
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
    Command::perform(
        async move {
            match time::timeout(timeout, action(client)).await {
                Ok(result) => result.map_err(RpcCallError::from),
                Err(_) => Err(RpcCallError::Timeout(timeout)),
            }
        },
        map,
    )
}
