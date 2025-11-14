use std::time::Duration;

use reqwest::{Client, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::dto::{
    BalanceResponse, BroadcastParams, BroadcastResponse, CreateTxParams, CreateTxResponse,
    DeriveAddressParams, DeriveAddressResponse, EstimateFeeParams, EstimateFeeResponse,
    GetPolicyResponse, JsonRpcError, JsonRpcRequest, JsonRpcResponse, ListPendingLocksResponse,
    ListTransactionsPageResponse, ListTransactionsParams, ListTransactionsResponse,
    ListUtxosResponse, PolicyPreviewResponse, ReleasePendingLocksParams,
    ReleasePendingLocksResponse, RescanParams, RescanResponse, SetPolicyParams, SetPolicyResponse,
    SignTxParams, SignTxResponse, SyncStatusResponse, JSONRPC_VERSION,
};
use super::error::WalletRpcErrorCode;

/// Typed JSON-RPC client for the wallet service.
#[derive(Clone)]
pub struct WalletRpcClient {
    inner: Client,
    url: Url,
    auth_token: Option<String>,
}

impl WalletRpcClient {
    /// Builds a new client from a string endpoint, normalising the `/rpc` suffix if needed.
    pub fn from_endpoint(
        endpoint: &str,
        auth_token: Option<String>,
        timeout: Duration,
    ) -> Result<Self, WalletRpcClientError> {
        let url = Self::normalize_endpoint(endpoint)?;
        Self::from_url(url, auth_token, timeout)
    }

    /// Builds a new client from an already parsed [`Url`].
    pub fn from_url(
        url: Url,
        auth_token: Option<String>,
        timeout: Duration,
    ) -> Result<Self, WalletRpcClientError> {
        let client = Client::builder().timeout(timeout).build()?;
        Ok(Self {
            inner: client,
            url: Self::normalize_url(url),
            auth_token,
        })
    }

    /// Returns the RPC endpoint used by the client.
    pub fn endpoint(&self) -> &Url {
        &self.url
    }

    /// Issues a raw JSON-RPC call returning the untyped [`Value`] payload.
    pub async fn request<P: Serialize>(
        &self,
        method: &str,
        params: Option<P>,
    ) -> Result<Value, WalletRpcClientError> {
        let payload = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(Value::from(1)),
            method: method.to_owned(),
            params: params
                .map(serde_json::to_value)
                .transpose()
                .map_err(WalletRpcClientError::from)?,
        };

        let mut request = self.inner.post(self.url.clone()).json(&payload);
        if let Some(token) = &self.auth_token {
            request = request.bearer_auth(token);
        }

        let response = request.send().await?;
        if !response.status().is_success() {
            return Err(WalletRpcClientError::HttpStatus(response.status()));
        }

        let response: JsonRpcResponse = response.json().await?;
        if let Some(error) = response.error {
            let (code, details) = rpc_error_payload(&error);
            return Err(WalletRpcClientError::Rpc {
                code,
                message: error.message,
                json_code: error.code,
                details,
            });
        }

        response.result.ok_or(WalletRpcClientError::EmptyResponse)
    }

    /// Issues a JSON-RPC call and deserialises the result into `R`.
    pub async fn call<P, R>(
        &self,
        method: &str,
        params: Option<P>,
    ) -> Result<R, WalletRpcClientError>
    where
        P: Serialize,
        R: DeserializeOwned,
    {
        let value = self.request(method, params).await?;
        Ok(serde_json::from_value(value)?)
    }

    /// Fetches the wallet balance snapshot.
    pub async fn get_balance(&self) -> Result<BalanceResponse, WalletRpcClientError> {
        self.call("get_balance", Option::<Value>::None).await
    }

    /// Lists spendable UTXOs tracked by the wallet.
    pub async fn list_utxos(&self) -> Result<ListUtxosResponse, WalletRpcClientError> {
        self.call("list_utxos", Option::<Value>::None).await
    }

    /// Lists cached transaction history entries.
    pub async fn list_transactions(
        &self,
    ) -> Result<ListTransactionsResponse, WalletRpcClientError> {
        self.call("list_txs", Option::<Value>::None).await
    }

    /// Lists transaction history entries using the provided filters.
    pub async fn list_transactions_filtered(
        &self,
        params: &ListTransactionsParams,
    ) -> Result<ListTransactionsPageResponse, WalletRpcClientError> {
        self.call("list_txs", Some(params)).await
    }

    /// Derives a new address, optionally from the change branch.
    pub async fn derive_address(
        &self,
        change: bool,
    ) -> Result<DeriveAddressResponse, WalletRpcClientError> {
        let params = DeriveAddressParams { change };
        self.call("derive_address", Some(&params)).await
    }

    /// Builds a draft transaction using the provided parameters.
    pub async fn create_tx(
        &self,
        params: &CreateTxParams,
    ) -> Result<CreateTxResponse, WalletRpcClientError> {
        self.call("create_tx", Some(params)).await
    }

    /// Signs an existing draft transaction.
    pub async fn sign_tx(&self, draft_id: &str) -> Result<SignTxResponse, WalletRpcClientError> {
        let params = SignTxParams {
            draft_id: draft_id.to_owned(),
        };
        self.call("sign_tx", Some(&params)).await
    }

    /// Broadcasts a signed draft transaction to the node.
    pub async fn broadcast(
        &self,
        draft_id: &str,
    ) -> Result<BroadcastResponse, WalletRpcClientError> {
        let params = BroadcastParams {
            draft_id: draft_id.to_owned(),
        };
        self.call("broadcast", Some(&params)).await
    }

    /// Fetches the compiled policy preview from the runtime.
    pub async fn policy_preview(&self) -> Result<PolicyPreviewResponse, WalletRpcClientError> {
        self.call("policy_preview", Option::<Value>::None).await
    }

    /// Fetches the persisted policy snapshot, if any.
    pub async fn get_policy(&self) -> Result<GetPolicyResponse, WalletRpcClientError> {
        self.call("get_policy", Option::<Value>::None).await
    }

    /// Persists a new policy snapshot.
    pub async fn set_policy(
        &self,
        params: &SetPolicyParams,
    ) -> Result<SetPolicyResponse, WalletRpcClientError> {
        self.call("set_policy", Some(params)).await
    }

    /// Estimates the fee rate for a given confirmation target.
    pub async fn estimate_fee(
        &self,
        confirmation_target: u16,
    ) -> Result<EstimateFeeResponse, WalletRpcClientError> {
        let params = EstimateFeeParams {
            confirmation_target,
        };
        self.call("estimate_fee", Some(&params)).await
    }

    /// Lists all pending locks tracked by the engine.
    pub async fn list_pending_locks(
        &self,
    ) -> Result<ListPendingLocksResponse, WalletRpcClientError> {
        self.call("list_pending_locks", Option::<Value>::None).await
    }

    /// Releases all pending locks, returning the entries that were freed.
    pub async fn release_pending_locks(
        &self,
    ) -> Result<ReleasePendingLocksResponse, WalletRpcClientError> {
        self.call("release_pending_locks", Some(ReleasePendingLocksParams))
            .await
    }

    /// Fetches the latest sync status snapshot.
    pub async fn sync_status(&self) -> Result<SyncStatusResponse, WalletRpcClientError> {
        self.call("sync_status", Option::<Value>::None).await
    }

    /// Schedules a wallet rescan using the provided parameters.
    pub async fn rescan(
        &self,
        params: &RescanParams,
    ) -> Result<RescanResponse, WalletRpcClientError> {
        self.call("rescan", Some(params)).await
    }

    /// Toggles telemetry sampling for forthcoming GUI workflows.
    pub async fn toggle_telemetry(&self, enabled: bool) -> Result<bool, WalletRpcClientError> {
        #[derive(Serialize)]
        struct TelemetryToggleParams {
            enabled: bool,
        }

        #[derive(Deserialize)]
        struct TelemetryToggleResponse {
            enabled: bool,
        }

        let params = TelemetryToggleParams { enabled };
        let response: TelemetryToggleResponse =
            self.call("telemetry_toggle", Some(&params)).await?;
        Ok(response.enabled)
    }

    fn normalize_endpoint(endpoint: &str) -> Result<Url, WalletRpcClientError> {
        let url = Url::parse(endpoint)
            .map_err(|err| WalletRpcClientError::InvalidEndpoint(err.to_string()))?;
        Ok(Self::normalize_url(url))
    }

    fn normalize_url(mut url: Url) -> Url {
        let mut path = url.path().to_string();
        if path.is_empty() || path == "/" {
            url.set_path("/rpc");
        } else if !path.ends_with("/rpc") {
            if path.ends_with('/') {
                path.truncate(path.len() - 1);
            }
            path.push_str("/rpc");
            url.set_path(&path);
        }
        url
    }
}

fn rpc_error_payload(error: &JsonRpcError) -> (WalletRpcErrorCode, Option<Value>) {
    if let Some(Value::Object(map)) = &error.data {
        let code = map
            .get("code")
            .and_then(|value| value.as_str())
            .map(WalletRpcErrorCode::from)
            .unwrap_or_else(|| WalletRpcErrorCode::Custom(format!("JSON_RPC_{}", error.code)));
        let details = map.get("details").cloned();
        (code, details)
    } else {
        (
            WalletRpcErrorCode::Custom(format!("JSON_RPC_{}", error.code)),
            None,
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WalletRpcClientError {
    #[error("invalid RPC endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("wallet RPC JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("wallet RPC transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("wallet RPC transport error: HTTP status {0}")]
    HttpStatus(StatusCode),
    #[error("wallet RPC returned an empty response")]
    EmptyResponse,
    #[error("wallet RPC error [{code}]: {message}")]
    Rpc {
        code: WalletRpcErrorCode,
        message: String,
        json_code: i32,
        details: Option<Value>,
    },
}
