use std::time::Duration;

use reqwest::{Client, Identity, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "wallet_rpc_mtls")]
use super::dto::WalletRoleDto;
use super::dto::{
    BackupExportParams, BackupExportResponse, BackupImportParams, BackupImportResponse,
    BackupValidateParams, BackupValidateResponse, BalanceResponse, BroadcastParams,
    BroadcastRawParams, BroadcastRawResponse, BroadcastResponse, CosignerDto, CreateTxParams,
    CreateTxResponse, DeriveAddressParams, DeriveAddressResponse, EstimateFeeParams,
    EstimateFeeResponse, GetCosignersResponse, GetMultisigScopeResponse, GetPolicyResponse,
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, LifecycleStatusResponse,
    ListBranchAddressesParams, ListBranchAddressesResponse, ListPendingLocksResponse,
    ListTransactionsPageResponse, ListTransactionsParams, ListTransactionsResponse,
    ListUtxosResponse, MempoolInfoResponse, MultisigExportParams, MultisigExportResponse,
    MultisigScopeDto, PolicyPreviewResponse, RecentBlocksParams, RecentBlocksResponse,
    ReleasePendingLocksParams, ReleasePendingLocksResponse, RescanAbortResponse, RescanParams,
    RescanResponse, RescanStatusResponse, SecurityAssignParams, SecurityCertificateUploadParams,
    SecurityCertificateUploadResponse, SecurityMtlsUpdateParams, SecurityRemoveParams,
    SecuritySnapshotResponse, SetCosignersParams, SetCosignersResponse, SetMultisigScopeParams,
    SetMultisigScopeResponse, SetPolicyParams, SetPolicyResponse, SignTxParams, SignTxResponse,
    SyncStatusResponse, TelemetryCountersResponse, UpdateAddressMetadataParams,
    UpdateAddressMetadataResponse, WatchOnlyEnableParams, WatchOnlyStatusResponse, ZsiBindResponse,
    ZsiDeleteParams, ZsiDeleteResponse, ZsiListResponse, ZsiProofParams, ZsiProveResponse,
    ZsiVerifyParams, ZsiVerifyResponse, JSONRPC_VERSION,
};
#[cfg(feature = "wallet_hw")]
use super::dto::{HardwareEnumerateResponse, HardwareSignParams, HardwareSignResponse};
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
        client_identity: Option<Identity>,
        timeout: Duration,
    ) -> Result<Self, WalletRpcClientError> {
        let url = Self::normalize_endpoint(endpoint)?;
        Self::from_url(url, auth_token, client_identity, timeout)
    }

    /// Builds a new client from an already parsed [`Url`].
    pub fn from_url(
        url: Url,
        auth_token: Option<String>,
        client_identity: Option<Identity>,
        timeout: Duration,
    ) -> Result<Self, WalletRpcClientError> {
        let mut builder = Client::builder().timeout(timeout);
        if let Some(identity) = client_identity {
            builder = builder.identity(identity);
        }
        let client = builder.build()?;
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

    /// Lists derived addresses for a specific branch using cursor-based pagination.
    pub async fn list_branch_addresses(
        &self,
        params: &ListBranchAddressesParams,
    ) -> Result<ListBranchAddressesResponse, WalletRpcClientError> {
        self.call("addresses.list", Some(params)).await
    }

    /// Updates the label and/or note associated with a derived address.
    pub async fn update_address_metadata(
        &self,
        params: &UpdateAddressMetadataParams,
    ) -> Result<UpdateAddressMetadataResponse, WalletRpcClientError> {
        self.call("addresses.update_metadata", Some(params)).await
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

    #[cfg(feature = "wallet_hw")]
    pub async fn hw_enumerate(&self) -> Result<HardwareEnumerateResponse, WalletRpcClientError> {
        self.call("hw.enumerate", Option::<Value>::None).await
    }

    #[cfg(feature = "wallet_hw")]
    pub async fn hw_sign(
        &self,
        params: &HardwareSignParams,
    ) -> Result<HardwareSignResponse, WalletRpcClientError> {
        self.call("hw.sign", Some(params)).await
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

    /// Broadcasts an externally signed transaction payload.
    pub async fn broadcast_raw(
        &self,
        params: &BroadcastRawParams,
    ) -> Result<BroadcastRawResponse, WalletRpcClientError> {
        self.call("broadcast_raw", Some(params)).await
    }

    /// Request the wallet to generate a lifecycle proof.
    pub async fn zsi_prove(
        &self,
        params: &ZsiProofParams,
    ) -> Result<ZsiProveResponse, WalletRpcClientError> {
        self.call("zsi.prove", Some(params)).await
    }

    /// Verify a lifecycle proof against the configured backend.
    pub async fn zsi_verify(
        &self,
        params: &ZsiVerifyParams,
    ) -> Result<ZsiVerifyResponse, WalletRpcClientError> {
        self.call("zsi.verify", Some(params)).await
    }

    /// Bind an identity record to a witness payload.
    pub async fn zsi_bind_account(
        &self,
        params: &ZsiProofParams,
    ) -> Result<ZsiBindResponse, WalletRpcClientError> {
        self.call("zsi.bind_account", Some(params)).await
    }

    /// List cached lifecycle proof artefacts.
    pub async fn zsi_list(&self) -> Result<ZsiListResponse, WalletRpcClientError> {
        self.call("zsi.list", Option::<Value>::None).await
    }

    /// Delete a cached lifecycle proof artefact.
    pub async fn zsi_delete(
        &self,
        params: &ZsiDeleteParams,
    ) -> Result<ZsiDeleteResponse, WalletRpcClientError> {
        self.call("zsi.delete", Some(params)).await
    }

    pub async fn get_multisig_scope(
        &self,
    ) -> Result<GetMultisigScopeResponse, WalletRpcClientError> {
        self.call("multisig.get_scope", Option::<Value>::None).await
    }

    pub async fn set_multisig_scope(
        &self,
        scope: Option<&MultisigScopeDto>,
    ) -> Result<SetMultisigScopeResponse, WalletRpcClientError> {
        let params = SetMultisigScopeParams {
            scope: scope.cloned(),
        };
        self.call("multisig.set_scope", Some(&params)).await
    }

    pub async fn get_cosigners(&self) -> Result<GetCosignersResponse, WalletRpcClientError> {
        self.call("multisig.get_cosigners", Option::<Value>::None)
            .await
    }

    pub async fn set_cosigners(
        &self,
        cosigners: &[CosignerDto],
    ) -> Result<SetCosignersResponse, WalletRpcClientError> {
        let params = SetCosignersParams {
            cosigners: cosigners.to_vec(),
        };
        self.call("multisig.set_cosigners", Some(&params)).await
    }

    pub async fn export_multisig_metadata(
        &self,
        draft_id: &str,
    ) -> Result<MultisigExportResponse, WalletRpcClientError> {
        let params = MultisigExportParams {
            draft_id: draft_id.to_owned(),
        };
        self.call("multisig.export", Some(&params)).await
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

    /// Retrieves the current watch-only status snapshot.
    pub async fn watch_only_status(&self) -> Result<WatchOnlyStatusResponse, WalletRpcClientError> {
        self.call("watch_only.status", Option::<Value>::None).await
    }

    /// Enables watch-only mode using the supplied descriptors.
    pub async fn watch_only_enable(
        &self,
        params: &WatchOnlyEnableParams,
    ) -> Result<WatchOnlyStatusResponse, WalletRpcClientError> {
        self.call("watch_only.enable", Some(params)).await
    }

    /// Disables watch-only mode and re-enables signing operations.
    pub async fn watch_only_disable(
        &self,
    ) -> Result<WatchOnlyStatusResponse, WalletRpcClientError> {
        self.call("watch_only.disable", Option::<Value>::None).await
    }

    /// Fetches the wallet security snapshot including RBAC assignments and mTLS state.
    #[cfg(feature = "wallet_rpc_mtls")]
    pub async fn security_snapshot(
        &self,
    ) -> Result<SecuritySnapshotResponse, WalletRpcClientError> {
        self.call("security.snapshot", Option::<Value>::None).await
    }

    #[cfg(not(feature = "wallet_rpc_mtls"))]
    pub async fn security_snapshot(
        &self,
    ) -> Result<SecuritySnapshotResponse, WalletRpcClientError> {
        Err(mtls_rpc_disabled("security.snapshot"))
    }

    /// Applies a new RBAC assignment for the provided identity.
    #[cfg(feature = "wallet_rpc_mtls")]
    pub async fn security_assign(
        &self,
        params: &SecurityAssignParams,
    ) -> Result<SecuritySnapshotResponse, WalletRpcClientError> {
        self.call("security.assign", Some(params)).await
    }

    #[cfg(not(feature = "wallet_rpc_mtls"))]
    pub async fn security_assign(
        &self,
        _params: &SecurityAssignParams,
    ) -> Result<SecuritySnapshotResponse, WalletRpcClientError> {
        Err(mtls_rpc_disabled("security.assign"))
    }

    /// Removes an RBAC assignment for the provided identity.
    #[cfg(feature = "wallet_rpc_mtls")]
    pub async fn security_remove(
        &self,
        params: &SecurityRemoveParams,
    ) -> Result<SecuritySnapshotResponse, WalletRpcClientError> {
        self.call("security.remove", Some(params)).await
    }

    #[cfg(not(feature = "wallet_rpc_mtls"))]
    pub async fn security_remove(
        &self,
        _params: &SecurityRemoveParams,
    ) -> Result<SecuritySnapshotResponse, WalletRpcClientError> {
        Err(mtls_rpc_disabled("security.remove"))
    }

    /// Toggles the wallet mTLS configuration state.
    #[cfg(feature = "wallet_rpc_mtls")]
    pub async fn security_update_mtls(
        &self,
        params: &SecurityMtlsUpdateParams,
    ) -> Result<SecuritySnapshotResponse, WalletRpcClientError> {
        self.call("security.mtls_update", Some(params)).await
    }

    #[cfg(not(feature = "wallet_rpc_mtls"))]
    pub async fn security_update_mtls(
        &self,
        _params: &SecurityMtlsUpdateParams,
    ) -> Result<SecuritySnapshotResponse, WalletRpcClientError> {
        Err(mtls_rpc_disabled("security.mtls_update"))
    }

    /// Uploads certificate artifacts for the wallet RPC server.
    #[cfg(feature = "wallet_rpc_mtls")]
    pub async fn security_upload_certificate(
        &self,
        params: &SecurityCertificateUploadParams,
    ) -> Result<SecurityCertificateUploadResponse, WalletRpcClientError> {
        self.call("security.certificate_upload", Some(params)).await
    }

    #[cfg(not(feature = "wallet_rpc_mtls"))]
    pub async fn security_upload_certificate(
        &self,
        _params: &SecurityCertificateUploadParams,
    ) -> Result<SecurityCertificateUploadResponse, WalletRpcClientError> {
        Err(mtls_rpc_disabled("security.certificate_upload"))
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

    /// Retrieves the current embedded node lifecycle status.
    pub async fn lifecycle_status(&self) -> Result<LifecycleStatusResponse, WalletRpcClientError> {
        self.call("lifecycle.status", Option::<Value>::None).await
    }

    /// Attempts to start the embedded node runtime.
    pub async fn lifecycle_start(&self) -> Result<LifecycleStatusResponse, WalletRpcClientError> {
        self.call("lifecycle.start", Option::<Value>::None).await
    }

    /// Attempts to stop the embedded node runtime.
    pub async fn lifecycle_stop(&self) -> Result<LifecycleStatusResponse, WalletRpcClientError> {
        self.call("lifecycle.stop", Option::<Value>::None).await
    }

    /// Exports an encrypted wallet backup archive.
    pub async fn backup_export(
        &self,
        params: &BackupExportParams,
    ) -> Result<BackupExportResponse, WalletRpcClientError> {
        self.call("backup.export", Some(params)).await
    }

    /// Validates an encrypted wallet backup archive.
    pub async fn backup_validate(
        &self,
        params: &BackupValidateParams,
    ) -> Result<BackupValidateResponse, WalletRpcClientError> {
        self.call("backup.validate", Some(params)).await
    }

    /// Imports an encrypted wallet backup archive.
    pub async fn backup_import(
        &self,
        params: &BackupImportParams,
    ) -> Result<BackupImportResponse, WalletRpcClientError> {
        self.call("backup.import", Some(params)).await
    }

    /// Returns aggregate mempool statistics from the connected node.
    pub async fn mempool_info(&self) -> Result<MempoolInfoResponse, WalletRpcClientError> {
        self.call("mempool_info", Option::<Value>::None).await
    }

    /// Returns fee-related metadata for the most recent blocks.
    pub async fn recent_blocks(
        &self,
        limit: u32,
    ) -> Result<RecentBlocksResponse, WalletRpcClientError> {
        let params = RecentBlocksParams { limit: Some(limit) };
        self.call("recent_blocks", Some(&params)).await
    }

    /// Fetches the latest sampled telemetry counters, if available.
    pub async fn telemetry_counters(
        &self,
    ) -> Result<TelemetryCountersResponse, WalletRpcClientError> {
        self.call("telemetry_counters", Option::<Value>::None).await
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

    /// Returns status information about the currently scheduled rescan, if any.
    pub async fn rescan_status(&self) -> Result<RescanStatusResponse, WalletRpcClientError> {
        self.call("rescan.status", Option::<Value>::None).await
    }

    /// Attempts to abort the active or pending rescan.
    pub async fn rescan_abort(&self) -> Result<RescanAbortResponse, WalletRpcClientError> {
        self.call("rescan.abort", Option::<Value>::None).await
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

#[cfg(not(feature = "wallet_rpc_mtls"))]
fn mtls_rpc_disabled(method: &'static str) -> WalletRpcClientError {
    WalletRpcClientError::UnsupportedFeature {
        feature: "wallet_rpc_mtls",
        details: format!("{method} RPC requires wallet RPC mTLS support"),
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
    #[error("wallet RPC client feature `{feature}` unavailable: {details}")]
    UnsupportedFeature {
        feature: &'static str,
        details: String,
    },
}
