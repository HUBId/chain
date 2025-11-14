//! JSON-RPC facades for wallet subsystems.

pub mod dto;
pub mod zsi;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use dto::{
    BalanceResponse, BroadcastParams, BroadcastResponse, CreateTxParams, CreateTxResponse,
    DeriveAddressParams, DeriveAddressResponse, DraftInputDto, DraftOutputDto, DraftSpendModelDto,
    EmptyParams, EstimateFeeParams, EstimateFeeResponse, FeeEstimateSourceDto, GetPolicyResponse,
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, ListPendingLocksResponse,
    ListTransactionsResponse, ListUtxosResponse, PendingLockDto, PolicyPreviewResponse,
    PolicySnapshotDto, ReleasePendingLocksParams, ReleasePendingLocksResponse, RescanParams,
    RescanResponse, SetPolicyParams, SetPolicyResponse, SignTxParams, SignTxResponse,
    SyncCheckpointDto, SyncModeDto, SyncStatusParams, SyncStatusResponse, TransactionEntryDto,
    UtxoDto, JSONRPC_VERSION,
};
use hex::encode as hex_encode;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

use crate::db::{PendingLock, PolicySnapshot, TxCacheEntry, UtxoRecord};
use crate::engine::signing::ProverOutput;
use crate::engine::{DraftTransaction, SpendModel, WalletBalance};
use crate::indexer::scanner::{SyncMode, SyncStatus};
use crate::node_client::NodeClientError;
use crate::wallet::{PolicyPreview, Wallet, WalletError, WalletSyncCoordinator, WalletSyncError};

const CODE_INVALID_REQUEST: i32 = -32600;
const CODE_METHOD_NOT_FOUND: i32 = -32601;
const CODE_INVALID_PARAMS: i32 = -32602;
const CODE_INTERNAL_ERROR: i32 = -32603;
const CODE_WALLET_ERROR: i32 = -32010;
const CODE_SYNC_ERROR: i32 = -32020;
const CODE_NODE_ERROR: i32 = -32030;
const CODE_DRAFT_NOT_FOUND: i32 = -32040;
const CODE_DRAFT_UNSIGNED: i32 = -32041;
const CODE_SYNC_UNAVAILABLE: i32 = -32050;
const CODE_RESCAN_OUT_OF_RANGE: i32 = -32051;

#[derive(Clone, Debug)]
struct DraftState {
    draft: DraftTransaction,
    prover_output: Option<ProverOutput>,
}

pub trait SyncHandle: Send + Sync {
    fn is_syncing(&self) -> bool;
    fn latest_status(&self) -> Option<SyncStatus>;
    fn last_error(&self) -> Option<WalletSyncError>;
    fn request_rescan(&self, from_height: u64) -> Result<bool, WalletSyncError>;
    fn record_node_failure(&self, _error: &NodeClientError) {}
    fn clear_node_failure(&self) {}
}

impl SyncHandle for WalletSyncCoordinator {
    fn is_syncing(&self) -> bool {
        WalletSyncCoordinator::is_syncing(self)
    }

    fn latest_status(&self) -> Option<SyncStatus> {
        WalletSyncCoordinator::latest_status(self)
    }

    fn last_error(&self) -> Option<WalletSyncError> {
        WalletSyncCoordinator::last_error(self)
    }

    fn request_rescan(&self, from_height: u64) -> Result<bool, WalletSyncError> {
        WalletSyncCoordinator::request_rescan(self, from_height)
    }

    fn record_node_failure(&self, error: &NodeClientError) {
        WalletSyncCoordinator::record_node_failure(self, error);
    }

    fn clear_node_failure(&self) {
        WalletSyncCoordinator::clear_node_failure(self);
    }
}

pub struct WalletRpcRouter {
    wallet: Arc<Wallet>,
    drafts: Mutex<HashMap<String, DraftState>>,
    next_id: AtomicU64,
    sync: Option<Arc<dyn SyncHandle>>,
}

impl WalletRpcRouter {
    pub fn new(wallet: Arc<Wallet>, sync: Option<Arc<dyn SyncHandle>>) -> Self {
        Self {
            wallet,
            drafts: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            sync,
        }
    }

    fn record_node_failure(&self, error: &NodeClientError) {
        if let Some(sync) = &self.sync {
            sync.record_node_failure(error);
        }
    }

    fn clear_node_failure(&self) {
        if let Some(sync) = &self.sync {
            sync.clear_node_failure();
        }
    }

    fn wallet_call<T>(&self, result: Result<T, WalletError>) -> Result<T, RouterError> {
        match result {
            Ok(value) => {
                self.clear_node_failure();
                Ok(value)
            }
            Err(WalletError::Node(error)) => {
                self.record_node_failure(&error);
                Err(RouterError::Node(error))
            }
            Err(WalletError::Sync(sync)) => Err(RouterError::Sync(sync)),
            Err(other) => Err(RouterError::Wallet(other)),
        }
    }

    pub fn handle(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let JsonRpcRequest {
            jsonrpc,
            id,
            method,
            params,
        } = request;

        if jsonrpc
            .as_deref()
            .map_or(true, |value| value != JSONRPC_VERSION)
        {
            return JsonRpcResponse::error(
                id,
                RouterError::InvalidRequest("unsupported JSON-RPC version").into_json_error(),
            );
        }

        match self.dispatch(&method, params) {
            Ok(result) => JsonRpcResponse::success(id.clone(), result),
            Err(error) => JsonRpcResponse::error(id.clone(), error.into_json_error()),
        }
    }

    fn dispatch(&self, method: &str, params: Option<Value>) -> Result<Value, RouterError> {
        match method {
            "get_balance" => {
                parse_params::<EmptyParams>(params)?;
                let balance = self.wallet.balance()?;
                self.respond_balance(&balance)
            }
            "list_utxos" => {
                parse_params::<EmptyParams>(params)?;
                let utxos = self.wallet.list_utxos()?;
                self.respond_utxos(utxos)
            }
            "list_txs" => {
                parse_params::<EmptyParams>(params)?;
                let entries = self.wallet.list_transactions()?;
                self.respond_transactions(entries)
            }
            "derive_address" => {
                let params: DeriveAddressParams = parse_params(params)?;
                let address = self.wallet.derive_address(params.change)?;
                to_value(DeriveAddressResponse { address })
            }
            "create_tx" => {
                let params: CreateTxParams = parse_params(params)?;
                self.create_tx(params)
            }
            "sign_tx" => {
                let params: SignTxParams = parse_params(params)?;
                self.sign_draft(params.draft_id)
            }
            "broadcast" => {
                let params: BroadcastParams = parse_params(params)?;
                self.broadcast_draft(params.draft_id)
            }
            "policy_preview" => {
                parse_params::<EmptyParams>(params)?;
                let preview = self.wallet.policy_preview();
                self.respond_policy_preview(preview)
            }
            "get_policy" => {
                parse_params::<EmptyParams>(params)?;
                self.respond_policy_snapshot(self.wallet.get_policy_snapshot()?)
            }
            "set_policy" => {
                let params: SetPolicyParams = parse_params(params)?;
                let snapshot = self.wallet.set_policy_snapshot(params.statements)?;
                self.respond_policy_updated(snapshot)
            }
            "estimate_fee" => {
                let params: EstimateFeeParams = parse_params(params)?;
                self.estimate_fee(params)
            }
            "list_pending_locks" => {
                parse_params::<EmptyParams>(params)?;
                self.respond_pending_locks(self.wallet.pending_locks()?)
            }
            "release_pending_locks" => {
                let _params: ReleasePendingLocksParams = parse_params(params)?;
                let released = self.wallet.release_pending_locks()?;
                self.respond_released_locks(released)
            }
            "sync_status" => {
                parse_params::<SyncStatusParams>(params)?;
                self.respond_sync_status()
            }
            "rescan" => {
                let params: RescanParams = parse_params(params)?;
                self.handle_rescan(params)
            }
            _ => Err(RouterError::MethodNotFound(method.to_string())),
        }
    }

    fn respond_balance(&self, balance: &WalletBalance) -> Result<Value, RouterError> {
        let response = BalanceResponse {
            confirmed: balance.confirmed,
            pending: balance.pending,
            total: balance.total(),
        };
        to_value(response)
    }

    fn respond_utxos(&self, utxos: Vec<UtxoRecord<'static>>) -> Result<Value, RouterError> {
        let mapped: Vec<UtxoDto> = utxos
            .into_iter()
            .map(|record| UtxoDto {
                txid: hex_encode(record.outpoint.txid),
                index: record.outpoint.index,
                value: record.value,
                owner: record.owner,
                timelock: record.timelock,
            })
            .collect();
        to_value(ListUtxosResponse { utxos: mapped })
    }

    fn respond_transactions(
        &self,
        entries: Vec<([u8; 32], TxCacheEntry<'static>)>,
    ) -> Result<Value, RouterError> {
        let mapped: Vec<TransactionEntryDto> = entries
            .into_iter()
            .map(|(txid, entry)| TransactionEntryDto {
                txid: hex_encode(txid),
                height: entry.height,
                timestamp_ms: entry.timestamp_ms,
                payload_bytes: entry.payload.len(),
            })
            .collect();
        to_value(ListTransactionsResponse { entries: mapped })
    }

    fn create_tx(&self, params: CreateTxParams) -> Result<Value, RouterError> {
        let CreateTxParams {
            to,
            amount,
            fee_rate,
        } = params;
        let draft = self.wallet_call(self.wallet.create_draft(to, amount, fee_rate))?;
        let draft_id = self.store_draft(draft.clone())?;
        self.respond_draft(&draft_id, &draft)
    }

    fn respond_draft(
        &self,
        draft_id: &str,
        draft: &DraftTransaction,
    ) -> Result<Value, RouterError> {
        let inputs = draft
            .inputs
            .iter()
            .map(|input| DraftInputDto {
                txid: hex_encode(input.outpoint.txid),
                index: input.outpoint.index,
                value: input.value,
                confirmations: input.confirmations,
            })
            .collect();
        let outputs = draft
            .outputs
            .iter()
            .map(|output| DraftOutputDto {
                address: output.address.clone(),
                value: output.value,
                change: output.change,
            })
            .collect();
        let locks = self.pending_lock_dtos()?;
        let fee_source = self
            .wallet
            .latest_fee_quote()
            .map(|quote| FeeEstimateSourceDto::from(quote.source()));
        let response = CreateTxResponse {
            draft_id: draft_id.to_string(),
            fee_rate: draft.fee_rate,
            fee: draft.fee,
            fee_source,
            total_input_value: draft.total_input_value(),
            total_output_value: draft.total_output_value(),
            spend_model: spend_model_to_dto(&draft.spend_model),
            inputs,
            outputs,
            locks,
        };
        to_value(response)
    }

    fn estimate_fee(&self, params: EstimateFeeParams) -> Result<Value, RouterError> {
        let EstimateFeeParams {
            confirmation_target,
        } = params;
        let fee_rate = self.wallet_call(self.wallet.estimate_fee(confirmation_target))?;
        to_value(EstimateFeeResponse {
            confirmation_target,
            fee_rate,
        })
    }

    fn respond_policy_preview(&self, preview: PolicyPreview) -> Result<Value, RouterError> {
        let response = PolicyPreviewResponse {
            min_confirmations: preview.min_confirmations,
            dust_limit: preview.dust_limit,
            max_change_outputs: preview.max_change_outputs,
            spend_limit_daily: preview.spend_limit_daily,
            pending_lock_timeout: preview.pending_lock_timeout,
            tier_hooks: preview.tier_hooks,
        };
        to_value(response)
    }

    fn respond_policy_snapshot(
        &self,
        snapshot: Option<PolicySnapshot>,
    ) -> Result<Value, RouterError> {
        let dto = snapshot.map(policy_snapshot_to_dto);
        to_value(GetPolicyResponse { snapshot: dto })
    }

    fn respond_policy_updated(&self, snapshot: PolicySnapshot) -> Result<Value, RouterError> {
        let dto = policy_snapshot_to_dto(snapshot);
        to_value(SetPolicyResponse { snapshot: dto })
    }

    fn respond_pending_locks(&self, locks: Vec<PendingLock>) -> Result<Value, RouterError> {
        let locks = locks.into_iter().map(PendingLockDto::from).collect();
        to_value(ListPendingLocksResponse { locks })
    }

    fn respond_released_locks(&self, locks: Vec<PendingLock>) -> Result<Value, RouterError> {
        let released = locks.into_iter().map(PendingLockDto::from).collect();
        to_value(ReleasePendingLocksResponse { released })
    }

    fn respond_sync_status(&self) -> Result<Value, RouterError> {
        let sync = self.sync.as_ref().ok_or(RouterError::SyncUnavailable)?;
        let status = sync.latest_status();
        let (
            mode,
            latest_height,
            scanned_scripthashes,
            pending_ranges,
            checkpoints,
            last_rescan_timestamp,
            node_issue,
            hints,
        ) = if let Some(status) = status {
            (
                Some(match status.mode {
                    SyncMode::Full { start_height } => SyncModeDto::Full { start_height },
                    SyncMode::Resume { from_height } => SyncModeDto::Resume { from_height },
                    SyncMode::Rescan { from_height } => SyncModeDto::Rescan { from_height },
                }),
                Some(status.latest_height),
                Some(status.scanned_scripthashes),
                status.pending_ranges.clone(),
                Some(SyncCheckpointDto {
                    resume_height: status.checkpoints.resume_height,
                    birthday_height: status.checkpoints.birthday_height,
                    last_scan_ts: status.checkpoints.last_scan_ts,
                    last_full_rescan_ts: status.checkpoints.last_full_rescan_ts,
                    last_compact_scan_ts: status.checkpoints.last_compact_scan_ts,
                    last_targeted_rescan_ts: status.checkpoints.last_targeted_rescan_ts,
                }),
                status.checkpoints.last_targeted_rescan_ts,
                status.node_issue.clone(),
                status.hints.clone(),
            )
        } else {
            (None, None, None, Vec::new(), None, None, None, Vec::new())
        };
        let last_error = sync.last_error().map(|error| error.to_string());
        let response = SyncStatusResponse {
            syncing: sync.is_syncing(),
            mode,
            latest_height,
            scanned_scripthashes,
            pending_ranges,
            checkpoints,
            last_rescan_timestamp,
            last_error,
            node_issue,
            hints,
        };
        to_value(response)
    }

    fn handle_rescan(&self, params: RescanParams) -> Result<Value, RouterError> {
        let sync = self.sync.as_ref().ok_or(RouterError::SyncUnavailable)?;
        let status = sync.latest_status();
        let target_height = if let Some(explicit) = params.from_height {
            explicit
        } else if let Some(lookback) = params.lookback_blocks {
            let latest = status
                .as_ref()
                .ok_or_else(|| {
                    RouterError::InvalidParams("lookback rescan requires known height".into())
                })?
                .latest_height;
            latest.saturating_sub(lookback.min(latest))
        } else {
            return Err(RouterError::InvalidParams(
                "rescan requires either from_height or lookback_blocks".into(),
            ));
        };

        if let Some(status) = status {
            if target_height > status.latest_height {
                return Err(RouterError::RescanOutOfRange {
                    requested: target_height,
                    latest: status.latest_height,
                });
            }
        }
        let scheduled = sync.request_rescan(target_height)?;
        to_value(RescanResponse {
            scheduled,
            from_height: target_height,
        })
    }

    fn sign_draft(&self, draft_id: String) -> Result<Value, RouterError> {
        let mut drafts = self.lock_drafts()?;
        let state = drafts
            .get_mut(&draft_id)
            .ok_or_else(|| RouterError::MissingDraft(draft_id.clone()))?;
        let output = self.wallet.sign_and_prove(&state.draft)?;
        let proof_size = output.proof.as_ref().map(|proof| proof.as_ref().len());
        let locks = self.pending_lock_dtos()?;
        let response = SignTxResponse {
            draft_id: draft_id.clone(),
            backend: output.backend.clone(),
            witness_bytes: output.witness_bytes,
            proof_generated: output.proof.is_some(),
            proof_size,
            duration_ms: output.duration_ms,
            locks,
        };
        state.prover_output = Some(output);
        drop(drafts);
        to_value(response)
    }

    fn broadcast_draft(&self, draft_id: String) -> Result<Value, RouterError> {
        let mut drafts = self.lock_drafts()?;
        let state = drafts
            .get(&draft_id)
            .ok_or_else(|| RouterError::MissingDraft(draft_id.clone()))?;
        if state.prover_output.is_none() {
            return Err(RouterError::DraftUnsigned(draft_id));
        }
        self.wallet_call(self.wallet.broadcast(&state.draft))?;
        let locks = self.pending_lock_dtos()?;
        to_value(BroadcastResponse {
            draft_id,
            accepted: true,
            locks,
        })
    }

    fn store_draft(&self, draft: DraftTransaction) -> Result<String, RouterError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let identifier = format!("{id:016x}");
        let mut drafts = self.lock_drafts()?;
        drafts.insert(
            identifier.clone(),
            DraftState {
                draft,
                prover_output: None,
            },
        );
        Ok(identifier)
    }

    fn lock_drafts(&self) -> Result<MutexGuard<'_, HashMap<String, DraftState>>, RouterError> {
        self.drafts.lock().map_err(|_| RouterError::StatePoisoned)
    }

    fn pending_lock_dtos(&self) -> Result<Vec<PendingLockDto>, RouterError> {
        let locks = self.wallet.pending_locks()?;
        Ok(locks.into_iter().map(PendingLockDto::from).collect())
    }
}

#[derive(Debug)]
enum RouterError {
    InvalidRequest(&'static str),
    MethodNotFound(String),
    InvalidParams(String),
    Wallet(WalletError),
    Sync(WalletSyncError),
    Node(NodeClientError),
    MissingDraft(String),
    DraftUnsigned(String),
    SyncUnavailable,
    RescanOutOfRange { requested: u64, latest: u64 },
    StatePoisoned,
    Serialization(String),
}

impl RouterError {
    fn into_json_error(self) -> JsonRpcError {
        match self {
            RouterError::InvalidRequest(message) => {
                JsonRpcError::new(CODE_INVALID_REQUEST, message, None)
            }
            RouterError::MethodNotFound(method) => JsonRpcError::new(
                CODE_METHOD_NOT_FOUND,
                format!("method `{method}` not found"),
                None,
            ),
            RouterError::InvalidParams(message) => {
                JsonRpcError::new(CODE_INVALID_PARAMS, message, None)
            }
            RouterError::Wallet(error) => {
                JsonRpcError::new(CODE_WALLET_ERROR, error.to_string(), None)
            }
            RouterError::Sync(error) => JsonRpcError::new(CODE_SYNC_ERROR, error.to_string(), None),
            RouterError::Node(error) => node_error_to_json(&error),
            RouterError::MissingDraft(draft_id) => JsonRpcError::new(
                CODE_DRAFT_NOT_FOUND,
                "draft not found",
                Some(json!({ "draft_id": draft_id })),
            ),
            RouterError::DraftUnsigned(draft_id) => JsonRpcError::new(
                CODE_DRAFT_UNSIGNED,
                "draft must be signed before broadcasting",
                Some(json!({ "draft_id": draft_id })),
            ),
            RouterError::SyncUnavailable => JsonRpcError::new(
                CODE_SYNC_UNAVAILABLE,
                "wallet sync coordinator not configured",
                None,
            ),
            RouterError::RescanOutOfRange { requested, latest } => JsonRpcError::new(
                CODE_RESCAN_OUT_OF_RANGE,
                "rescan height is outside the indexed range",
                Some(json!({ "requested": requested, "latest": latest })),
            ),
            RouterError::StatePoisoned | RouterError::Serialization(_) => {
                JsonRpcError::new(CODE_INTERNAL_ERROR, "wallet router internal error", None)
            }
        }
    }
}

fn node_error_to_json(error: &NodeClientError) -> JsonRpcError {
    let mut data = serde_json::Map::new();
    data.insert("phase2_code".to_string(), json!(error.phase2_code()));
    let hints = error.hints();
    if !hints.is_empty() {
        data.insert("hints".to_string(), json!(hints));
    }
    JsonRpcError::new(
        CODE_NODE_ERROR,
        error.user_message(),
        Some(Value::Object(data)),
    )
}

impl From<WalletError> for RouterError {
    fn from(error: WalletError) -> Self {
        match error {
            WalletError::Sync(sync) => RouterError::Sync(sync),
            WalletError::Node(node) => RouterError::Node(node),
            other => RouterError::Wallet(other),
        }
    }
}

impl From<WalletSyncError> for RouterError {
    fn from(error: WalletSyncError) -> Self {
        RouterError::Sync(error)
    }
}

impl From<NodeClientError> for RouterError {
    fn from(error: NodeClientError) -> Self {
        RouterError::Node(error)
    }
}

fn parse_params<T: DeserializeOwned>(params: Option<Value>) -> Result<T, RouterError> {
    let value = params.unwrap_or(Value::Null);
    serde_json::from_value(value).map_err(|error| RouterError::InvalidParams(error.to_string()))
}

fn to_value<T: Serialize>(value: T) -> Result<Value, RouterError> {
    serde_json::to_value(value).map_err(|error| RouterError::Serialization(error.to_string()))
}

fn spend_model_to_dto(model: &SpendModel) -> DraftSpendModelDto {
    match model {
        SpendModel::Exact { amount } => DraftSpendModelDto::Exact { amount: *amount },
        SpendModel::Sweep => DraftSpendModelDto::Sweep,
        SpendModel::Account { debit } => DraftSpendModelDto::Account { debit: *debit },
    }
}

impl From<PendingLock> for PendingLockDto {
    fn from(lock: PendingLock) -> Self {
        PendingLockDto {
            utxo_txid: hex_encode(lock.outpoint.txid),
            utxo_index: lock.outpoint.index,
            locked_at_ms: lock.locked_at_ms,
            spending_txid: lock.spending_txid.map(hex_encode),
            backend: lock.metadata.backend,
            witness_bytes: lock.metadata.witness_bytes,
            prove_duration_ms: lock.metadata.prove_duration_ms,
            proof_bytes: lock.metadata.proof_bytes,
        }
    }
}

fn policy_snapshot_to_dto(snapshot: PolicySnapshot) -> PolicySnapshotDto {
    PolicySnapshotDto {
        revision: snapshot.revision,
        updated_at: snapshot.updated_at,
        statements: snapshot.statements,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::wallet::{WalletFeeConfig, WalletPolicyConfig, WalletProverConfig};
    use crate::db::UtxoOutpoint;
    use crate::db::WalletStore;
    use crate::engine::{DraftInput, DraftOutput, SpendModel};
    use crate::indexer::scanner::SyncCheckpoints;
    use crate::node_client::{
        BlockFeeSummary, ChainHead, MempoolInfo, NodeClient, NodeClientError, NodeClientResult,
        NodeRejectionHint, StubNodeClient,
    };
    use serde_json::json;
    use std::sync::Mutex;
    use tempfile::tempdir;

    fn build_router(sync: Option<Arc<dyn SyncHandle>>) -> WalletRpcRouter {
        let dir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(dir.path()).expect("store"));
        let wallet = Wallet::new(
            Arc::clone(&store),
            [0u8; 32],
            WalletPolicyConfig::default(),
            WalletFeeConfig::default(),
            WalletProverConfig::default(),
            Arc::new(StubNodeClient::default()),
        )
        .expect("wallet");
        let _persist = dir.into_path();
        WalletRpcRouter::new(Arc::new(wallet), sync)
    }

    #[test]
    fn router_reports_missing_draft() {
        let router = build_router(None);
        let request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(1)),
            method: "sign_tx".to_string(),
            params: Some(json!({ "draft_id": "deadbeef" })),
        };
        let response = router.handle(request);
        let error = response.error.expect("error");
        assert_eq!(error.code, CODE_DRAFT_NOT_FOUND);
    }

    #[derive(Clone)]
    struct StubSync {
        status: Option<SyncStatus>,
        syncing: bool,
    }

    impl SyncHandle for StubSync {
        fn is_syncing(&self) -> bool {
            self.syncing
        }

        fn latest_status(&self) -> Option<SyncStatus> {
            self.status.clone()
        }

        fn last_error(&self) -> Option<WalletSyncError> {
            None
        }

        fn request_rescan(&self, _from_height: u64) -> Result<bool, WalletSyncError> {
            panic!("rescan should not be invoked when height is invalid");
        }
    }

    #[derive(Default)]
    struct RecordingSync {
        status: Option<SyncStatus>,
        syncing: bool,
        issues: Mutex<Vec<String>>,
        hints: Mutex<Vec<String>>,
    }

    impl RecordingSync {
        fn issues(&self) -> Vec<String> {
            self.issues.lock().unwrap().clone()
        }

        fn hints(&self) -> Vec<String> {
            self.hints.lock().unwrap().clone()
        }
    }

    impl SyncHandle for RecordingSync {
        fn is_syncing(&self) -> bool {
            self.syncing
        }

        fn latest_status(&self) -> Option<SyncStatus> {
            self.status.clone()
        }

        fn last_error(&self) -> Option<WalletSyncError> {
            None
        }

        fn request_rescan(&self, _from_height: u64) -> Result<bool, WalletSyncError> {
            Ok(false)
        }

        fn record_node_failure(&self, error: &NodeClientError) {
            self.issues.lock().unwrap().push(error.user_message());
            self.hints.lock().unwrap().extend(error.hints());
        }

        fn clear_node_failure(&self) {
            self.issues.lock().unwrap().clear();
            self.hints.lock().unwrap().clear();
        }
    }

    #[derive(Clone)]
    struct RejectingNodeClient {
        inner: StubNodeClient,
    }

    impl RejectingNodeClient {
        fn new() -> Self {
            Self {
                inner: StubNodeClient::default(),
            }
        }
    }

    impl NodeClient for RejectingNodeClient {
        fn submit_tx(&self, _draft: &DraftTransaction) -> NodeClientResult<()> {
            Err(NodeClientError::rejected_with_hint(
                "mempool rejection",
                NodeRejectionHint::FeeRateTooLow { required: Some(25) },
            ))
        }

        fn estimate_fee(&self, confirmation_target: u16) -> NodeClientResult<u64> {
            self.inner.estimate_fee(confirmation_target)
        }

        fn chain_head(&self) -> NodeClientResult<ChainHead> {
            self.inner.chain_head()
        }

        fn mempool_status(&self) -> NodeClientResult<rpp::runtime::node::MempoolStatus> {
            self.inner.mempool_status()
        }

        fn mempool_info(&self) -> NodeClientResult<MempoolInfo> {
            self.inner.mempool_info()
        }

        fn recent_blocks(&self, limit: usize) -> NodeClientResult<Vec<BlockFeeSummary>> {
            self.inner.recent_blocks(limit)
        }
    }

    #[test]
    fn router_rejects_out_of_range_rescan() {
        let status = SyncStatus {
            latest_height: 10,
            mode: SyncMode::Resume { from_height: 10 },
            scanned_scripthashes: 2,
            pending_ranges: Vec::new(),
            checkpoints: SyncCheckpoints {
                resume_height: Some(10),
                ..SyncCheckpoints::default()
            },
            hints: Vec::new(),
            node_issue: None,
        };
        let sync = Arc::new(StubSync {
            status: Some(status),
            syncing: false,
        });
        let router = build_router(Some(sync));
        let request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(1)),
            method: "rescan".to_string(),
            params: Some(json!({ "from_height": 25 })),
        };
        let response = router.handle(request);
        let error = response.error.expect("error");
        assert_eq!(error.code, CODE_RESCAN_OUT_OF_RANGE);
    }

    #[test]
    fn node_error_conversion_adds_phase2_metadata() {
        let error = NodeClientError::rejected_with_hint(
            "policy",
            NodeRejectionHint::FeeRateTooLow { required: Some(15) },
        );
        let json_error = super::node_error_to_json(&error);
        assert_eq!(json_error.code, CODE_NODE_ERROR);
        assert_eq!(
            json_error.message,
            "node rejected transaction (fee rate too low (required 15 sats/vB))"
        );
        let data = json_error.data.expect("phase2 metadata");
        assert_eq!(data["phase2_code"], json!("FEE_TOO_LOW"));
        assert_eq!(
            data["hints"],
            json!(["Increase the fee rate to at least 15 sats/vB and retry."])
        );
    }

    #[test]
    fn broadcast_rejection_exposes_phase2_code() {
        let dir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(dir.path()).expect("store"));
        let wallet = Wallet::new(
            Arc::clone(&store),
            [0u8; 32],
            WalletPolicyConfig::default(),
            WalletFeeConfig::default(),
            WalletProverConfig::default(),
            Arc::new(RejectingNodeClient::new()),
        )
        .expect("wallet");
        let sync = Arc::new(RecordingSync::default());
        let router = WalletRpcRouter::new(Arc::new(wallet), Some(sync.clone()));

        let draft = DraftTransaction {
            inputs: vec![DraftInput {
                outpoint: UtxoOutpoint::new([1u8; 32], 0),
                value: 10_000,
                confirmations: 1,
            }],
            outputs: vec![DraftOutput::new("addr", 9_000, false)],
            fee_rate: 1,
            fee: 1_000,
            spend_model: SpendModel::Exact { amount: 9_000 },
        };
        let draft_id = "deadbeef".to_string();
        {
            let mut drafts = router.drafts.lock().unwrap();
            drafts.insert(
                draft_id.clone(),
                DraftState {
                    draft: draft.clone(),
                    prover_output: Some(ProverOutput {
                        backend: "test".to_string(),
                        proof: None,
                        witness_bytes: 0,
                        duration_ms: 0,
                    }),
                },
            );
        }

        let request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(1)),
            method: "broadcast".to_string(),
            params: Some(json!({ "draft_id": draft_id })),
        };
        let response = router.handle(request);
        let error = response.error.expect("error");
        assert_eq!(error.code, CODE_NODE_ERROR);
        assert_eq!(
            error.message,
            "node rejected transaction (fee rate too low (required 25 sats/vB))"
        );
        let data = error.data.expect("metadata");
        assert_eq!(data["phase2_code"], json!("FEE_TOO_LOW"));
        assert_eq!(
            data["hints"],
            json!(["Increase the fee rate to at least 25 sats/vB and retry."])
        );
        assert_eq!(
            sync.issues(),
            vec!["node rejected transaction (fee rate too low (required 25 sats/vB))".to_string()]
        );
        assert_eq!(
            sync.hints(),
            vec!["Increase the fee rate to at least 25 sats/vB and retry.".to_string()]
        );
        let _persist = dir.into_path();
    }
}
