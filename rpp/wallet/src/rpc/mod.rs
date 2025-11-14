//! JSON-RPC facades for wallet subsystems.

pub mod client;
pub mod dto;
pub mod error;
pub mod zsi;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use dto::{
    BackupExportParams, BackupExportResponse, BackupImportParams, BackupImportResponse,
    BackupMetadataDto, BackupValidateParams, BackupValidateResponse, BackupValidationModeDto,
    BalanceResponse, BlockFeeSummaryDto, BroadcastParams, BroadcastResponse, CreateTxParams,
    CreateTxResponse, DeriveAddressParams, DeriveAddressResponse, DraftInputDto, DraftOutputDto,
    DraftSpendModelDto, EmptyParams, EstimateFeeParams, EstimateFeeResponse, FeeEstimateSourceDto,
    GetPolicyResponse, JsonRpcError, JsonRpcRequest, JsonRpcResponse, ListPendingLocksResponse,
    ListTransactionsResponse, ListUtxosResponse, MempoolInfoResponse, PendingLockDto,
    PolicyPreviewResponse, PolicySnapshotDto, RecentBlocksParams, RecentBlocksResponse,
    ReleasePendingLocksParams, ReleasePendingLocksResponse, RescanParams, RescanResponse,
    SetPolicyParams, SetPolicyResponse, SignTxParams, SignTxResponse, SyncCheckpointDto,
    SyncModeDto, SyncStatusParams, SyncStatusResponse, TelemetryCounterDto,
    TelemetryCountersResponse, TransactionEntryDto, UtxoDto, JSONRPC_VERSION,
};
use error::WalletRpcErrorCode;
use hex::encode as hex_encode;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

use crate::backup::{
    backup_export, backup_import, backup_validate, BackupError, BackupExportOptions,
    BackupImportOutcome, BackupValidationMode,
};
use crate::db::{PendingLock, PolicySnapshot, TxCacheEntry, UtxoRecord};
use crate::engine::signing::ProverOutput;
use crate::engine::{
    BuilderError, DraftTransaction, EngineError, FeeError, ProverError, SelectionError, SpendModel,
    WalletBalance,
};
use crate::indexer::scanner::{SyncMode, SyncStatus};
use crate::node_client::{
    BlockFeeSummary, MempoolInfo, NodeClientError, NodePolicyHint, NodeRejectionHint,
};
use crate::wallet::{
    PolicyPreview, TelemetryCounter, TelemetryCounters, Wallet, WalletError, WalletPaths,
    WalletSyncCoordinator, WalletSyncError,
};
use zeroize::Zeroizing;

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

const DEFAULT_RECENT_BLOCK_LIMIT: usize = 8;

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
            "mempool_info" => {
                parse_params::<EmptyParams>(params)?;
                let info = self.wallet.mempool_info()?;
                self.respond_mempool_info(info)
            }
            "recent_blocks" => {
                let params: RecentBlocksParams = parse_params(params)?;
                let requested = params.limit.unwrap_or(DEFAULT_RECENT_BLOCK_LIMIT as u32);
                let limit = requested.clamp(1, 32) as usize;
                let blocks = self.wallet.recent_blocks(limit)?;
                self.respond_recent_blocks(blocks)
            }
            "telemetry_counters" => {
                parse_params::<EmptyParams>(params)?;
                self.respond_telemetry_counters()
            }
            "sync_status" => {
                parse_params::<SyncStatusParams>(params)?;
                self.respond_sync_status()
            }
            "rescan" => {
                let params: RescanParams = parse_params(params)?;
                self.handle_rescan(params)
            }
            "backup.export" => {
                let params: BackupExportParams = parse_params(params)?;
                self.handle_backup_export(params)
            }
            "backup.validate" => {
                let params: BackupValidateParams = parse_params(params)?;
                self.handle_backup_validate(params)
            }
            "backup.import" => {
                let params: BackupImportParams = parse_params(params)?;
                self.handle_backup_import(params)
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

    fn respond_mempool_info(&self, info: MempoolInfo) -> Result<Value, RouterError> {
        to_value(MempoolInfoResponse::from(info))
    }

    fn respond_recent_blocks(&self, blocks: Vec<BlockFeeSummary>) -> Result<Value, RouterError> {
        let blocks = blocks.into_iter().map(BlockFeeSummaryDto::from).collect();
        to_value(RecentBlocksResponse { blocks })
    }

    fn respond_telemetry_counters(&self) -> Result<Value, RouterError> {
        let counters = telemetry_counters_to_dto(self.wallet.telemetry_counters());
        to_value(counters)
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

        if let Some(ref status) = status {
            if target_height > status.latest_height {
                return Err(RouterError::RescanOutOfRange {
                    requested: target_height,
                    latest: status.latest_height,
                });
            }
        }
        let scheduled = sync.request_rescan(target_height)?;
        if !scheduled {
            let pending_from = status
                .as_ref()
                .and_then(|value| value.pending_ranges.first().map(|(start, _)| *start));
            return Err(RouterError::RescanInProgress {
                requested: target_height,
                pending_from,
            });
        }
        to_value(RescanResponse {
            scheduled,
            from_height: target_height,
        })
    }

    fn handle_backup_export(&self, params: BackupExportParams) -> Result<Value, RouterError> {
        let BackupExportParams {
            passphrase,
            confirmation,
            metadata_only,
            include_checksums,
        } = params;
        let passphrase = Zeroizing::new(passphrase.into_bytes());
        let confirmation = Zeroizing::new(confirmation.into_bytes());
        let options = BackupExportOptions {
            metadata_only,
            include_checksums,
        };
        let store = self.wallet.store();
        let result = backup_export(
            store.as_ref(),
            self.wallet.keystore_path(),
            self.wallet.backup_dir(),
            passphrase,
            confirmation,
            options,
        )
        .map_err(RouterError::Backup)?;
        let response = BackupExportResponse {
            path: result.path.to_string_lossy().to_string(),
            metadata: metadata_to_dto(&result.metadata),
        };
        to_value(response)
    }

    fn handle_backup_validate(&self, params: BackupValidateParams) -> Result<Value, RouterError> {
        let BackupValidateParams {
            name,
            passphrase,
            mode,
        } = params;
        let passphrase = Zeroizing::new(passphrase.into_bytes());
        let mode = match mode {
            BackupValidationModeDto::DryRun => BackupValidationMode::DryRun,
            BackupValidationModeDto::Full => BackupValidationMode::Full,
        };
        let store = self.wallet.store();
        let validation = backup_validate(
            store.as_ref(),
            self.wallet.backup_dir(),
            &name,
            passphrase,
            mode,
        )
        .map_err(RouterError::Backup)?;
        let response = BackupValidateResponse {
            metadata: metadata_to_dto(&validation.metadata),
            has_keystore: validation.has_keystore,
            policy_count: validation.policy_count,
            meta_entries: validation.meta_entries,
        };
        to_value(response)
    }

    fn handle_backup_import(&self, params: BackupImportParams) -> Result<Value, RouterError> {
        let BackupImportParams { name, passphrase } = params;
        let passphrase = Zeroizing::new(passphrase.into_bytes());
        let store = self.wallet.store();
        let outcome = backup_import(
            store.as_ref(),
            self.wallet.keystore_path(),
            self.wallet.backup_dir(),
            &name,
            passphrase,
        )
        .map_err(RouterError::Backup)?;
        let sync = self.sync.as_ref().ok_or(RouterError::SyncUnavailable)?;
        let _ = sync
            .request_rescan(outcome.rescan_from)
            .map_err(RouterError::Sync)?;
        let response = BackupImportResponse {
            metadata: metadata_to_dto(&outcome.metadata),
            restored_keystore: outcome.restored_keystore,
            restored_policy: outcome.restored_policy,
            rescan_from_height: outcome.rescan_from,
        };
        to_value(response)
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
    Backup(BackupError),
    MissingDraft(String),
    DraftUnsigned(String),
    SyncUnavailable,
    RescanOutOfRange {
        requested: u64,
        latest: u64,
    },
    RescanInProgress {
        requested: u64,
        pending_from: Option<u64>,
    },
    StatePoisoned,
    Serialization(String),
}

impl RouterError {
    fn into_json_error(self) -> JsonRpcError {
        match self {
            RouterError::InvalidRequest(message) => {
                json_error(WalletRpcErrorCode::InvalidRequest, message, None)
            }
            RouterError::MethodNotFound(method) => json_error(
                WalletRpcErrorCode::MethodNotFound,
                format!("method `{method}` not found"),
                Some(json!({ "method": method })),
            ),
            RouterError::InvalidParams(message) => {
                json_error(WalletRpcErrorCode::InvalidParams, message, None)
            }
            RouterError::Wallet(error) => wallet_error_to_json(&error),
            RouterError::Sync(error) => wallet_sync_error_to_json(&error),
            RouterError::Node(error) => node_error_to_json(&error),
            RouterError::Backup(error) => backup_error_to_json(&error),
            RouterError::MissingDraft(draft_id) => json_error(
                WalletRpcErrorCode::DraftNotFound,
                "draft not found",
                Some(json!({ "draft_id": draft_id })),
            ),
            RouterError::DraftUnsigned(draft_id) => json_error(
                WalletRpcErrorCode::DraftUnsigned,
                "draft must be signed before broadcasting",
                Some(json!({ "draft_id": draft_id })),
            ),
            RouterError::SyncUnavailable => json_error(
                WalletRpcErrorCode::SyncUnavailable,
                "wallet sync coordinator not configured",
                None,
            ),
            RouterError::RescanOutOfRange { requested, latest } => json_error(
                WalletRpcErrorCode::RescanOutOfRange,
                "rescan height is outside the indexed range",
                Some(json!({ "requested": requested, "latest": latest })),
            ),
            RouterError::RescanInProgress {
                requested,
                pending_from,
            } => json_error(
                WalletRpcErrorCode::RescanInProgress,
                "wallet rescan already scheduled",
                Some(json!({ "requested": requested, "pending_from": pending_from })),
            ),
            RouterError::StatePoisoned | RouterError::Serialization(_) => json_error(
                WalletRpcErrorCode::InternalError,
                "wallet router internal error",
                None,
            ),
        }
    }
}

fn json_error(
    code: WalletRpcErrorCode,
    message: impl Into<String>,
    details: Option<Value>,
) -> JsonRpcError {
    let payload = code.data_payload(details);
    JsonRpcError::new(code.as_i32(), message.into(), Some(payload))
}

fn wallet_error_to_json(error: &WalletError) -> JsonRpcError {
    match error {
        WalletError::Engine(engine) => engine_error_to_json(engine),
        WalletError::Prover(prover) => prover_error_to_json(prover),
        WalletError::Node(node) => node_error_to_json(node),
        WalletError::Sync(sync) => wallet_sync_error_to_json(sync),
    }
}

fn backup_error_to_json(error: &BackupError) -> JsonRpcError {
    json_error(
        WalletRpcErrorCode::Custom("BACKUP_ERROR".into()),
        error.to_string(),
        None,
    )
}

fn wallet_sync_error_to_json(error: &WalletSyncError) -> JsonRpcError {
    match error {
        WalletSyncError::Scanner(inner) => json_error(
            WalletRpcErrorCode::SyncError,
            inner.to_string(),
            Some(json!({ "kind": "scanner" })),
        ),
        WalletSyncError::Stopped => json_error(
            WalletRpcErrorCode::SyncError,
            error.to_string(),
            Some(json!({ "kind": "stopped" })),
        ),
    }
}

fn engine_error_to_json(error: &EngineError) -> JsonRpcError {
    match error {
        EngineError::Policy(violations) => json_error(
            WalletRpcErrorCode::WalletPolicyViolation,
            "wallet policy violation",
            Some(json!({ "violations": violations })),
        ),
        EngineError::Fee(fee) => fee_error_to_json(fee),
        EngineError::Selection(selection) => selection_error_to_json(selection),
        EngineError::Builder(builder) => builder_error_to_json(builder),
        EngineError::Store(store) => json_error(
            WalletRpcErrorCode::EngineFailure,
            error.to_string(),
            Some(json!({ "kind": "store", "message": store.to_string() })),
        ),
        EngineError::Address(address) => json_error(
            WalletRpcErrorCode::EngineFailure,
            error.to_string(),
            Some(json!({ "kind": "address", "message": address.to_string() })),
        ),
    }
}

fn selection_error_to_json(error: &SelectionError) -> JsonRpcError {
    match error {
        SelectionError::InsufficientFunds {
            required,
            confirmed_available,
            total_available,
        } => json_error(
            WalletRpcErrorCode::PendingLockConflict,
            error.to_string(),
            Some(json!({
                "required": required,
                "confirmed_available": confirmed_available,
                "total_available": total_available,
            })),
        ),
    }
}

fn builder_error_to_json(error: &BuilderError) -> JsonRpcError {
    match error {
        BuilderError::InsufficientFunds {
            required,
            available,
        } => json_error(
            WalletRpcErrorCode::PendingLockConflict,
            error.to_string(),
            Some(json!({ "required": required, "available": available })),
        ),
        BuilderError::FeeOverflow => json_error(
            WalletRpcErrorCode::EngineFailure,
            error.to_string(),
            Some(json!({ "kind": "fee_overflow" })),
        ),
        BuilderError::MissingSelection => json_error(
            WalletRpcErrorCode::EngineFailure,
            error.to_string(),
            Some(json!({ "kind": "missing_selection" })),
        ),
    }
}

fn fee_error_to_json(error: &FeeError) -> JsonRpcError {
    match error {
        FeeError::BelowMinimum { requested, minimum } => json_error(
            WalletRpcErrorCode::FeeTooLow,
            error.to_string(),
            Some(json!({ "requested": requested, "minimum": minimum })),
        ),
        FeeError::AboveMaximum { requested, maximum } => json_error(
            WalletRpcErrorCode::FeeTooHigh,
            error.to_string(),
            Some(json!({ "requested": requested, "maximum": maximum })),
        ),
        FeeError::Node(node) => node_error_to_json(node),
    }
}

fn prover_error_to_json(error: &ProverError) -> JsonRpcError {
    match error {
        ProverError::Timeout(timeout) => json_error(
            WalletRpcErrorCode::ProverTimeout,
            error.to_string(),
            Some(json!({ "timeout_secs": timeout })),
        ),
        ProverError::Cancelled => {
            json_error(WalletRpcErrorCode::ProverCancelled, error.to_string(), None)
        }
        ProverError::WitnessTooLarge { size, limit } => json_error(
            WalletRpcErrorCode::WitnessTooLarge,
            error.to_string(),
            Some(json!({ "size_bytes": size, "limit_bytes": limit })),
        ),
        ProverError::Backend(inner) => json_error(
            WalletRpcErrorCode::ProverFailed,
            error.to_string(),
            Some(json!({ "kind": "backend", "message": inner.to_string() })),
        ),
        ProverError::Serialization(message) => json_error(
            WalletRpcErrorCode::ProverFailed,
            error.to_string(),
            Some(json!({ "kind": "serialization", "message": message })),
        ),
        ProverError::Unsupported(backend) => json_error(
            WalletRpcErrorCode::ProverFailed,
            error.to_string(),
            Some(json!({ "kind": "unsupported", "backend": backend })),
        ),
        ProverError::Runtime(message) => json_error(
            WalletRpcErrorCode::ProverFailed,
            error.to_string(),
            Some(json!({ "kind": "runtime", "message": message })),
        ),
    }
}

fn node_error_to_json(error: &NodeClientError) -> JsonRpcError {
    let phase2 = error.phase2_code();
    let mut details = serde_json::Map::new();
    details.insert("phase2_code".to_string(), json!(phase2));
    let code = match error {
        NodeClientError::Network { message, .. } => {
            details.insert("message".to_string(), json!(message));
            WalletRpcErrorCode::NodeUnavailable
        }
        NodeClientError::Rejected { reason, hint } => {
            details.insert("reason".to_string(), json!(reason));
            if let Some(hint) = hint {
                details.insert("hint".to_string(), node_rejection_hint_to_json(hint));
            }
            if phase2 == "FEE_TOO_LOW" {
                WalletRpcErrorCode::FeeTooLow
            } else {
                WalletRpcErrorCode::NodeRejected
            }
        }
        NodeClientError::Policy { reason, hint } => {
            details.insert("reason".to_string(), json!(reason));
            if let Some(hint) = hint {
                details.insert("hint".to_string(), node_policy_hint_to_json(hint));
            }
            if phase2 == "FEE_TOO_LOW" {
                WalletRpcErrorCode::FeeTooLow
            } else {
                WalletRpcErrorCode::NodePolicy
            }
        }
        NodeClientError::StatsUnavailable { kind, message } => {
            details.insert("message".to_string(), json!(message));
            details.insert("stats_kind".to_string(), json!(kind.to_string()));
            WalletRpcErrorCode::NodeStatsUnavailable
        }
    };
    let hints = error.hints();
    if !hints.is_empty() {
        details.insert("hints".to_string(), json!(hints));
    }
    json_error(code, error.user_message(), Some(Value::Object(details)))
}

fn node_rejection_hint_to_json(hint: &NodeRejectionHint) -> Value {
    match hint {
        NodeRejectionHint::FeeRateTooLow { required } => json!({
            "kind": "fee_rate_too_low",
            "required": required,
        }),
        NodeRejectionHint::AlreadyKnown => json!({ "kind": "already_known" }),
        NodeRejectionHint::Conflicting => json!({ "kind": "conflicting" }),
        NodeRejectionHint::MempoolFull => json!({ "kind": "mempool_full" }),
        NodeRejectionHint::Other(reason) => json!({ "kind": "other", "reason": reason }),
    }
}

fn node_policy_hint_to_json(hint: &NodePolicyHint) -> Value {
    match hint {
        NodePolicyHint::FeeRateTooLow { minimum } => json!({
            "kind": "fee_rate_too_low",
            "minimum": minimum,
        }),
        NodePolicyHint::MissingInputs => json!({ "kind": "missing_inputs" }),
        NodePolicyHint::DustOutput => json!({ "kind": "dust_output" }),
        NodePolicyHint::ReplacementRejected => json!({ "kind": "replacement_rejected" }),
        NodePolicyHint::Other(reason) => json!({ "kind": "other", "reason": reason }),
    }
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

impl From<MempoolInfo> for MempoolInfoResponse {
    fn from(info: MempoolInfo) -> Self {
        Self {
            tx_count: info.tx_count,
            vsize_limit: info.vsize_limit,
            vsize_in_use: info.vsize_in_use,
            min_fee_rate: info.min_fee_rate,
            max_fee_rate: info.max_fee_rate,
        }
    }
}

impl From<BlockFeeSummary> for BlockFeeSummaryDto {
    fn from(summary: BlockFeeSummary) -> Self {
        Self {
            height: summary.height,
            median_fee_rate: summary.median_fee_rate,
            max_fee_rate: summary.max_fee_rate,
        }
    }
}

fn telemetry_counters_to_dto(counters: TelemetryCounters) -> TelemetryCountersResponse {
    let TelemetryCounters { enabled, counters } = counters;
    let counters = counters
        .into_iter()
        .map(|TelemetryCounter { name, value }| TelemetryCounterDto { name, value })
        .collect();
    TelemetryCountersResponse { enabled, counters }
}

fn metadata_to_dto(metadata: &crate::backup::BackupMetadata) -> BackupMetadataDto {
    BackupMetadataDto {
        version: metadata.version,
        schema_checksum: metadata.schema_checksum.clone(),
        created_at_ms: metadata.created_at_ms,
        has_keystore: metadata.has_keystore,
        policy_entries: metadata.policy_entries,
        meta_entries: metadata.meta_entries,
        include_checksums: metadata.include_checksums,
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
    use super::error::WalletRpcErrorCode;
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
        let keystore = dir.path().join("keystore.toml");
        let backup = dir.path().join("backups");
        let wallet = Wallet::new(
            Arc::clone(&store),
            [0u8; 32],
            WalletPolicyConfig::default(),
            WalletFeeConfig::default(),
            WalletProverConfig::default(),
            Arc::new(StubNodeClient::default()),
            WalletPaths::new(keystore, backup),
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
        assert_eq!(error.code, WalletRpcErrorCode::DraftNotFound.as_i32());
        let data = error.data.expect("error data");
        assert_eq!(data["code"], json!("DRAFT_NOT_FOUND"));
        assert_eq!(data["details"]["draft_id"], json!("deadbeef"));
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
        assert_eq!(error.code, WalletRpcErrorCode::RescanOutOfRange.as_i32());
        let data = error.data.expect("error data");
        assert_eq!(data["code"], json!("RESCAN_OUT_OF_RANGE"));
        assert_eq!(data["details"]["requested"], json!(25));
        assert_eq!(data["details"]["latest"], json!(10));
    }

    #[test]
    fn router_reports_rescan_in_progress() {
        let status = SyncStatus {
            latest_height: 24,
            mode: SyncMode::Rescan { from_height: 12 },
            scanned_scripthashes: 4,
            pending_ranges: vec![(6, 12)],
            checkpoints: SyncCheckpoints {
                resume_height: Some(20),
                ..SyncCheckpoints::default()
            },
            hints: Vec::new(),
            node_issue: None,
        };
        let mut recording = RecordingSync::default();
        recording.status = Some(status);
        let sync = Arc::new(recording);
        let router = build_router(Some(sync));
        let request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(1)),
            method: "rescan".to_string(),
            params: Some(json!({ "from_height": 8 })),
        };
        let response = router.handle(request);
        let error = response.error.expect("error");
        assert_eq!(error.code, WalletRpcErrorCode::RescanInProgress.as_i32());
        let data = error.data.expect("error data");
        assert_eq!(data["code"], json!("RESCAN_IN_PROGRESS"));
        assert_eq!(data["details"]["requested"], json!(8));
        assert_eq!(data["details"]["pending_from"], json!(6));
    }

    #[test]
    fn node_error_conversion_adds_phase2_metadata() {
        let error = NodeClientError::rejected_with_hint(
            "policy",
            NodeRejectionHint::FeeRateTooLow { required: Some(15) },
        );
        let json_error = super::node_error_to_json(&error);
        assert_eq!(json_error.code, WalletRpcErrorCode::FeeTooLow.as_i32());
        assert_eq!(
            json_error.message,
            "node rejected transaction (fee rate too low (required 15 sats/vB))"
        );
        let data = json_error.data.expect("phase2 metadata");
        assert_eq!(data["code"], json!("FEE_TOO_LOW"));
        assert_eq!(data["details"]["phase2_code"], json!("FEE_TOO_LOW"));
        assert_eq!(
            data["details"]["hints"],
            json!(["Increase the fee rate to at least 15 sats/vB and retry."])
        );
    }

    #[test]
    fn broadcast_rejection_exposes_phase2_code() {
        let dir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(dir.path()).expect("store"));
        let keystore = dir.path().join("keystore.toml");
        let backup = dir.path().join("backups");
        let wallet = Wallet::new(
            Arc::clone(&store),
            [0u8; 32],
            WalletPolicyConfig::default(),
            WalletFeeConfig::default(),
            WalletProverConfig::default(),
            Arc::new(RejectingNodeClient::new()),
            WalletPaths::new(keystore, backup),
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
        assert_eq!(error.code, WalletRpcErrorCode::FeeTooLow.as_i32());
        assert_eq!(
            error.message,
            "node rejected transaction (fee rate too low (required 25 sats/vB))"
        );
        let data = error.data.expect("metadata");
        assert_eq!(data["code"], json!("FEE_TOO_LOW"));
        assert_eq!(data["details"]["phase2_code"], json!("FEE_TOO_LOW"));
        assert_eq!(
            data["details"]["hints"],
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
