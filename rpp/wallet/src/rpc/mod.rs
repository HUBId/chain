//! JSON-RPC facades for wallet subsystems.

pub mod client;
pub mod dto;
pub mod error;
#[cfg(feature = "wallet_zsi")]
pub mod zsi;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use dto::{
    BackupExportParams, BackupExportResponse, BackupImportParams, BackupImportResponse,
    BackupMetadataDto, BackupValidateParams, BackupValidateResponse, BackupValidationModeDto,
    BalanceResponse, BlockFeeSummaryDto, BroadcastParams, BroadcastRawParams, BroadcastRawResponse,
    BroadcastResponse, CreateTxParams, CreateTxResponse, DerivationPathDto, DeriveAddressParams,
    DeriveAddressResponse, DraftInputDto, DraftOutputDto, DraftSpendModelDto, EmptyParams,
    EstimateFeeParams, EstimateFeeResponse, FeeEstimateSourceDto, GetPolicyResponse,
    HardwareDeviceDto, HardwareEnumerateResponse, HardwareSignParams, HardwareSignResponse,
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, ListPendingLocksResponse,
    ListTransactionsResponse, ListUtxosResponse, MempoolInfoResponse, PendingLockDto,
    PolicyPreviewResponse, PolicySnapshotDto, PolicyTierHooks as PolicyTierHooksDto,
    RecentBlocksParams, RecentBlocksResponse, ReleasePendingLocksParams,
    ReleasePendingLocksResponse, RescanParams, RescanResponse, SetPolicyParams, SetPolicyResponse,
    SignTxParams, SignTxResponse, SyncCheckpointDto, SyncModeDto, SyncStatusParams,
    SyncStatusResponse, TelemetryCounterDto, TelemetryCountersResponse, TransactionEntryDto,
    UtxoDto, WatchOnlyEnableParams, WatchOnlyStatusResponse, JSONRPC_VERSION,
};
#[cfg(feature = "wallet_multisig_hooks")]
use dto::{
    CosignerDto, GetCosignersResponse, GetMultisigScopeResponse, MultisigDraftMetadataDto,
    MultisigExportParams, MultisigExportResponse, MultisigScopeDto, SetCosignersParams,
    SetCosignersResponse, SetMultisigScopeParams, SetMultisigScopeResponse,
};
#[cfg(feature = "wallet_zsi")]
use dto::{
    ZsiArtifactDto, ZsiBindResponse, ZsiDeleteParams, ZsiDeleteResponse, ZsiListResponse,
    ZsiProofParams, ZsiProveResponse, ZsiVerifyParams, ZsiVerifyResponse,
};
use error::WalletRpcErrorCode;
use hex::{decode as hex_decode, encode as hex_encode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Value};

use crate::backup::{
    backup_export, backup_import, backup_validate, BackupError, BackupExportOptions,
    BackupImportOutcome, BackupValidationMode,
};
#[cfg(feature = "wallet_zsi")]
use crate::db::StoredZsiArtifact;
use crate::db::{PendingLock, PolicySnapshot, TxCacheEntry, UtxoRecord};
use crate::engine::signing::ProveResult;
use crate::engine::{
    BuildMetadata, BuilderError, DraftBundle, DraftTransaction, EngineError, FeeError, ProverError,
    SelectionError, SpendModel, WalletBalance,
};
#[cfg(feature = "wallet_hw")]
use crate::hw::{HardwareDevice, HardwareSignRequest, HardwareSignature, HardwareSignerError};
use crate::indexer::scanner::{SyncMode, SyncStatus};
use crate::modes::watch_only::{WatchOnlyRecord, WatchOnlyStatus};
#[cfg(feature = "wallet_multisig_hooks")]
use crate::multisig::{Cosigner, CosignerRegistry, MultisigScope};
use crate::node_client::{
    BlockFeeSummary, MempoolInfo, NodeClientError, NodePolicyHint, NodeRejectionHint,
};
use crate::telemetry::{
    TelemetryCounter, TelemetryCounters, TelemetryOutcome, WalletActionTelemetry,
    WalletTelemetryAction,
};
use crate::wallet::{
    PolicyPreview, Wallet, WalletError, WalletMode, WalletPaths, WalletSyncCoordinator,
    WalletSyncError, WatchOnlyError, ZsiError,
};
#[cfg(feature = "wallet_zsi")]
use crate::wallet::{ZsiBinding, ZsiProofRequest, ZsiVerifyRequest};
use rpp_wallet_interface::runtime_telemetry::{
    noop_runtime_metrics, RuntimeMetricsHandle, WalletAction, WalletActionResult,
};
use zeroize::Zeroizing;

#[derive(Clone, Debug)]
struct DraftState {
    draft: DraftTransaction,
    metadata: BuildMetadata,
    prover_result: Option<ProveResult>,
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
    telemetry: Arc<WalletActionTelemetry>,
    drafts: Mutex<HashMap<String, DraftState>>,
    next_id: AtomicU64,
    sync: Option<Arc<dyn SyncHandle>>,
    metrics: RuntimeMetricsHandle,
}

impl Drop for WalletRpcRouter {
    fn drop(&mut self) {
        self.telemetry.record_session("stop");
        self.telemetry.flush();
    }
}

const DEFAULT_RECENT_BLOCK_LIMIT: usize = 8;
#[cfg(feature = "wallet_hw")]
const HARDWARE_DISABLED_ERROR: &str = "wallet hardware support disabled by configuration";

impl WalletRpcRouter {
    pub fn new(
        wallet: Arc<Wallet>,
        sync: Option<Arc<dyn SyncHandle>>,
        metrics: RuntimeMetricsHandle,
    ) -> Self {
        let telemetry = wallet.telemetry_handle();
        telemetry.record_session("start");
        Self {
            telemetry,
            wallet,
            drafts: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            sync,
            metrics,
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

    fn record_action(&self, action: WalletTelemetryAction, outcome: TelemetryOutcome) {
        self.telemetry.record(action, outcome);
        {
            let action_label = match action {
                WalletTelemetryAction::BackupExport => WalletAction::BackupExport,
                WalletTelemetryAction::BackupValidate => WalletAction::BackupValidate,
                WalletTelemetryAction::BackupImport => WalletAction::BackupImport,
                WalletTelemetryAction::WatchOnlyStatus => WalletAction::WatchOnlyStatus,
                WalletTelemetryAction::WatchOnlyEnable => WalletAction::WatchOnlyEnable,
                WalletTelemetryAction::WatchOnlyDisable => WalletAction::WatchOnlyDisable,
                #[cfg(feature = "wallet_multisig_hooks")]
                WalletTelemetryAction::MultisigGetScope => WalletAction::MultisigGetScope,
                #[cfg(feature = "wallet_multisig_hooks")]
                WalletTelemetryAction::MultisigSetScope => WalletAction::MultisigSetScope,
                #[cfg(feature = "wallet_multisig_hooks")]
                WalletTelemetryAction::MultisigGetCosigners => WalletAction::MultisigGetCosigners,
                #[cfg(feature = "wallet_multisig_hooks")]
                WalletTelemetryAction::MultisigSetCosigners => WalletAction::MultisigSetCosigners,
                #[cfg(feature = "wallet_multisig_hooks")]
                WalletTelemetryAction::MultisigExport => WalletAction::MultisigExport,
                #[cfg(feature = "wallet_zsi")]
                WalletTelemetryAction::ZsiProve => WalletAction::ZsiProve,
                #[cfg(feature = "wallet_zsi")]
                WalletTelemetryAction::ZsiVerify => WalletAction::ZsiVerify,
                #[cfg(feature = "wallet_zsi")]
                WalletTelemetryAction::ZsiBindAccount => WalletAction::ZsiBindAccount,
                #[cfg(feature = "wallet_zsi")]
                WalletTelemetryAction::ZsiList => WalletAction::ZsiList,
                #[cfg(feature = "wallet_zsi")]
                WalletTelemetryAction::ZsiDelete => WalletAction::ZsiDelete,
                WalletTelemetryAction::HwEnumerate => WalletAction::HwEnumerate,
                WalletTelemetryAction::HwSign => WalletAction::HwSign,
            };
            let outcome_label = match outcome {
                TelemetryOutcome::Success => WalletActionResult::Success,
                TelemetryOutcome::Error => WalletActionResult::Error,
            };
            self.metrics
                .record_wallet_action(action_label, outcome_label);
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

        let started = Instant::now();
        let method_label = method.clone();
        match self.dispatch(&method, params) {
            Ok(result) => {
                self.telemetry.record_rpc_event(
                    &method_label,
                    started.elapsed(),
                    TelemetryOutcome::Success,
                    None,
                );
                if let Some(stage) = send_stage_for_method(&method_label) {
                    self.telemetry
                        .record_send_stage(stage, TelemetryOutcome::Success);
                }
                if let Some(stage) = rescan_stage_for_method(&method_label) {
                    self.telemetry.record_rescan_stage(
                        stage,
                        Some(started.elapsed()),
                        TelemetryOutcome::Success,
                    );
                }
                JsonRpcResponse::success(id.clone(), result)
            }
            Err(error) => {
                let code_value = error.telemetry_code();
                let code = code_value.map(|value| value.as_str().into_owned());
                self.telemetry.record_rpc_event(
                    &method_label,
                    started.elapsed(),
                    TelemetryOutcome::Error,
                    code.as_deref(),
                );
                if let Some(stage) = send_stage_for_method(&method_label) {
                    self.telemetry
                        .record_send_stage(stage, TelemetryOutcome::Error);
                }
                if let Some(stage) = rescan_stage_for_method(&method_label) {
                    self.telemetry.record_rescan_stage(
                        stage,
                        Some(started.elapsed()),
                        TelemetryOutcome::Error,
                    );
                }
                JsonRpcResponse::error(id.clone(), error.into_json_error())
            }
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
            #[cfg(feature = "wallet_hw")]
            "hw.enumerate" => {
                if !self.wallet.hardware_enabled() {
                    return Err(RouterError::InvalidRequest(HARDWARE_DISABLED_ERROR));
                }
                parse_params::<EmptyParams>(params)?;
                self.hw_enumerate()
            }
            #[cfg(feature = "wallet_hw")]
            "hw.sign" => {
                if !self.wallet.hardware_enabled() {
                    return Err(RouterError::InvalidRequest(HARDWARE_DISABLED_ERROR));
                }
                let params: HardwareSignParams = parse_params(params)?;
                self.hw_sign(params)
            }
            "broadcast" => {
                let params: BroadcastParams = parse_params(params)?;
                self.broadcast_draft(params.draft_id)
            }
            "broadcast_raw" => {
                let params: BroadcastRawParams = parse_params(params)?;
                self.broadcast_raw(params.tx_hex)
            }
            #[cfg(feature = "wallet_zsi")]
            "zsi.prove" => {
                let params: ZsiProofParams = parse_params(params)?;
                let request = zsi_proof_params_to_request(params);
                match self.wallet_call(self.wallet.zsi_prove(request)) {
                    Ok(proof) => {
                        self.record_action(
                            WalletTelemetryAction::ZsiProve,
                            TelemetryOutcome::Success,
                        );
                        to_value(ZsiProveResponse { proof })
                    }
                    Err(error) => {
                        self.record_action(
                            WalletTelemetryAction::ZsiProve,
                            TelemetryOutcome::Error,
                        );
                        Err(error)
                    }
                }
            }
            #[cfg(feature = "wallet_zsi")]
            "zsi.verify" => {
                let params: ZsiVerifyParams = parse_params(params)?;
                let request = zsi_verify_params_to_request(params);
                match self.wallet_call(self.wallet.zsi_verify(request)) {
                    Ok(()) => {
                        self.record_action(
                            WalletTelemetryAction::ZsiVerify,
                            TelemetryOutcome::Success,
                        );
                        to_value(ZsiVerifyResponse { valid: true })
                    }
                    Err(error) => {
                        self.record_action(
                            WalletTelemetryAction::ZsiVerify,
                            TelemetryOutcome::Error,
                        );
                        Err(error)
                    }
                }
            }
            #[cfg(feature = "wallet_zsi")]
            "zsi.bind_account" => {
                let params: ZsiProofParams = parse_params(params)?;
                let request = zsi_proof_params_to_request(params);
                match self.wallet_call(self.wallet.zsi_bind_account(request)) {
                    Ok(binding) => {
                        self.record_action(
                            WalletTelemetryAction::ZsiBindAccount,
                            TelemetryOutcome::Success,
                        );
                        to_value(ZsiBindResponse {
                            binding: zsi_binding_to_dto(binding),
                        })
                    }
                    Err(error) => {
                        self.record_action(
                            WalletTelemetryAction::ZsiBindAccount,
                            TelemetryOutcome::Error,
                        );
                        Err(error)
                    }
                }
            }
            #[cfg(feature = "wallet_zsi")]
            "zsi.list" => {
                parse_params::<EmptyParams>(params)?;
                match self.wallet_call(self.wallet.zsi_list()) {
                    Ok(artifacts) => {
                        self.record_action(
                            WalletTelemetryAction::ZsiList,
                            TelemetryOutcome::Success,
                        );
                        let artifacts = artifacts.into_iter().map(zsi_artifact_to_dto).collect();
                        to_value(ZsiListResponse { artifacts })
                    }
                    Err(error) => {
                        self.record_action(WalletTelemetryAction::ZsiList, TelemetryOutcome::Error);
                        Err(error)
                    }
                }
            }
            #[cfg(feature = "wallet_zsi")]
            "zsi.delete" => {
                let params: ZsiDeleteParams = parse_params(params)?;
                match self.wallet_call(
                    self.wallet
                        .zsi_delete(&params.identity, &params.commitment_digest),
                ) {
                    Ok(()) => {
                        self.record_action(
                            WalletTelemetryAction::ZsiDelete,
                            TelemetryOutcome::Success,
                        );
                        to_value(ZsiDeleteResponse { deleted: true })
                    }
                    Err(error) => {
                        self.record_action(
                            WalletTelemetryAction::ZsiDelete,
                            TelemetryOutcome::Error,
                        );
                        Err(error)
                    }
                }
            }
            #[cfg(feature = "wallet_multisig_hooks")]
            "multisig.get_scope" => {
                parse_params::<EmptyParams>(params)?;
                self.multisig_get_scope()
            }
            #[cfg(feature = "wallet_multisig_hooks")]
            "multisig.set_scope" => {
                let params: SetMultisigScopeParams = parse_params(params)?;
                self.multisig_set_scope(params)
            }
            #[cfg(feature = "wallet_multisig_hooks")]
            "multisig.get_cosigners" => {
                parse_params::<EmptyParams>(params)?;
                self.multisig_get_cosigners()
            }
            #[cfg(feature = "wallet_multisig_hooks")]
            "multisig.set_cosigners" => {
                let params: SetCosignersParams = parse_params(params)?;
                self.multisig_set_cosigners(params)
            }
            #[cfg(feature = "wallet_multisig_hooks")]
            "multisig.export" => {
                let params: MultisigExportParams = parse_params(params)?;
                self.multisig_export(params)
            }
            #[cfg(not(feature = "wallet_multisig_hooks"))]
            "multisig.get_scope"
            | "multisig.set_scope"
            | "multisig.get_cosigners"
            | "multisig.set_cosigners"
            | "multisig.export" => Err(RouterError::Wallet(WalletError::MultisigDisabled)),
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
            "watch_only.status" => {
                parse_params::<EmptyParams>(params)?;
                self.watch_only_status()
            }
            "watch_only.enable" => {
                let params: WatchOnlyEnableParams = parse_params(params)?;
                self.watch_only_enable(params)
            }
            "watch_only.disable" => {
                parse_params::<EmptyParams>(params)?;
                self.watch_only_disable()
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
        let bundle = self.wallet_call(self.wallet.create_draft(to, amount, fee_rate))?;
        let draft_id = self.store_draft(bundle.clone())?;
        self.respond_draft(&draft_id, &bundle)
    }

    #[cfg(feature = "wallet_hw")]
    fn hw_enumerate(&self) -> Result<Value, RouterError> {
        match self.wallet_call(self.wallet.hardware_devices()) {
            Ok(devices) => {
                self.record_action(
                    WalletTelemetryAction::HwEnumerate,
                    TelemetryOutcome::Success,
                );
                let devices = devices.into_iter().map(hardware_device_to_dto).collect();
                to_value(HardwareEnumerateResponse { devices })
            }
            Err(error) => {
                self.record_action(WalletTelemetryAction::HwEnumerate, TelemetryOutcome::Error);
                Err(error)
            }
        }
    }

    #[cfg(feature = "wallet_hw")]
    fn hw_sign(&self, params: HardwareSignParams) -> Result<Value, RouterError> {
        let payload = match hex_decode(&params.payload) {
            Ok(payload) => payload,
            Err(err) => {
                self.record_action(WalletTelemetryAction::HwSign, TelemetryOutcome::Error);
                return Err(RouterError::InvalidParams(format!(
                    "invalid payload hex: {err}"
                )));
            }
        };
        let path = dto_to_derivation_path(params.path);
        let request = HardwareSignRequest::new(params.fingerprint.clone(), path.clone(), payload);
        match self.wallet_call(self.wallet.hardware_sign(request)) {
            Ok(signature) => {
                self.record_action(WalletTelemetryAction::HwSign, TelemetryOutcome::Success);
                to_value(HardwareSignResponse {
                    fingerprint: signature.fingerprint,
                    signature: hex_encode(signature.signature),
                    public_key: hex_encode(signature.public_key),
                    path: derivation_path_to_dto(&signature.path),
                })
            }
            Err(error) => {
                self.record_action(WalletTelemetryAction::HwSign, TelemetryOutcome::Error);
                Err(error)
            }
        }
    }

    fn respond_draft(&self, draft_id: &str, bundle: &DraftBundle) -> Result<Value, RouterError> {
        let draft = &bundle.draft;
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
            #[cfg(feature = "wallet_multisig_hooks")]
            multisig: bundle
                .metadata
                .multisig
                .as_ref()
                .map(MultisigDraftMetadataDto::from),
        };
        to_value(response)
    }

    #[cfg(feature = "wallet_multisig_hooks")]
    fn multisig_get_scope(&self) -> Result<Value, RouterError> {
        match self.wallet_call(self.wallet.multisig_scope()) {
            Ok(scope) => {
                self.record_action(
                    WalletTelemetryAction::MultisigGetScope,
                    TelemetryOutcome::Success,
                );
                let dto = scope.as_ref().map(MultisigScopeDto::from);
                to_value(GetMultisigScopeResponse { scope: dto })
            }
            Err(error) => {
                self.record_action(
                    WalletTelemetryAction::MultisigGetScope,
                    TelemetryOutcome::Error,
                );
                Err(error)
            }
        }
    }

    #[cfg(feature = "wallet_multisig_hooks")]
    fn multisig_set_scope(&self, params: SetMultisigScopeParams) -> Result<Value, RouterError> {
        let scope = match params.scope.map(scope_from_dto).transpose() {
            Ok(scope) => scope,
            Err(error) => {
                self.record_action(
                    WalletTelemetryAction::MultisigSetScope,
                    TelemetryOutcome::Error,
                );
                return Err(error);
            }
        };
        if let Err(error) = self.wallet_call(self.wallet.set_multisig_scope(scope)) {
            self.record_action(
                WalletTelemetryAction::MultisigSetScope,
                TelemetryOutcome::Error,
            );
            return Err(error);
        }
        match self.wallet_call(self.wallet.multisig_scope()) {
            Ok(updated) => {
                self.record_action(
                    WalletTelemetryAction::MultisigSetScope,
                    TelemetryOutcome::Success,
                );
                let dto = updated.as_ref().map(MultisigScopeDto::from);
                to_value(SetMultisigScopeResponse { scope: dto })
            }
            Err(error) => {
                self.record_action(
                    WalletTelemetryAction::MultisigSetScope,
                    TelemetryOutcome::Error,
                );
                Err(error)
            }
        }
    }

    #[cfg(feature = "wallet_multisig_hooks")]
    fn multisig_get_cosigners(&self) -> Result<Value, RouterError> {
        match self.wallet_call(self.wallet.cosigner_registry()) {
            Ok(registry) => {
                self.record_action(
                    WalletTelemetryAction::MultisigGetCosigners,
                    TelemetryOutcome::Success,
                );
                let cosigners = registry
                    .as_ref()
                    .map(|registry| registry.entries().iter().map(CosignerDto::from).collect())
                    .unwrap_or_default();
                to_value(GetCosignersResponse { cosigners })
            }
            Err(error) => {
                self.record_action(
                    WalletTelemetryAction::MultisigGetCosigners,
                    TelemetryOutcome::Error,
                );
                Err(error)
            }
        }
    }

    #[cfg(feature = "wallet_multisig_hooks")]
    fn multisig_set_cosigners(&self, params: SetCosignersParams) -> Result<Value, RouterError> {
        if params.cosigners.is_empty() {
            self.record_action(
                WalletTelemetryAction::MultisigSetCosigners,
                TelemetryOutcome::Error,
            );
            return Err(RouterError::InvalidParams(
                "cosigners list cannot be empty".to_string(),
            ));
        }
        let registry = match registry_from_dtos(params.cosigners) {
            Ok(registry) => registry,
            Err(error) => {
                self.record_action(
                    WalletTelemetryAction::MultisigSetCosigners,
                    TelemetryOutcome::Error,
                );
                return Err(error);
            }
        };
        if let Err(error) = self.wallet_call(self.wallet.set_cosigner_registry(Some(registry))) {
            self.record_action(
                WalletTelemetryAction::MultisigSetCosigners,
                TelemetryOutcome::Error,
            );
            return Err(error);
        }
        match self.wallet_call(self.wallet.cosigner_registry()) {
            Ok(registry) => {
                self.record_action(
                    WalletTelemetryAction::MultisigSetCosigners,
                    TelemetryOutcome::Success,
                );
                let cosigners = registry
                    .as_ref()
                    .map(|registry| registry.entries().iter().map(CosignerDto::from).collect())
                    .unwrap_or_default();
                to_value(SetCosignersResponse { cosigners })
            }
            Err(error) => {
                self.record_action(
                    WalletTelemetryAction::MultisigSetCosigners,
                    TelemetryOutcome::Error,
                );
                Err(error)
            }
        }
    }

    #[cfg(feature = "wallet_multisig_hooks")]
    fn multisig_export(&self, params: MultisigExportParams) -> Result<Value, RouterError> {
        let draft_id = params.draft_id;
        let drafts = match self.lock_drafts() {
            Ok(drafts) => drafts,
            Err(error) => {
                self.record_action(
                    WalletTelemetryAction::MultisigExport,
                    TelemetryOutcome::Error,
                );
                return Err(error);
            }
        };
        let metadata = match drafts.get(&draft_id) {
            Some(state) => state.metadata.multisig.clone(),
            None => {
                self.record_action(
                    WalletTelemetryAction::MultisigExport,
                    TelemetryOutcome::Error,
                );
                return Err(RouterError::MissingDraft(draft_id.clone()));
            }
        };
        drop(drafts);
        self.record_action(
            WalletTelemetryAction::MultisigExport,
            TelemetryOutcome::Success,
        );
        let metadata = metadata.as_ref().map(MultisigDraftMetadataDto::from);
        to_value(MultisigExportResponse { draft_id, metadata })
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
            tier_hooks: map_policy_tier_hooks(&preview.tier_hooks),
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
        match backup_export(
            store.as_ref(),
            self.wallet.keystore_path(),
            self.wallet.backup_dir(),
            passphrase,
            confirmation,
            options,
        ) {
            Ok(result) => {
                self.record_action(
                    WalletTelemetryAction::BackupExport,
                    TelemetryOutcome::Success,
                );
                let response = BackupExportResponse {
                    path: result.path.to_string_lossy().to_string(),
                    metadata: metadata_to_dto(&result.metadata),
                };
                to_value(response)
            }
            Err(error) => {
                self.record_action(WalletTelemetryAction::BackupExport, TelemetryOutcome::Error);
                Err(RouterError::Backup(error))
            }
        }
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
        match backup_validate(
            store.as_ref(),
            self.wallet.backup_dir(),
            &name,
            passphrase,
            mode,
        ) {
            Ok(validation) => {
                self.record_action(
                    WalletTelemetryAction::BackupValidate,
                    TelemetryOutcome::Success,
                );
                let response = BackupValidateResponse {
                    metadata: metadata_to_dto(&validation.metadata),
                    has_keystore: validation.has_keystore,
                    policy_count: validation.policy_count,
                    meta_entries: validation.meta_entries,
                };
                to_value(response)
            }
            Err(error) => {
                self.record_action(
                    WalletTelemetryAction::BackupValidate,
                    TelemetryOutcome::Error,
                );
                Err(RouterError::Backup(error))
            }
        }
    }

    fn handle_backup_import(&self, params: BackupImportParams) -> Result<Value, RouterError> {
        let BackupImportParams { name, passphrase } = params;
        let passphrase = Zeroizing::new(passphrase.into_bytes());
        let store = self.wallet.store();
        let outcome = match backup_import(
            store.as_ref(),
            self.wallet.keystore_path(),
            self.wallet.backup_dir(),
            &name,
            passphrase,
        ) {
            Ok(outcome) => {
                self.record_action(
                    WalletTelemetryAction::BackupImport,
                    TelemetryOutcome::Success,
                );
                outcome
            }
            Err(error) => {
                self.record_action(WalletTelemetryAction::BackupImport, TelemetryOutcome::Error);
                return Err(RouterError::Backup(error));
            }
        };
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
        let identity = self.wallet.prover_identity();
        let proof_size = output.proof().map(|proof| proof.as_ref().len());
        let locks = self.pending_lock_dtos()?;
        let response = SignTxResponse {
            draft_id: draft_id.clone(),
            backend: identity.backend.to_string(),
            witness_bytes: output.witness_bytes(),
            proof_generated: output.proof().is_some(),
            proof_size,
            duration_ms: output.duration().as_millis() as u64,
            locks,
        };
        state.prover_result = Some(output);
        drop(drafts);
        to_value(response)
    }

    fn broadcast_draft(&self, draft_id: String) -> Result<Value, RouterError> {
        if self.wallet.is_watch_only() {
            return Err(RouterError::WatchOnly(WatchOnlyError::BroadcastDisabled));
        }
        let mut drafts = self.lock_drafts()?;
        let state = drafts
            .get(&draft_id)
            .ok_or_else(|| RouterError::MissingDraft(draft_id.clone()))?;
        if state.prover_result.is_none() {
            return Err(RouterError::DraftUnsigned {
                draft_id,
                proof_required: self.wallet.prover_config().require_proof,
            });
        }
        if let Some(output) = &state.prover_result {
            if output.proof().is_none()
                && !self.wallet.prover_config().allow_broadcast_without_proof
            {
                return Err(RouterError::DraftUnsigned {
                    draft_id,
                    proof_required: true,
                });
            }
        }
        self.wallet_call(self.wallet.broadcast(&state.draft))?;
        let locks = self.pending_lock_dtos()?;
        to_value(BroadcastResponse {
            draft_id,
            accepted: true,
            locks,
        })
    }

    fn broadcast_raw(&self, tx_hex: String) -> Result<Value, RouterError> {
        let bytes = hex::decode(tx_hex).map_err(|err| {
            RouterError::InvalidParams(format!("invalid raw transaction hex: {err}"))
        })?;
        self.wallet_call(self.wallet.broadcast_raw(&bytes))?;
        to_value(BroadcastRawResponse { accepted: true })
    }

    fn watch_only_status(&self) -> Result<Value, RouterError> {
        match self.wallet.watch_only_status() {
            Ok(status) => {
                self.record_action(
                    WalletTelemetryAction::WatchOnlyStatus,
                    TelemetryOutcome::Success,
                );
                to_value(watch_only_status_to_dto(status))
            }
            Err(error) => {
                self.record_action(
                    WalletTelemetryAction::WatchOnlyStatus,
                    TelemetryOutcome::Error,
                );
                Err(RouterError::WatchOnly(error))
            }
        }
    }

    fn watch_only_enable(&self, params: WatchOnlyEnableParams) -> Result<Value, RouterError> {
        let record = watch_only_record_from_params(params);
        match self.wallet_call(self.wallet.enable_watch_only(record)) {
            Ok(status) => {
                self.record_action(
                    WalletTelemetryAction::WatchOnlyEnable,
                    TelemetryOutcome::Success,
                );
                to_value(watch_only_status_to_dto(status))
            }
            Err(error) => {
                self.record_action(
                    WalletTelemetryAction::WatchOnlyEnable,
                    TelemetryOutcome::Error,
                );
                Err(error)
            }
        }
    }

    fn watch_only_disable(&self) -> Result<Value, RouterError> {
        match self.wallet_call(self.wallet.disable_watch_only()) {
            Ok(status) => {
                self.record_action(
                    WalletTelemetryAction::WatchOnlyDisable,
                    TelemetryOutcome::Success,
                );
                to_value(watch_only_status_to_dto(status))
            }
            Err(error) => {
                self.record_action(
                    WalletTelemetryAction::WatchOnlyDisable,
                    TelemetryOutcome::Error,
                );
                Err(error)
            }
        }
    }

    fn store_draft(&self, bundle: DraftBundle) -> Result<String, RouterError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let identifier = format!("{id:016x}");
        let mut drafts = self.lock_drafts()?;
        drafts.insert(
            identifier.clone(),
            DraftState {
                draft: bundle.draft,
                metadata: bundle.metadata,
                prover_result: None,
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
    WatchOnly(WatchOnlyError),
    Sync(WalletSyncError),
    Node(NodeClientError),
    Backup(BackupError),
    MissingDraft(String),
    DraftUnsigned {
        draft_id: String,
        proof_required: bool,
    },
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
    fn telemetry_code(&self) -> Option<WalletRpcErrorCode> {
        match self {
            RouterError::InvalidRequest(_) => Some(WalletRpcErrorCode::InvalidRequest),
            RouterError::MethodNotFound(_) => Some(WalletRpcErrorCode::MethodNotFound),
            RouterError::InvalidParams(_) => Some(WalletRpcErrorCode::InvalidParams),
            RouterError::Wallet(error) => Some(wallet_error_code(error)),
            RouterError::WatchOnly(error) => Some(watch_only_error_code(error)),
            RouterError::Sync(_) => Some(WalletRpcErrorCode::SyncError),
            RouterError::Node(error) => Some(node_error_code(error)),
            RouterError::Backup(_) => Some(WalletRpcErrorCode::InternalError),
            RouterError::MissingDraft(_) => Some(WalletRpcErrorCode::DraftNotFound),
            RouterError::DraftUnsigned { .. } => Some(WalletRpcErrorCode::DraftUnsigned),
            RouterError::SyncUnavailable => Some(WalletRpcErrorCode::SyncUnavailable),
            RouterError::RescanOutOfRange { .. } => Some(WalletRpcErrorCode::RescanOutOfRange),
            RouterError::RescanInProgress { .. } => Some(WalletRpcErrorCode::RescanInProgress),
            RouterError::StatePoisoned => Some(WalletRpcErrorCode::StatePoisoned),
            RouterError::Serialization(_) => Some(WalletRpcErrorCode::SerializationFailure),
        }
    }
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
            RouterError::WatchOnly(error) => watch_only_error_to_json(&error),
            RouterError::Sync(error) => wallet_sync_error_to_json(&error),
            RouterError::Node(error) => node_error_to_json(&error),
            RouterError::Backup(error) => backup_error_to_json(&error),
            RouterError::MissingDraft(draft_id) => json_error(
                WalletRpcErrorCode::DraftNotFound,
                "draft not found",
                Some(json!({ "draft_id": draft_id })),
            ),
            RouterError::DraftUnsigned {
                draft_id,
                proof_required,
            } => json_error(
                WalletRpcErrorCode::DraftUnsigned,
                if *proof_required {
                    "draft must include a proof before broadcasting"
                } else {
                    "draft must be signed before broadcasting"
                },
                Some(json!({ "draft_id": draft_id, "proof_required": proof_required })),
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

fn send_stage_for_method(method: &str) -> Option<&'static str> {
    match method {
        "create_tx" => Some("draft"),
        "sign_tx" => Some("sign"),
        "broadcast" | "broadcast_raw" => Some("broadcast"),
        _ => None,
    }
}

fn rescan_stage_for_method(method: &str) -> Option<&'static str> {
    if method == "rescan" {
        Some("reschedule")
    } else {
        None
    }
}

fn wallet_error_code(error: &WalletError) -> WalletRpcErrorCode {
    match error {
        WalletError::Engine(_) => WalletRpcErrorCode::EngineFailure,
        WalletError::Prover(_) => WalletRpcErrorCode::ProverFailed,
        WalletError::Node(node) => node_error_code(node),
        WalletError::Sync(_) => WalletRpcErrorCode::SyncError,
        WalletError::WatchOnly(watch_only) => watch_only_error_code(watch_only),
        #[cfg(feature = "wallet_multisig_hooks")]
        WalletError::Multisig(_) => WalletRpcErrorCode::InvalidParams,
        WalletError::MultisigDisabled => WalletRpcErrorCode::InvalidRequest,
        WalletError::Zsi(_) => WalletRpcErrorCode::InvalidRequest,
        WalletError::HardwareFeatureDisabled => WalletRpcErrorCode::InvalidRequest,
        #[cfg(feature = "wallet_hw")]
        WalletError::Hardware(_) => WalletRpcErrorCode::EngineFailure,
        #[cfg(feature = "wallet_hw")]
        WalletError::HardwareUnavailable => WalletRpcErrorCode::InvalidRequest,
        #[cfg(feature = "wallet_hw")]
        WalletError::HardwareStatePoisoned => WalletRpcErrorCode::StatePoisoned,
        #[cfg(feature = "wallet_hw")]
        WalletError::HardwareDisabled => WalletRpcErrorCode::InvalidRequest,
    }
}

fn watch_only_error_code(error: &WatchOnlyError) -> WalletRpcErrorCode {
    match error {
        WatchOnlyError::StatePoisoned => WalletRpcErrorCode::StatePoisoned,
        WatchOnlyError::SigningDisabled | WatchOnlyError::BroadcastDisabled => {
            WalletRpcErrorCode::WatchOnlyNotEnabled
        }
    }
}

fn node_error_code(error: &NodeClientError) -> WalletRpcErrorCode {
    match error {
        NodeClientError::Network { .. } => WalletRpcErrorCode::NodeUnavailable,
        NodeClientError::Rejected { .. } => WalletRpcErrorCode::NodeRejected,
        NodeClientError::Policy { .. } => WalletRpcErrorCode::NodePolicy,
        NodeClientError::StatsUnavailable { .. } => WalletRpcErrorCode::NodeStatsUnavailable,
    }
}

fn watch_only_status_to_dto(status: WatchOnlyStatus) -> WatchOnlyStatusResponse {
    WatchOnlyStatusResponse {
        enabled: status.enabled,
        external_descriptor: status.external_descriptor,
        internal_descriptor: status.internal_descriptor,
        account_xpub: status.account_xpub,
        birthday_height: status.birthday_height,
    }
}

#[cfg(feature = "wallet_zsi")]
fn zsi_proof_params_to_request(params: ZsiProofParams) -> ZsiProofRequest {
    ZsiProofRequest {
        operation: params.operation,
        record: params.record,
    }
}

#[cfg(feature = "wallet_zsi")]
fn zsi_verify_params_to_request(params: ZsiVerifyParams) -> ZsiVerifyRequest {
    ZsiVerifyRequest {
        operation: params.operation,
        record: params.record,
        proof: params.proof,
    }
}

#[cfg(feature = "wallet_zsi")]
fn zsi_binding_to_dto(binding: ZsiBinding) -> ZsiBindingDto {
    ZsiBindingDto {
        operation: binding.operation,
        record: binding.record,
        witness: binding.witness,
        inputs: binding.inputs,
    }
}

#[cfg(feature = "wallet_zsi")]
fn zsi_artifact_to_dto(artifact: StoredZsiArtifact<'static>) -> ZsiArtifactDto {
    ZsiArtifactDto {
        recorded_at_ms: artifact.recorded_at_ms,
        identity: artifact.identity,
        commitment_digest: artifact.commitment_digest,
        backend: artifact.backend,
        proof: artifact.proof.into_owned(),
    }
}

#[cfg(feature = "wallet_hw")]
fn hardware_device_to_dto(device: HardwareDevice) -> HardwareDeviceDto {
    HardwareDeviceDto {
        fingerprint: device.fingerprint,
        model: device.model,
        label: device.label,
    }
}

#[cfg(feature = "wallet_hw")]
fn derivation_path_to_dto(path: &DerivationPath) -> DerivationPathDto {
    DerivationPathDto {
        account: path.account,
        change: path.change,
        index: path.index,
    }
}

#[cfg(feature = "wallet_hw")]
fn dto_to_derivation_path(dto: DerivationPathDto) -> DerivationPath {
    DerivationPath {
        account: dto.account,
        change: dto.change,
        index: dto.index,
    }
}

fn watch_only_record_from_params(params: WatchOnlyEnableParams) -> WatchOnlyRecord {
    let mut record = WatchOnlyRecord::new(params.external_descriptor);
    if let Some(internal) = params.internal_descriptor {
        record = record.with_internal_descriptor(internal);
    }
    if let Some(xpub) = params.account_xpub {
        record = record.with_account_xpub(xpub);
    }
    record.with_birthday_height(params.birthday_height)
}

fn wallet_error_to_json(error: &WalletError) -> JsonRpcError {
    match error {
        WalletError::Engine(engine) => engine_error_to_json(engine),
        WalletError::Prover(prover) => prover_error_to_json(prover),
        WalletError::Node(node) => node_error_to_json(node),
        WalletError::Sync(sync) => wallet_sync_error_to_json(sync),
        WalletError::WatchOnly(watch_only) => watch_only_error_to_json(watch_only),
        #[cfg(feature = "wallet_multisig_hooks")]
        WalletError::Multisig(multisig) => json_error(
            WalletRpcErrorCode::InvalidParams,
            multisig.to_string(),
            Some(json!({ "kind": "multisig" })),
        ),
        WalletError::MultisigDisabled => json_error(
            WalletRpcErrorCode::InvalidRequest,
            "wallet multisig support disabled at build time",
            Some(json!({ "kind": "multisig" })),
        ),
        WalletError::Zsi(zsi) => zsi_error_to_json(zsi),
        WalletError::HardwareFeatureDisabled => json_error(
            WalletRpcErrorCode::InvalidRequest,
            "wallet hardware support disabled at build time",
            None,
        ),
        #[cfg(feature = "wallet_hw")]
        WalletError::Hardware(err) => hardware_error_to_json(err),
        #[cfg(feature = "wallet_hw")]
        WalletError::HardwareUnavailable => json_error(
            WalletRpcErrorCode::InvalidRequest,
            "hardware signer not configured",
            None,
        ),
        #[cfg(feature = "wallet_hw")]
        WalletError::HardwareStatePoisoned => json_error(
            WalletRpcErrorCode::StatePoisoned,
            "hardware signer state unavailable",
            None,
        ),
        #[cfg(feature = "wallet_hw")]
        WalletError::HardwareDisabled => json_error(
            WalletRpcErrorCode::InvalidRequest,
            "wallet hardware support disabled by configuration",
            None,
        ),
    }
}

#[cfg(feature = "wallet_hw")]
fn hardware_error_to_json(error: &HardwareSignerError) -> JsonRpcError {
    match error {
        HardwareSignerError::DeviceNotFound { fingerprint } => json_error(
            WalletRpcErrorCode::InvalidParams,
            format!("hardware device `{fingerprint}` not found"),
            Some(json!({ "fingerprint": fingerprint })),
        ),
        HardwareSignerError::PathUnsupported { fingerprint, path } => json_error(
            WalletRpcErrorCode::InvalidParams,
            format!("hardware device `{fingerprint}` does not support derivation path {path}"),
            Some(json!({
                "fingerprint": fingerprint,
                "path": {
                    "account": path.account,
                    "change": path.change,
                    "index": path.index,
                }
            })),
        ),
        HardwareSignerError::Rejected { reason } => json_error(
            WalletRpcErrorCode::Custom("HW_REJECTED".into()),
            reason.clone(),
            None,
        ),
        HardwareSignerError::Communication(reason) => {
            json_error(WalletRpcErrorCode::EngineFailure, reason.clone(), None)
        }
        HardwareSignerError::Unsupported(reason) => {
            json_error(WalletRpcErrorCode::InvalidRequest, reason.clone(), None)
        }
    }
}

fn watch_only_error_to_json(error: &WatchOnlyError) -> JsonRpcError {
    match error {
        WatchOnlyError::StatePoisoned => json_error(
            WalletRpcErrorCode::StatePoisoned,
            "watch-only state unavailable",
            None,
        ),
        WatchOnlyError::SigningDisabled | WatchOnlyError::BroadcastDisabled => json_error(
            WalletRpcErrorCode::WatchOnlyNotEnabled,
            "wallet watch-only mode prevents this operation",
            None,
        ),
    }
}

fn zsi_error_to_json(error: &ZsiError) -> JsonRpcError {
    match error {
        ZsiError::Disabled => json_error(
            WalletRpcErrorCode::InvalidRequest,
            "zsi workflows disabled by configuration",
            None,
        ),
        ZsiError::BackendUnavailable => json_error(
            WalletRpcErrorCode::InternalError,
            "zsi backend not configured",
            None,
        ),
        ZsiError::Unsupported => json_error(
            WalletRpcErrorCode::InvalidRequest,
            "zsi backend does not support identity proofs",
            None,
        ),
        ZsiError::Backend(err) => json_error(
            WalletRpcErrorCode::InvalidRequest,
            err.to_string(),
            Some(json!({ "kind": "zsi_backend" })),
        ),
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
        EngineError::Multisig(multisig) => json_error(
            WalletRpcErrorCode::InvalidParams,
            multisig.to_string(),
            Some(json!({ "kind": "multisig" })),
        ),
    }
}

#[cfg(feature = "wallet_multisig_hooks")]
fn scope_from_dto(dto: MultisigScopeDto) -> Result<MultisigScope, RouterError> {
    MultisigScope::new(dto.threshold, dto.participants)
        .map_err(|err| RouterError::InvalidParams(err.to_string()))
}

#[cfg(feature = "wallet_multisig_hooks")]
fn registry_from_dtos(dtos: Vec<CosignerDto>) -> Result<CosignerRegistry, RouterError> {
    let cosigners = dtos
        .into_iter()
        .map(cosigner_from_dto)
        .collect::<Result<Vec<_>, _>>()?;
    CosignerRegistry::new(cosigners).map_err(|err| RouterError::InvalidParams(err.to_string()))
}

#[cfg(feature = "wallet_multisig_hooks")]
fn cosigner_from_dto(dto: CosignerDto) -> Result<Cosigner, RouterError> {
    Cosigner::new(dto.fingerprint, dto.endpoint)
        .map_err(|err| RouterError::InvalidParams(err.to_string()))
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
        ProverError::Busy => json_error(
            WalletRpcErrorCode::ProverFailed,
            error.to_string(),
            Some(json!({ "kind": "busy" })),
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

fn map_policy_tier_hooks(hooks: &crate::config::wallet::PolicyTierHooks) -> PolicyTierHooksDto {
    PolicyTierHooksDto {
        enabled: hooks.enabled,
        hook: hooks.hook.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::dto::WatchOnlyStatusResponse;
    #[cfg(feature = "wallet_hw")]
    use super::dto::{HardwareEnumerateResponse, HardwareSignResponse};
    use super::error::WalletRpcErrorCode;
    use super::*;
    use crate::config::wallet::{
        WalletFeeConfig, WalletHwConfig, WalletPolicyConfig, WalletProverConfig, WalletZsiConfig,
    };
    use crate::db::UtxoOutpoint;
    use crate::db::WalletStore;
    #[cfg(feature = "wallet_hw")]
    use crate::engine::DerivationPath;
    use crate::engine::{DraftInput, DraftOutput, SpendModel};
    #[cfg(feature = "wallet_hw")]
    use crate::hw::{HardwareDevice, HardwareSignature, HardwareSignerError, MockHardwareSigner};
    use crate::indexer::scanner::SyncCheckpoints;
    use crate::node_client::{
        BlockFeeSummary, ChainHead, MempoolInfo, NodeClient, NodeClientError, NodeClientResult,
        NodeRejectionHint, StubNodeClient,
    };
    use serde_json::json;
    use std::sync::Mutex;
    use tempfile::tempdir;

    fn router_fixture(
        sync: Option<Arc<dyn SyncHandle>>,
    ) -> (WalletRpcRouter, Arc<WalletStore>, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(dir.path()).expect("store"));
        let keystore = dir.path().join("keystore.toml");
        let backup = dir.path().join("backups");
        let telemetry = Arc::new(WalletActionTelemetry::new(false));
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [0u8; 32],
            },
            WalletPolicyConfig::default(),
            WalletFeeConfig::default(),
            WalletProverConfig::default(),
            WalletHwConfig::default(),
            WalletZsiConfig::default(),
            None,
            Arc::new(StubNodeClient::default()),
            WalletPaths::new(keystore, backup),
            Arc::clone(&telemetry),
        )
        .expect("wallet");
        let metrics = noop_runtime_metrics();
        (
            WalletRpcRouter::new(Arc::new(wallet), sync, metrics),
            store,
            dir,
        )
    }

    fn build_router(sync: Option<Arc<dyn SyncHandle>>) -> WalletRpcRouter {
        let (router, _store, dir) = router_fixture(sync);
        let _persist = dir.into_path();
        router
    }

    #[cfg(feature = "wallet_hw")]
    fn hardware_router() -> (WalletRpcRouter, MockHardwareSigner, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(dir.path()).expect("store"));
        let keystore = dir.path().join("keystore.toml");
        let backup = dir.path().join("backups");
        let telemetry = Arc::new(WalletActionTelemetry::new(false));
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [9u8; 32],
            },
            WalletPolicyConfig::default(),
            WalletFeeConfig::default(),
            WalletProverConfig::default(),
            {
                let mut hw = WalletHwConfig::default();
                hw.enabled = true;
                hw
            },
            WalletZsiConfig::default(),
            None,
            Arc::new(StubNodeClient::default()),
            WalletPaths::new(keystore, backup),
            Arc::clone(&telemetry),
        )
        .expect("wallet");
        let signer = MockHardwareSigner::new(vec![
            HardwareDevice::new("deadbeef", "TestSigner").with_label("Primary")
        ]);
        wallet
            .configure_hardware_signer(Some(Arc::new(signer.clone())))
            .expect("configure signer");
        let metrics = noop_runtime_metrics();
        (
            WalletRpcRouter::new(Arc::new(wallet), None, metrics),
            signer,
            dir,
        )
    }

    fn build_watch_only_router() -> WalletRpcRouter {
        let dir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(dir.path()).expect("store"));
        let keystore = dir.path().join("keystore.toml");
        let backup = dir.path().join("backups");
        let record = WatchOnlyRecord::new("wpkh(external)");
        let telemetry = Arc::new(WalletActionTelemetry::new(false));
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::WatchOnly(record),
            WalletPolicyConfig::default(),
            WalletFeeConfig::default(),
            WalletProverConfig::default(),
            WalletHwConfig::default(),
            WalletZsiConfig::default(),
            None,
            Arc::new(StubNodeClient::default()),
            WalletPaths::new(keystore, backup),
            Arc::clone(&telemetry),
        )
        .expect("wallet");
        let _persist = dir.into_path();
        let metrics = noop_runtime_metrics();
        WalletRpcRouter::new(Arc::new(wallet), None, metrics)
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

    #[test]
    fn watch_only_router_rejects_sign_and_broadcast() {
        let router = build_watch_only_router();
        let draft = DraftTransaction {
            inputs: vec![DraftInput {
                outpoint: UtxoOutpoint::new([1u8; 32], 0),
                value: 5_000,
                confirmations: 1,
            }],
            outputs: vec![DraftOutput::new("addr", 4_000, false)],
            fee_rate: 1,
            fee: 1_000,
            spend_model: SpendModel::Exact { amount: 4_000 },
        };

        {
            let mut drafts = router.drafts.lock().unwrap();
            drafts.insert(
                "watch-sign".to_string(),
                DraftState {
                    draft: draft.clone(),
                    metadata: BuildMetadata {
                        selection: None,
                        change_outputs: 0,
                        change_folded_into_fee: false,
                        estimated_vbytes: 0,
                        multisig: None,
                    },
                    prover_result: None,
                },
            );
            drafts.insert(
                "watch-broadcast".to_string(),
                DraftState {
                    draft,
                    metadata: BuildMetadata {
                        selection: None,
                        change_outputs: 0,
                        change_folded_into_fee: false,
                        estimated_vbytes: 0,
                        multisig: None,
                    },
                    prover_result: None,
                },
            );
        }

        let sign_request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(1)),
            method: "sign_tx".to_string(),
            params: Some(json!({ "draft_id": "watch-sign" })),
        };
        let sign_error = router.handle(sign_request).error.expect("sign error");
        assert_eq!(
            sign_error.code,
            WalletRpcErrorCode::WatchOnlyNotEnabled.as_i32()
        );

        let broadcast_request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(2)),
            method: "broadcast".to_string(),
            params: Some(json!({ "draft_id": "watch-broadcast" })),
        };
        let broadcast_error = router
            .handle(broadcast_request)
            .error
            .expect("broadcast error");
        assert_eq!(
            broadcast_error.code,
            WalletRpcErrorCode::WatchOnlyNotEnabled.as_i32()
        );
    }

    #[test]
    fn watch_only_enable_disable_updates_store() {
        let (router, store, _tempdir) = router_fixture(None);
        assert!(store
            .watch_only_record()
            .expect("watch-only record")
            .is_none());

        let enable_request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(1)),
            method: "watch_only.enable".to_string(),
            params: Some(json!({
                "external_descriptor": "wpkh(external)",
                "internal_descriptor": "wpkh(internal)",
                "account_xpub": "xpub123",
                "birthday_height": 321u64,
            })),
        };
        let enable_response = router.handle(enable_request);
        assert!(enable_response.error.is_none());
        let enable_status: WatchOnlyStatusResponse =
            serde_json::from_value(enable_response.result.expect("enable result"))
                .expect("enable status");
        assert!(enable_status.enabled);
        assert_eq!(
            enable_status.external_descriptor.as_deref(),
            Some("wpkh(external)"),
        );
        assert_eq!(
            store.watch_only_record().expect("record read"),
            Some(
                WatchOnlyRecord::new("wpkh(external)")
                    .with_internal_descriptor("wpkh(internal)")
                    .with_account_xpub("xpub123")
                    .with_birthday_height(Some(321)),
            ),
        );

        let status_response = router.handle(JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(2)),
            method: "watch_only.status".to_string(),
            params: None,
        });
        assert!(status_response.error.is_none());
        let status: WatchOnlyStatusResponse =
            serde_json::from_value(status_response.result.expect("status result")).expect("status");
        assert!(status.enabled);
        assert_eq!(status.birthday_height, Some(321));

        let disable_response = router.handle(JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(3)),
            method: "watch_only.disable".to_string(),
            params: None,
        });
        assert!(disable_response.error.is_none());
        let disable_status: WatchOnlyStatusResponse =
            serde_json::from_value(disable_response.result.expect("disable result"))
                .expect("disable status");
        assert!(!disable_status.enabled);
        assert!(store
            .watch_only_record()
            .expect("post-disable record")
            .is_none());
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
        fn submit_tx(
            &self,
            _submission: &crate::node_client::TransactionSubmission,
        ) -> NodeClientResult<()> {
            Err(NodeClientError::rejected_with_hint(
                "mempool rejection",
                NodeRejectionHint::FeeRateTooLow { required: Some(25) },
            ))
        }

        fn submit_raw_tx(&self, _tx: &[u8]) -> NodeClientResult<()> {
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

        fn mempool_status(&self) -> NodeClientResult<crate::node_client::MempoolStatus> {
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
            WalletMode::Full {
                root_seed: [0u8; 32],
            },
            WalletPolicyConfig::default(),
            WalletFeeConfig::default(),
            WalletProverConfig::default(),
            WalletZsiConfig::default(),
            None,
            Arc::new(RejectingNodeClient::new()),
            WalletPaths::new(keystore, backup),
        )
        .expect("wallet");
        let sync = Arc::new(RecordingSync::default());
        let router =
            WalletRpcRouter::new(Arc::new(wallet), Some(sync.clone()), noop_runtime_metrics());

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
                    metadata: BuildMetadata {
                        selection: None,
                        change_outputs: 0,
                        change_folded_into_fee: false,
                        estimated_vbytes: 0,
                        multisig: None,
                    },
                    prover_result: Some(ProveResult::new(None, 0, Instant::now(), Instant::now())),
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

    #[cfg(feature = "wallet_hw")]
    #[test]
    fn hw_enumerate_lists_devices() {
        let (router, _signer, _dir) = hardware_router();
        let request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(1)),
            method: "hw.enumerate".to_string(),
            params: None,
        };
        let response = router.handle(request);
        assert!(response.error.is_none());
        let result = response.result.expect("result");
        let enumerate: HardwareEnumerateResponse = serde_json::from_value(result).expect("decode");
        assert_eq!(enumerate.devices.len(), 1);
        assert_eq!(enumerate.devices[0].fingerprint, "deadbeef");
    }

    #[cfg(feature = "wallet_hw")]
    #[test]
    fn hw_methods_rejected_when_disabled_in_config() {
        let router = build_router(None);
        let request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(1)),
            method: "hw.enumerate".to_string(),
            params: None,
        };
        let response = router.handle(request);
        let error = response.error.expect("error");
        assert_eq!(error.code, WalletRpcErrorCode::InvalidRequest.as_i32());
        assert_eq!(error.message, HARDWARE_DISABLED_ERROR);
    }

    #[cfg(feature = "wallet_hw")]
    #[test]
    fn hw_sign_produces_signature() {
        let (router, signer, _dir) = hardware_router();
        signer.push_sign_response(Ok(HardwareSignature::new(
            "deadbeef",
            DerivationPath::new(0, false, 1),
            [0x11u8; 64],
            [0x22u8; 33],
        )));
        let request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(1)),
            method: "hw.sign".to_string(),
            params: Some(json!({
                "fingerprint": "deadbeef",
                "path": { "account": 0, "change": false, "index": 1 },
                "payload": hex_encode([0xAAu8; 32]),
            })),
        };
        let response = router.handle(request);
        assert!(response.error.is_none());
        let result = response.result.expect("result");
        let sign: HardwareSignResponse = serde_json::from_value(result).expect("decode");
        assert_eq!(sign.fingerprint, "deadbeef");
        assert_eq!(sign.signature, hex_encode([0x11u8; 64]));
        assert_eq!(sign.public_key, hex_encode([0x22u8; 33]));
    }

    #[cfg(feature = "wallet_hw")]
    #[test]
    fn hw_sign_rejection_returns_error() {
        let (router, signer, _dir) = hardware_router();
        signer.push_sign_response(Err(HardwareSignerError::rejected("user cancelled")));
        let request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(json!(1)),
            method: "hw.sign".to_string(),
            params: Some(json!({
                "fingerprint": "deadbeef",
                "path": { "account": 0, "change": false, "index": 0 },
                "payload": hex_encode([0x55u8; 16]),
            })),
        };
        let response = router.handle(request);
        let error = response.error.expect("error");
        assert_eq!(
            error.code,
            WalletRpcErrorCode::Custom("HW_REJECTED".into()).as_i32()
        );
        assert_eq!(error.message, "user cancelled");
        let data = error.data.expect("data");
        assert_eq!(data["code"], json!("HW_REJECTED"));
    }
}
