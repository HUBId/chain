use crate::config::wallet::PolicyTierHooks;
use crate::engine::{FeeCongestionLevel, FeeEstimateSource};
#[cfg(feature = "wallet_multisig_hooks")]
use crate::multisig::{Cosigner, MultisigDraftMetadata, MultisigScope};
use crate::proof_backend::IdentityPublicInputs;
use crate::zsi::{LifecycleProof, ZsiOperation, ZsiRecord};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const JSONRPC_VERSION: &str = "2.0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcRequest {
    #[serde(default)]
    pub jsonrpc: Option<String>,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(default)]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<Value>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            id,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    pub fn new(code: i32, message: impl Into<String>, data: Option<Value>) -> Self {
        Self {
            code,
            message: message.into(),
            data,
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct EmptyParams;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BalanceResponse {
    pub confirmed: u128,
    pub pending: u128,
    pub total: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UtxoDto {
    pub txid: String,
    pub index: u32,
    pub value: u128,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timelock: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListUtxosResponse {
    pub utxos: Vec<UtxoDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionEntryDto {
    pub txid: String,
    pub height: u64,
    pub timestamp_ms: u64,
    pub payload_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListTransactionsResponse {
    pub entries: Vec<TransactionEntryDto>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListTransactionsParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<TransactionDirectionDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<TransactionConfirmationDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_timestamp_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_timestamp_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txid: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionDirectionDto {
    Incoming,
    Outgoing,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionConfirmationDto {
    Pending,
    Confirmed,
    Pruned,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionHistoryStatusDto {
    Pending,
    Confirmed,
    Pruned,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionPartyDto {
    pub address: String,
    pub value: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionHistoryEntryDto {
    pub txid: String,
    pub timestamp_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<u128>,
    pub direction: TransactionDirectionDto,
    pub status: TransactionHistoryStatusDto,
    #[serde(default)]
    pub inputs: Vec<TransactionPartyDto>,
    #[serde(default)]
    pub outputs: Vec<TransactionPartyDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListTransactionsPageResponse {
    pub entries: Vec<TransactionHistoryEntryDto>,
    pub page: u32,
    pub page_size: u32,
    pub total: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeriveAddressParams {
    #[serde(default)]
    pub change: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeriveAddressResponse {
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateTxParams {
    pub to: String,
    pub amount: u128,
    #[serde(default)]
    pub fee_rate: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DraftInputDto {
    pub txid: String,
    pub index: u32,
    pub value: u128,
    pub confirmations: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DraftOutputDto {
    pub address: String,
    pub value: u128,
    pub change: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingLockDto {
    pub utxo_txid: String,
    pub utxo_index: u32,
    pub locked_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spending_txid: Option<String>,
    #[serde(default)]
    pub backend: String,
    #[serde(default)]
    pub witness_bytes: u64,
    #[serde(default)]
    pub prove_duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub proof_bytes: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySnapshotDto {
    pub revision: u64,
    pub updated_at: u64,
    pub statements: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DraftSpendModelDto {
    Exact { amount: u128 },
    Sweep,
    Account { debit: u128 },
}

#[cfg(feature = "wallet_hw")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardwareDeviceDto {
    pub fingerprint: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[cfg(feature = "wallet_hw")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardwareEnumerateResponse {
    pub devices: Vec<HardwareDeviceDto>,
}

#[cfg(feature = "wallet_hw")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerivationPathDto {
    pub account: u32,
    pub change: bool,
    pub index: u32,
}

#[cfg(feature = "wallet_hw")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardwareSignParams {
    pub fingerprint: String,
    pub path: DerivationPathDto,
    /// Hex-encoded payload to sign.
    pub payload: String,
}

#[cfg(feature = "wallet_hw")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct HardwareSignResponse {
    pub fingerprint: String,
    pub path: DerivationPathDto,
    /// Hex-encoded signature emitted by the hardware device.
    pub signature: String,
    /// Hex-encoded public key corresponding to the derivation path.
    pub public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateTxResponse {
    pub draft_id: String,
    pub fee_rate: u64,
    pub fee: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_source: Option<FeeEstimateSourceDto>,
    pub total_input_value: u128,
    pub total_output_value: u128,
    pub spend_model: DraftSpendModelDto,
    pub inputs: Vec<DraftInputDto>,
    pub outputs: Vec<DraftOutputDto>,
    pub locks: Vec<PendingLockDto>,
    #[cfg(feature = "wallet_multisig_hooks")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multisig: Option<MultisigDraftMetadataDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeeEstimateSourceDto {
    Override,
    Node {
        congestion: FeeCongestionDto,
        samples: usize,
    },
    ConfigFallback,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeeCongestionDto {
    Low,
    Moderate,
    High,
    Unknown,
}

impl From<&FeeEstimateSource> for FeeEstimateSourceDto {
    fn from(source: &FeeEstimateSource) -> Self {
        match source {
            FeeEstimateSource::Override => FeeEstimateSourceDto::Override,
            FeeEstimateSource::ConfigFallback => FeeEstimateSourceDto::ConfigFallback,
            FeeEstimateSource::Node {
                congestion,
                samples,
            } => FeeEstimateSourceDto::Node {
                congestion: (*congestion).into(),
                samples: *samples,
            },
        }
    }
}

impl From<FeeCongestionLevel> for FeeCongestionDto {
    fn from(level: FeeCongestionLevel) -> Self {
        match level {
            FeeCongestionLevel::Low => FeeCongestionDto::Low,
            FeeCongestionLevel::Moderate => FeeCongestionDto::Moderate,
            FeeCongestionLevel::High => FeeCongestionDto::High,
            FeeCongestionLevel::Unknown => FeeCongestionDto::Unknown,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignTxParams {
    pub draft_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignTxResponse {
    pub draft_id: String,
    pub backend: String,
    pub witness_bytes: usize,
    pub proof_generated: bool,
    pub proof_size: Option<usize>,
    pub duration_ms: u64,
    pub locks: Vec<PendingLockDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultisigScopeDto {
    pub threshold: u8,
    pub participants: u8,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CosignerDto {
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultisigDraftMetadataDto {
    pub scope: MultisigScopeDto,
    pub cosigners: Vec<CosignerDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
impl From<&MultisigDraftMetadata> for MultisigDraftMetadataDto {
    fn from(metadata: &MultisigDraftMetadata) -> Self {
        Self {
            scope: MultisigScopeDto {
                threshold: metadata.scope.threshold(),
                participants: metadata.scope.participants(),
            },
            cosigners: metadata.cosigners.iter().map(CosignerDto::from).collect(),
        }
    }
}

#[cfg(feature = "wallet_multisig_hooks")]
impl From<&Cosigner> for CosignerDto {
    fn from(value: &Cosigner) -> Self {
        Self {
            fingerprint: value.fingerprint.clone(),
            endpoint: value.endpoint.clone(),
        }
    }
}

#[cfg(feature = "wallet_multisig_hooks")]
impl From<&MultisigScope> for MultisigScopeDto {
    fn from(scope: &MultisigScope) -> Self {
        Self {
            threshold: scope.threshold(),
            participants: scope.participants(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BroadcastParams {
    pub draft_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BroadcastResponse {
    pub draft_id: String,
    pub accepted: bool,
    pub locks: Vec<PendingLockDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BroadcastRawParams {
    pub tx_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BroadcastRawResponse {
    pub accepted: bool,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetMultisigScopeResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<MultisigScopeDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetMultisigScopeParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<MultisigScopeDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetMultisigScopeResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<MultisigScopeDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetCosignersResponse {
    pub cosigners: Vec<CosignerDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetCosignersParams {
    pub cosigners: Vec<CosignerDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetCosignersResponse {
    pub cosigners: Vec<CosignerDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultisigExportParams {
    pub draft_id: String,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MultisigExportResponse {
    pub draft_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MultisigDraftMetadataDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyPreviewResponse {
    pub min_confirmations: u32,
    pub dust_limit: u128,
    pub max_change_outputs: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spend_limit_daily: Option<u128>,
    pub pending_lock_timeout: u64,
    pub tier_hooks: PolicyTierHooks,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetPolicyResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<PolicySnapshotDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetPolicyParams {
    #[serde(default)]
    pub statements: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetPolicyResponse {
    pub snapshot: PolicySnapshotDto,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchOnlyEnableParams {
    pub external_descriptor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_descriptor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_xpub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthday_height: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchOnlyStatusResponse {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_descriptor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_descriptor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_xpub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthday_height: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EstimateFeeParams {
    pub confirmation_target: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EstimateFeeResponse {
    pub confirmation_target: u16,
    pub fee_rate: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListPendingLocksResponse {
    pub locks: Vec<PendingLockDto>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleasePendingLocksParams;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleasePendingLocksResponse {
    pub released: Vec<PendingLockDto>,
}

#[cfg(feature = "wallet_rpc_mtls")]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletRoleDto {
    Admin,
    Operator,
    Viewer,
}

#[cfg(feature = "wallet_rpc_mtls")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityAssignmentDto {
    pub identity: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<WalletRoleDto>,
}

#[cfg(feature = "wallet_rpc_mtls")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityFingerprintDto {
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[cfg(feature = "wallet_rpc_mtls")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecuritySnapshotResponse {
    pub mtls_enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assignments: Vec<SecurityAssignmentDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ca_fingerprints: Vec<SecurityFingerprintDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub current_roles: Vec<WalletRoleDto>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_fingerprints: Vec<String>,
}

#[cfg(feature = "wallet_rpc_mtls")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityAssignParams {
    pub identity: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<WalletRoleDto>,
}

#[cfg(feature = "wallet_rpc_mtls")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityRemoveParams {
    pub identity: String,
}

#[cfg(feature = "wallet_rpc_mtls")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityMtlsUpdateParams {
    pub enabled: bool,
}

#[cfg(feature = "wallet_rpc_mtls")]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityCertificateUploadParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_certificate_path: Option<String>,
}

#[cfg(feature = "wallet_rpc_mtls")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityCertificateUploadResponse {
    pub stored: bool,
}

#[cfg(not(feature = "wallet_rpc_mtls"))]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletRoleDto {}

#[cfg(not(feature = "wallet_rpc_mtls"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityAssignmentDto;

#[cfg(not(feature = "wallet_rpc_mtls"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityFingerprintDto;

#[cfg(not(feature = "wallet_rpc_mtls"))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecuritySnapshotResponse;

#[cfg(not(feature = "wallet_rpc_mtls"))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityAssignParams;

#[cfg(not(feature = "wallet_rpc_mtls"))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityRemoveParams;

#[cfg(not(feature = "wallet_rpc_mtls"))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityMtlsUpdateParams;

#[cfg(not(feature = "wallet_rpc_mtls"))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityCertificateUploadParams;

#[cfg(not(feature = "wallet_rpc_mtls"))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityCertificateUploadResponse;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupMetadataDto {
    pub version: u32,
    pub schema_checksum: String,
    pub created_at_ms: u64,
    pub has_keystore: bool,
    pub policy_entries: usize,
    pub meta_entries: usize,
    pub include_checksums: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupExportParams {
    pub passphrase: String,
    pub confirmation: String,
    #[serde(default)]
    pub metadata_only: bool,
    #[serde(default = "default_include_checksums")]
    pub include_checksums: bool,
}

fn default_include_checksums() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupExportResponse {
    pub path: String,
    pub metadata: BackupMetadataDto,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BackupValidationModeDto {
    DryRun,
    Full,
}

impl Default for BackupValidationModeDto {
    fn default() -> Self {
        BackupValidationModeDto::Full
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupValidateParams {
    pub name: String,
    pub passphrase: String,
    #[serde(default)]
    pub mode: BackupValidationModeDto,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupValidateResponse {
    pub metadata: BackupMetadataDto,
    pub has_keystore: bool,
    pub policy_count: usize,
    pub meta_entries: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupImportParams {
    pub name: String,
    pub passphrase: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupImportResponse {
    pub metadata: BackupMetadataDto,
    pub restored_keystore: bool,
    pub restored_policy: bool,
    pub rescan_from_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MempoolInfoResponse {
    pub tx_count: u64,
    pub vsize_limit: u64,
    pub vsize_in_use: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_fee_rate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_rate: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentBlocksParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockFeeSummaryDto {
    pub height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub median_fee_rate: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_rate: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentBlocksResponse {
    pub blocks: Vec<BlockFeeSummaryDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelemetryCounterDto {
    pub name: String,
    pub value: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelemetryCountersResponse {
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub counters: Vec<TelemetryCounterDto>,
}

#[cfg(feature = "wallet_zsi")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiProofParams {
    pub operation: ZsiOperation,
    pub record: ZsiRecord,
}

#[cfg(not(feature = "wallet_zsi"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiProofParams {
    pub operation: ZsiOperation,
    pub record: ZsiRecord,
}

#[cfg(feature = "wallet_zsi")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiProveResponse {
    pub proof: LifecycleProof,
}

#[cfg(not(feature = "wallet_zsi"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiProveResponse {
    pub proof: LifecycleProof,
}

#[cfg(feature = "wallet_zsi")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiVerifyParams {
    pub operation: ZsiOperation,
    pub record: ZsiRecord,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

#[cfg(not(feature = "wallet_zsi"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiVerifyParams {
    pub operation: ZsiOperation,
    pub record: ZsiRecord,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

#[cfg(feature = "wallet_zsi")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiVerifyResponse {
    pub valid: bool,
}

#[cfg(not(feature = "wallet_zsi"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiVerifyResponse {
    pub valid: bool,
}

#[cfg(feature = "wallet_zsi")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiBindResponse {
    pub binding: ZsiBindingDto,
}

#[cfg(not(feature = "wallet_zsi"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiBindResponse {
    pub binding: ZsiBindingDto,
}

#[cfg(feature = "wallet_zsi")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiBindingDto {
    pub operation: ZsiOperation,
    pub record: ZsiRecord,
    #[serde(with = "serde_bytes")]
    pub witness: Vec<u8>,
    pub inputs: IdentityPublicInputs,
}

#[cfg(not(feature = "wallet_zsi"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiBindingDto {
    pub operation: ZsiOperation,
    pub record: ZsiRecord,
    #[serde(with = "serde_bytes")]
    pub witness: Vec<u8>,
    pub inputs: IdentityPublicInputs,
}

#[cfg(feature = "wallet_zsi")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiListResponse {
    pub artifacts: Vec<ZsiArtifactDto>,
}

#[cfg(not(feature = "wallet_zsi"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiListResponse {
    pub artifacts: Vec<ZsiArtifactDto>,
}

#[cfg(feature = "wallet_zsi")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiArtifactDto {
    pub recorded_at_ms: u64,
    pub identity: String,
    pub commitment_digest: String,
    pub backend: String,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

#[cfg(not(feature = "wallet_zsi"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiArtifactDto {
    pub recorded_at_ms: u64,
    pub identity: String,
    pub commitment_digest: String,
    pub backend: String,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

#[cfg(feature = "wallet_zsi")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiDeleteParams {
    pub identity: String,
    pub commitment_digest: String,
}

#[cfg(not(feature = "wallet_zsi"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiDeleteParams {
    pub identity: String,
    pub commitment_digest: String,
}

#[cfg(feature = "wallet_zsi")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiDeleteResponse {
    pub deleted: bool,
}

#[cfg(not(feature = "wallet_zsi"))]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiDeleteResponse {
    pub deleted: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncStatusParams;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncStatusResponse {
    pub syncing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<SyncModeDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_scripthashes: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_ranges: Vec<(u64, u64)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoints: Option<SyncCheckpointDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rescan_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_issue: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hints: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SyncModeDto {
    Full { start_height: u64 },
    Resume { from_height: u64 },
    Rescan { from_height: u64 },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncCheckpointDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birthday_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_scan_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_full_rescan_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_compact_scan_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_targeted_rescan_ts: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RescanParams {
    #[serde(default)]
    pub from_height: Option<u64>,
    #[serde(default)]
    pub lookback_blocks: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RescanResponse {
    pub scheduled: bool,
    pub from_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use std::fmt::Debug;

    fn roundtrip<T>(value: &T)
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug,
    {
        let json = serde_json::to_value(value).expect("serialize");
        let restored: T = serde_json::from_value(json).expect("deserialize");
        assert_eq!(&restored, value);
    }

    #[test]
    fn jsonrpc_request_roundtrip() {
        let request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(Value::from(1)),
            method: "get_balance".to_string(),
            params: Some(Value::from(serde_json::json!({"change": false}))),
        };
        roundtrip(&request);
    }

    #[test]
    fn jsonrpc_response_roundtrip() {
        let response = JsonRpcResponse::success(
            Some(Value::from(1)),
            Value::from(serde_json::json!({"ok": true})),
        );
        roundtrip(&response);
    }

    #[test]
    fn jsonrpc_error_roundtrip() {
        let error = JsonRpcError::new(-32000, "wallet error", Some(Value::from("boom")));
        roundtrip(&error);
    }

    #[test]
    fn balance_response_roundtrip() {
        let balance = BalanceResponse {
            confirmed: 100,
            pending: 25,
            total: 125,
        };
        roundtrip(&balance);
    }

    #[test]
    fn utxo_roundtrip() {
        let utxo = UtxoDto {
            txid: "ff".to_string(),
            index: 0,
            value: 42,
            owner: "addr".to_string(),
            timelock: Some(12),
        };
        roundtrip(&utxo);
    }

    #[test]
    fn list_utxos_response_roundtrip() {
        let response = ListUtxosResponse {
            utxos: vec![UtxoDto {
                txid: "aa".to_string(),
                index: 1,
                value: 10,
                owner: "addr".to_string(),
                timelock: None,
            }],
        };
        roundtrip(&response);
    }

    #[test]
    fn transaction_entry_roundtrip() {
        let entry = TransactionEntryDto {
            txid: "bb".to_string(),
            height: 5,
            timestamp_ms: 1234,
            payload_bytes: 128,
        };
        roundtrip(&entry);
    }

    #[test]
    fn list_transactions_response_roundtrip() {
        let response = ListTransactionsResponse {
            entries: vec![TransactionEntryDto {
                txid: "cc".to_string(),
                height: 6,
                timestamp_ms: 5678,
                payload_bytes: 256,
            }],
        };
        roundtrip(&response);
    }

    #[test]
    fn derive_address_params_roundtrip() {
        let params = DeriveAddressParams { change: true };
        roundtrip(&params);
    }

    #[test]
    fn derive_address_response_roundtrip() {
        let response = DeriveAddressResponse {
            address: "wallet1".to_string(),
        };
        roundtrip(&response);
    }

    #[test]
    fn create_tx_params_roundtrip() {
        let params = CreateTxParams {
            to: "wallet1".to_string(),
            amount: 50,
            fee_rate: Some(2),
        };
        roundtrip(&params);
    }

    #[test]
    fn draft_input_roundtrip() {
        let input = DraftInputDto {
            txid: "dd".to_string(),
            index: 2,
            value: 75,
            confirmations: 3,
        };
        roundtrip(&input);
    }

    #[test]
    fn draft_output_roundtrip() {
        let output = DraftOutputDto {
            address: "wallet2".to_string(),
            value: 80,
            change: false,
        };
        roundtrip(&output);
    }

    #[test]
    fn draft_spend_model_roundtrip() {
        let model = DraftSpendModelDto::Exact { amount: 100 };
        roundtrip(&model);
        let sweep = DraftSpendModelDto::Sweep;
        roundtrip(&sweep);
    }

    #[test]
    fn create_tx_response_roundtrip() {
        let response = CreateTxResponse {
            draft_id: "draft1".to_string(),
            fee_rate: 2,
            fee: 4,
            fee_source: None,
            total_input_value: 104,
            total_output_value: 100,
            spend_model: DraftSpendModelDto::Exact { amount: 100 },
            inputs: vec![DraftInputDto {
                txid: "ee".to_string(),
                index: 0,
                value: 104,
                confirmations: 10,
            }],
            outputs: vec![DraftOutputDto {
                address: "wallet3".to_string(),
                value: 100,
                change: false,
            }],
        };
        roundtrip(&response);
    }

    #[test]
    fn sign_tx_params_roundtrip() {
        let params = SignTxParams {
            draft_id: "draft1".to_string(),
        };
        roundtrip(&params);
    }

    #[test]
    fn sign_tx_response_roundtrip() {
        let response = SignTxResponse {
            draft_id: "draft1".to_string(),
            backend: "mock".to_string(),
            witness_bytes: 512,
            proof_generated: true,
            proof_size: Some(256),
            duration_ms: 42,
            locks: vec![PendingLockDto {
                utxo_txid: "aa".into(),
                utxo_index: 0,
                locked_at_ms: 1234,
                spending_txid: None,
                backend: "mock".into(),
                witness_bytes: 1,
                prove_duration_ms: 2,
                proof_bytes: None,
            }],
        };
        roundtrip(&response);
    }

    #[test]
    fn broadcast_params_roundtrip() {
        let params = BroadcastParams {
            draft_id: "draft1".to_string(),
        };
        roundtrip(&params);
    }

    #[test]
    fn broadcast_response_roundtrip() {
        let response = BroadcastResponse {
            draft_id: "draft1".to_string(),
            accepted: true,
            locks: vec![],
        };
        roundtrip(&response);
    }

    #[test]
    fn policy_preview_response_roundtrip() {
        let response = PolicyPreviewResponse {
            min_confirmations: 6,
            dust_limit: 546,
            max_change_outputs: 2,
            spend_limit_daily: Some(1_000),
            pending_lock_timeout: 120,
            tier_hooks: PolicyTierHooks {
                enabled: true,
                hook: Some("utxo_tier".to_string()),
            },
        };
        roundtrip(&response);
    }

    #[test]
    fn sync_status_params_roundtrip() {
        let params = SyncStatusParams;
        roundtrip(&params);
    }

    #[test]
    fn sync_status_response_roundtrip() {
        let response = SyncStatusResponse {
            syncing: true,
            mode: Some(SyncModeDto::Rescan { from_height: 5 }),
            latest_height: Some(12),
            scanned_scripthashes: Some(4),
            pending_ranges: vec![(10, 12)],
            checkpoints: Some(SyncCheckpointDto {
                resume_height: Some(12),
                birthday_height: Some(0),
                last_scan_ts: Some(1),
                last_full_rescan_ts: Some(2),
                last_compact_scan_ts: Some(3),
                last_targeted_rescan_ts: Some(4),
            }),
            last_rescan_timestamp: Some(4),
            last_error: Some("stalled".to_string()),
        };
        roundtrip(&response);
    }

    #[test]
    fn rescan_params_roundtrip() {
        let params = RescanParams {
            from_height: Some(25),
            lookback_blocks: None,
        };
        roundtrip(&params);
    }

    #[test]
    fn rescan_response_roundtrip() {
        let response = RescanResponse {
            scheduled: true,
            from_height: 42,
        };
        roundtrip(&response);
    }

    #[test]
    fn policy_snapshot_roundtrip() {
        let response = GetPolicyResponse {
            snapshot: Some(PolicySnapshotDto {
                revision: 2,
                updated_at: 1_700_000_000,
                statements: vec!["allow foo".into(), "deny bar".into()],
            }),
        };
        roundtrip(&response);
        let set = SetPolicyResponse {
            snapshot: PolicySnapshotDto {
                revision: 3,
                updated_at: 1_800_000_000,
                statements: vec![],
            },
        };
        roundtrip(&set);
    }

    #[test]
    fn estimate_fee_roundtrip() {
        let params = EstimateFeeParams {
            confirmation_target: 3,
        };
        roundtrip(&params);
        let response = EstimateFeeResponse {
            confirmation_target: 3,
            fee_rate: 42,
        };
        roundtrip(&response);
    }

    #[test]
    fn pending_locks_roundtrip() {
        let list = ListPendingLocksResponse {
            locks: vec![PendingLockDto {
                utxo_txid: "bb".into(),
                utxo_index: 1,
                locked_at_ms: 2,
                spending_txid: Some("cc".into()),
                backend: "mock".into(),
                witness_bytes: 42,
                prove_duration_ms: 7,
                proof_bytes: Some(128),
            }],
        };
        roundtrip(&list);
        let release = ReleasePendingLocksResponse {
            released: list.locks.clone(),
        };
        roundtrip(&release);
        let params = ReleasePendingLocksParams;
        roundtrip(&params);
    }

    #[test]
    fn mempool_info_roundtrip() {
        let response = MempoolInfoResponse {
            tx_count: 42,
            vsize_limit: 1_000_000,
            vsize_in_use: 250_000,
            min_fee_rate: Some(1),
            max_fee_rate: Some(10),
        };
        roundtrip(&response);
    }

    #[test]
    fn recent_blocks_roundtrip() {
        let params = RecentBlocksParams { limit: Some(8) };
        roundtrip(&params);
        let response = RecentBlocksResponse {
            blocks: vec![BlockFeeSummaryDto {
                height: 100,
                median_fee_rate: Some(12),
                max_fee_rate: Some(24),
            }],
        };
        roundtrip(&response);
    }

    #[test]
    fn telemetry_counters_roundtrip() {
        let response = TelemetryCountersResponse {
            enabled: true,
            counters: vec![TelemetryCounterDto {
                name: "proofs".into(),
                value: 5,
            }],
        };
        roundtrip(&response);
    }
}
