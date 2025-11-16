use serde::de::IntoDeserializer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
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

/// Zero Sync lifecycle proof summary exchanged via RPC.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleProof {
    /// Backend responsible for generating the proof.
    pub backend: String,
    /// Operation the proof corresponds to.
    pub operation: String,
    /// Digest of the witness payload used by the prover.
    pub witness_digest: String,
    /// Digest of the proof payload emitted by the prover.
    pub proof_commitment: String,
    /// Raw proof bytes as emitted by the prover backend.
    pub raw_proof: Vec<u8>,
}

/// Operations supported by the Zero Sync identity prover.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ZsiOperation {
    /// Issue a new identity declaration.
    Issue,
    /// Rotate the identity to a new commitment.
    Rotate,
    /// Revoke an existing identity.
    Revoke,
    /// Audit an existing identity record.
    Audit,
}

/// Approval emitted by consensus while onboarding an identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ConsensusApproval {
    /// Validator that emitted the approval.
    pub validator: String,
    /// Validator signature attesting to the approval.
    pub signature: String,
    /// Timestamp associated with the approval.
    pub timestamp: u64,
}

/// Canonical ZSI registry record summarising a wallet identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiRecord {
    /// Unique identifier of the identity.
    pub identity: String,
    /// Genesis identifier associated with the record.
    pub genesis_id: String,
    /// Digest of the attestation payload.
    pub attestation_digest: String,
    /// Consensus approvals collected for the identity.
    pub approvals: Vec<ConsensusApproval>,
}

/// Public inputs required when verifying lifecycle artifacts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityPublicInputs {
    /// Wallet address commitment used by the lifecycle circuit.
    pub wallet_address: [u8; 32],
    /// VRF tag associated with the identity operation.
    pub vrf_tag: Vec<u8>,
    /// Identity root observed when constructing the proof.
    pub identity_root: [u8; 32],
    /// State root observed when constructing the proof.
    pub state_root: [u8; 32],
}

/// Control tier-aware runtime integrations for wallet policies.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PolicyTierHooks {
    /// Enable tier integration checks for spending policies.
    pub enabled: bool,
    /// Optional named hook surfaced to clients for bespoke integrations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
}

impl Default for PolicyTierHooks {
    fn default() -> Self {
        Self {
            enabled: false,
            hook: None,
        }
    }
}

/// Stable Phase 2 wallet RPC error codes.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum WalletRpcErrorCode {
    InvalidRequest,
    MethodNotFound,
    InvalidParams,
    InternalError,
    WalletPolicyViolation,
    FeeTooLow,
    FeeTooHigh,
    PendingLockConflict,
    ProverTimeout,
    ProverFailed,
    ProverCancelled,
    WitnessTooLarge,
    SyncUnavailable,
    SyncError,
    RescanOutOfRange,
    RescanInProgress,
    DraftNotFound,
    DraftUnsigned,
    NodeUnavailable,
    NodeRejected,
    NodePolicy,
    NodeStatsUnavailable,
    EngineFailure,
    SerializationFailure,
    StatePoisoned,
    RbacForbidden,
    WatchOnlyNotEnabled,
    Custom(String),
}

impl WalletRpcErrorCode {
    /// Returns the canonical string representation for the error code.
    pub fn as_str(&self) -> std::borrow::Cow<'_, str> {
        match self {
            WalletRpcErrorCode::InvalidRequest => std::borrow::Cow::Borrowed("INVALID_REQUEST"),
            WalletRpcErrorCode::MethodNotFound => std::borrow::Cow::Borrowed("METHOD_NOT_FOUND"),
            WalletRpcErrorCode::InvalidParams => std::borrow::Cow::Borrowed("INVALID_PARAMS"),
            WalletRpcErrorCode::InternalError => std::borrow::Cow::Borrowed("INTERNAL_ERROR"),
            WalletRpcErrorCode::WalletPolicyViolation => {
                std::borrow::Cow::Borrowed("WALLET_POLICY_VIOLATION")
            }
            WalletRpcErrorCode::FeeTooLow => std::borrow::Cow::Borrowed("FEE_TOO_LOW"),
            WalletRpcErrorCode::FeeTooHigh => std::borrow::Cow::Borrowed("FEE_TOO_HIGH"),
            WalletRpcErrorCode::PendingLockConflict => {
                std::borrow::Cow::Borrowed("PENDING_LOCK_CONFLICT")
            }
            WalletRpcErrorCode::ProverTimeout => std::borrow::Cow::Borrowed("PROVER_TIMEOUT"),
            WalletRpcErrorCode::ProverFailed => std::borrow::Cow::Borrowed("PROVER_FAILED"),
            WalletRpcErrorCode::ProverCancelled => std::borrow::Cow::Borrowed("PROVER_CANCELLED"),
            WalletRpcErrorCode::WitnessTooLarge => std::borrow::Cow::Borrowed("WITNESS_TOO_LARGE"),
            WalletRpcErrorCode::SyncUnavailable => std::borrow::Cow::Borrowed("SYNC_UNAVAILABLE"),
            WalletRpcErrorCode::SyncError => std::borrow::Cow::Borrowed("SYNC_ERROR"),
            WalletRpcErrorCode::RescanOutOfRange => {
                std::borrow::Cow::Borrowed("RESCAN_OUT_OF_RANGE")
            }
            WalletRpcErrorCode::RescanInProgress => {
                std::borrow::Cow::Borrowed("RESCAN_IN_PROGRESS")
            }
            WalletRpcErrorCode::DraftNotFound => std::borrow::Cow::Borrowed("DRAFT_NOT_FOUND"),
            WalletRpcErrorCode::DraftUnsigned => std::borrow::Cow::Borrowed("DRAFT_UNSIGNED"),
            WalletRpcErrorCode::NodeUnavailable => std::borrow::Cow::Borrowed("NODE_UNAVAILABLE"),
            WalletRpcErrorCode::NodeRejected => std::borrow::Cow::Borrowed("NODE_REJECTED"),
            WalletRpcErrorCode::NodePolicy => std::borrow::Cow::Borrowed("NODE_POLICY"),
            WalletRpcErrorCode::NodeStatsUnavailable => {
                std::borrow::Cow::Borrowed("NODE_STATS_UNAVAILABLE")
            }
            WalletRpcErrorCode::EngineFailure => std::borrow::Cow::Borrowed("ENGINE_FAILURE"),
            WalletRpcErrorCode::SerializationFailure => {
                std::borrow::Cow::Borrowed("SERIALIZATION_FAILURE")
            }
            WalletRpcErrorCode::StatePoisoned => std::borrow::Cow::Borrowed("STATE_POISONED"),
            WalletRpcErrorCode::RbacForbidden => std::borrow::Cow::Borrowed("RBAC_FORBIDDEN"),
            WalletRpcErrorCode::WatchOnlyNotEnabled => {
                std::borrow::Cow::Borrowed("WATCH_ONLY_NOT_ENABLED")
            }
            WalletRpcErrorCode::Custom(other) => std::borrow::Cow::Borrowed(other.as_str()),
        }
    }
}

impl std::fmt::Display for WalletRpcErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for WalletRpcErrorCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.as_str())
    }
}

impl<'de> Deserialize<'de> for WalletRpcErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "INVALID_REQUEST" => WalletRpcErrorCode::InvalidRequest,
            "METHOD_NOT_FOUND" => WalletRpcErrorCode::MethodNotFound,
            "INVALID_PARAMS" => WalletRpcErrorCode::InvalidParams,
            "INTERNAL_ERROR" => WalletRpcErrorCode::InternalError,
            "WALLET_POLICY_VIOLATION" => WalletRpcErrorCode::WalletPolicyViolation,
            "FEE_TOO_LOW" => WalletRpcErrorCode::FeeTooLow,
            "FEE_TOO_HIGH" => WalletRpcErrorCode::FeeTooHigh,
            "PENDING_LOCK_CONFLICT" => WalletRpcErrorCode::PendingLockConflict,
            "PROVER_TIMEOUT" => WalletRpcErrorCode::ProverTimeout,
            "PROVER_FAILED" => WalletRpcErrorCode::ProverFailed,
            "PROVER_CANCELLED" => WalletRpcErrorCode::ProverCancelled,
            "WITNESS_TOO_LARGE" => WalletRpcErrorCode::WitnessTooLarge,
            "SYNC_UNAVAILABLE" => WalletRpcErrorCode::SyncUnavailable,
            "SYNC_ERROR" => WalletRpcErrorCode::SyncError,
            "RESCAN_OUT_OF_RANGE" => WalletRpcErrorCode::RescanOutOfRange,
            "RESCAN_IN_PROGRESS" => WalletRpcErrorCode::RescanInProgress,
            "DRAFT_NOT_FOUND" => WalletRpcErrorCode::DraftNotFound,
            "DRAFT_UNSIGNED" => WalletRpcErrorCode::DraftUnsigned,
            "NODE_UNAVAILABLE" => WalletRpcErrorCode::NodeUnavailable,
            "NODE_REJECTED" => WalletRpcErrorCode::NodeRejected,
            "NODE_POLICY" => WalletRpcErrorCode::NodePolicy,
            "NODE_STATS_UNAVAILABLE" => WalletRpcErrorCode::NodeStatsUnavailable,
            "ENGINE_FAILURE" => WalletRpcErrorCode::EngineFailure,
            "SERIALIZATION_FAILURE" => WalletRpcErrorCode::SerializationFailure,
            "STATE_POISONED" => WalletRpcErrorCode::StatePoisoned,
            "RBAC_FORBIDDEN" => WalletRpcErrorCode::RbacForbidden,
            "WATCH_ONLY_NOT_ENABLED" => WalletRpcErrorCode::WatchOnlyNotEnabled,
            other => WalletRpcErrorCode::Custom(other.to_string()),
        })
    }
}

impl From<&str> for WalletRpcErrorCode {
    fn from(value: &str) -> Self {
        WalletRpcErrorCode::deserialize(value.into_deserializer())
            .unwrap_or_else(|_| WalletRpcErrorCode::Custom(value.to_string()))
    }
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
    use serde_json::json;

    // The RPC types are called across process boundaries, so we cover several
    // variants (requests, responses, and error payloads) to lock in the expected JSON shape.

    fn roundtrip<T>(value: &T)
    where
        T: Serialize + DeserializeOwned + PartialEq + Debug,
    {
        let json = serde_json::to_value(value).expect("serialize");
        let restored: T = serde_json::from_value(json).expect("deserialize");
        assert_eq!(&restored, value);
    }

    #[test]
    fn jsonrpc_structs_roundtrip() {
        let request = JsonRpcRequest {
            jsonrpc: Some(JSONRPC_VERSION.to_string()),
            id: Some(Value::from(1)),
            method: "get_balance".to_string(),
            params: Some(Value::from(serde_json::json!({"change": false}))),
        };
        roundtrip(&request);

        let response = JsonRpcResponse {
            jsonrpc: JSONRPC_VERSION,
            id: Some(Value::from(1)),
            result: Some(Value::from(serde_json::json!({"ok": true}))),
            error: None,
        };
        roundtrip(&response);

        let error = JsonRpcError {
            code: -32000,
            message: "boom".into(),
            data: None,
        };
        roundtrip(&error);
    }

    #[test]
    fn transaction_related_roundtrip() {
        let response = CreateTxResponse {
            draft_id: "draft1".to_string(),
            fee_rate: 2,
            fee: 4,
            fee_source: Some(FeeEstimateSourceDto::Override),
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
            locks: Vec::new(),
            #[cfg(feature = "wallet_multisig_hooks")]
            multisig: None,
        };
        roundtrip(&response);

        let policy = PolicyPreviewResponse {
            min_confirmations: 1,
            dust_limit: 100,
            max_change_outputs: 2,
            spend_limit_daily: Some(10),
            pending_lock_timeout: 30,
            tier_hooks: PolicyTierHooks {
                enabled: true,
                hook: Some("hook".into()),
            },
        };
        roundtrip(&policy);
    }

    #[test]
    fn telemetry_and_sync_roundtrip() {
        let telemetry = TelemetryCountersResponse {
            enabled: true,
            counters: vec![TelemetryCounterDto {
                name: "backup.export.ok".to_string(),
                value: 3,
            }],
        };
        roundtrip(&telemetry);

        let sync = SyncStatusResponse {
            syncing: false,
            mode: Some(SyncModeDto::Full { start_height: 0 }),
            latest_height: Some(10),
            scanned_scripthashes: Some(5),
            pending_ranges: vec![(0, 1)],
            checkpoints: Some(SyncCheckpointDto {
                resume_height: Some(1),
                birthday_height: None,
                last_scan_ts: Some(10),
                last_full_rescan_ts: None,
                last_compact_scan_ts: None,
                last_targeted_rescan_ts: None,
            }),
            last_rescan_timestamp: Some(20),
            last_error: None,
            node_issue: Some("node".into()),
            hints: vec!["hint".into()],
        };
        roundtrip(&sync);
    }

    #[test]
    fn zsi_and_error_roundtrip() {
        let params = ZsiProofParams {
            operation: ZsiOperation::Issue,
            record: ZsiRecord {
                identity: "id".into(),
                genesis_id: "gen".into(),
                attestation_digest: "attn".into(),
                approvals: vec![ConsensusApproval {
                    validator: "val".into(),
                    signature: "sig".into(),
                    timestamp: 1,
                }],
            },
        };
        roundtrip(&params);

        let binding = ZsiBindingDto {
            operation: ZsiOperation::Audit,
            record: params.record.clone(),
            witness: vec![1, 2, 3],
            inputs: IdentityPublicInputs {
                wallet_address: [0u8; 32],
                vrf_tag: vec![4, 5, 6],
                identity_root: [1u8; 32],
                state_root: [2u8; 32],
            },
        };
        roundtrip(&binding);

        let code = WalletRpcErrorCode::WatchOnlyNotEnabled;
        let encoded = serde_json::to_string(&code).expect("encode");
        let decoded: WalletRpcErrorCode = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, code);
    }

    #[test]
    fn jsonrpc_error_payload_shape() {
        let response = JsonRpcResponse {
            jsonrpc: JSONRPC_VERSION,
            id: Some(Value::from("req-7")),
            result: None,
            error: Some(JsonRpcError {
                code: -32010,
                message: "policy violation".into(),
                data: Some(json!({
                    "code": WalletRpcErrorCode::WalletPolicyViolation.as_str(),
                    "details": {"draft_id": "draft-7"}
                })),
            }),
        };
        let serialized = serde_json::to_value(&response).expect("serialize response");
        assert_eq!(
            serialized,
            json!({
                "jsonrpc": "2.0",
                "id": "req-7",
                "error": {
                    "code": -32010,
                    "message": "policy violation",
                    "data": {
                        "code": "WALLET_POLICY_VIOLATION",
                        "details": {"draft_id": "draft-7"}
                    }
                }
            })
        );
    }

    #[test]
    fn wallet_rpc_error_code_serialization_covers_variants() {
        let known = WalletRpcErrorCode::PendingLockConflict;
        assert_eq!(
            serde_json::to_string(&known).expect("serialize known"),
            "\"PENDING_LOCK_CONFLICT\""
        );

        let custom = WalletRpcErrorCode::Custom("ANALYTICS_FAILURE".into());
        assert_eq!(
            serde_json::to_string(&custom).expect("serialize custom"),
            "\"ANALYTICS_FAILURE\""
        );
        assert_eq!(WalletRpcErrorCode::from("ANALYTICS_FAILURE"), custom);
    }
}
