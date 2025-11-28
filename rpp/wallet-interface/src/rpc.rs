#![allow(missing_docs)]

use serde::de::{value::Error as DeError, IntoDeserializer};
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
    pub jsonrpc: String,
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
#[serde(rename_all = "snake_case")]
pub enum AddressStatusDto {
    Unused,
    Used,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressMetadataDto {
    pub address: String,
    pub change: bool,
    pub index: u32,
    pub status: AddressStatusDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_synced_height: Option<u64>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AddressBranchDto {
    Receive,
    Change,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAddressDto {
    pub address: String,
    pub branch: AddressBranchDto,
    pub index: u32,
    pub status: AddressStatusDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListAddressesParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub change: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListAddressesResponse {
    pub addresses: Vec<AddressMetadataDto>,
    pub page: u32,
    pub page_size: u32,
    pub total: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetAddressLabelParams {
    pub address: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SetAddressLabelResponse {
    pub address: AddressMetadataDto,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListBranchAddressesParams {
    pub branch: AddressBranchDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_size: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListBranchAddressesResponse {
    pub addresses: Vec<WalletAddressDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateAddressMetadataParams {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateAddressMetadataResponse {
    pub address: WalletAddressDto,
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
/// Metadata describing a pending UTXO lock.
pub struct PendingLockDto {
    /// Transaction id of the locked UTXO.
    pub utxo_txid: String,
    /// Output index of the locked UTXO.
    pub utxo_index: u32,
    /// Timestamp (ms) when the lock was acquired.
    pub locked_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Transaction id currently spending the lock, if any.
    pub spending_txid: Option<String>,
    #[serde(default)]
    /// Backend responsible for the lock.
    pub backend: String,
    #[serde(default)]
    /// Witness bytes generated so far.
    pub witness_bytes: u64,
    #[serde(default)]
    /// Proof generation duration in milliseconds.
    pub prove_duration_ms: u64,
    #[serde(default)]
    /// Whether the wallet required a proof when the lock was recorded.
    pub proof_required: bool,
    #[serde(default)]
    /// Whether a proof was present when the lock was recorded.
    pub proof_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    /// Size of the generated proof, if available.
    pub proof_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    /// Hash of the generated proof, if available.
    pub proof_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Metadata captured from the prover backend during signing.
pub struct ProverMetadataDto {
    /// Backend that produced the witness and proof.
    pub backend: String,
    /// Total witness bytes processed during signing.
    pub witness_bytes: u64,
    /// Duration of the proving job in milliseconds.
    pub prove_duration_ms: u64,
    #[serde(default)]
    /// Whether the wallet required a proof for the draft.
    pub proof_required: bool,
    #[serde(default)]
    /// Whether the prover produced a proof for the draft.
    pub proof_present: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Size of the generated proof in bytes, when available.
    pub proof_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Hex-encoded hash of the generated proof, when available.
    pub proof_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Signed transaction payload paired with the prover metadata.
pub struct SignedTxProverBundleDto {
    /// Hex-encoded transaction submission bytes.
    pub tx_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional hex-encoded proof bytes.
    pub proof_hex: Option<String>,
    /// Metadata reported by the prover backend.
    pub metadata: ProverMetadataDto,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Parameters accepted by the `prover.status` RPC method.
pub struct ProverStatusParams {
    /// Transaction identifier being inspected.
    pub txid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Result returned by `prover.status`.
pub struct ProverStatusResponse {
    /// Transaction identifier being inspected.
    pub txid: String,
    /// Current prover status for the transaction.
    pub status: ProverStatusDto,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
/// States tracked by the prover status endpoint.
pub enum ProverStatusDto {
    /// Prover job is pending or inputs remain locked.
    Pending,
    /// Prover metadata has been recorded for the transaction.
    Recorded,
    /// No prover state is available for the transaction.
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Parameters accepted by the `prover.meta` RPC method.
pub struct ProverMetaParams {
    /// Transaction identifier whose prover metadata is requested.
    pub txid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Result returned by `prover.meta` when metadata is available.
pub struct ProverMetaDto {
    /// Transaction identifier the metadata is associated with.
    pub txid: String,
    /// Backend that produced the witness and proof.
    pub backend: String,
    /// Duration of the prover job in milliseconds.
    pub prove_duration_ms: u64,
    /// Total witness bytes processed during proving.
    pub witness_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    /// Size of the generated proof in bytes, when present.
    pub proof_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    /// Hex-encoded hash of the generated proof, when available.
    pub proof_hash: Option<String>,
    /// Timestamp (ms) when the prover job began.
    pub started_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    /// Timestamp (ms) when the prover job finished, when known.
    pub finished_at_ms: Option<u64>,
    /// Backend-provided result description.
    pub result: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Wrapper returned by `prover.meta`.
pub struct ProverMetaResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    /// Recorded metadata if available for the transaction.
    pub metadata: Option<ProverMetaDto>,
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
/// Metadata returned by the `draft.sign` RPC method.
pub struct SignTxResponse {
    /// Identifier of the signed draft.
    pub draft_id: String,
    /// Signed transaction bundle returned by the prover.
    pub signed: SignedTxProverBundleDto,
    /// Locks acquired while signing.
    pub locks: Vec<PendingLockDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Multisig scope describing threshold/participant counts.
pub struct MultisigScopeDto {
    /// Number of required signers.
    pub threshold: u8,
    /// Total participants for the scope.
    pub participants: u8,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Remote cosigner descriptor.
pub struct CosignerDto {
    /// Fingerprint identifying the cosigner.
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional RPC endpoint for the cosigner.
    pub endpoint: Option<String>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Multisig metadata returned alongside drafts.
pub struct MultisigDraftMetadataDto {
    /// Scope defining threshold/participants.
    pub scope: MultisigScopeDto,
    /// Cosigners included in the draft.
    pub cosigners: Vec<CosignerDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Parameters accepted by the `draft.broadcast` RPC method.
pub struct BroadcastParams {
    /// Identifier of the draft to broadcast.
    pub draft_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Result of broadcasting a signed draft.
pub struct BroadcastResponse {
    /// Identifier of the broadcast draft.
    pub draft_id: String,
    /// Whether the transaction was accepted by the node.
    pub accepted: bool,
    #[serde(default)]
    /// Whether the wallet required a proof before broadcasting.
    pub proof_required: bool,
    #[serde(default)]
    /// Whether a proof was present when broadcasting.
    pub proof_present: bool,
    /// Locks held while broadcasting.
    pub locks: Vec<PendingLockDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Parameters accepted by the `draft.broadcast_raw` RPC method.
pub struct BroadcastRawParams {
    /// Raw transaction hex to broadcast.
    pub tx_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Result returned by `draft.broadcast_raw`.
pub struct BroadcastRawResponse {
    /// Whether the node accepted the transaction.
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
/// List of known cosigners returned by `multisig.get_cosigners`.
pub struct GetCosignersResponse {
    /// Registered cosigners.
    pub cosigners: Vec<CosignerDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Payload accepted by `multisig.set_cosigners`.
pub struct SetCosignersParams {
    /// Updated list of cosigners.
    pub cosigners: Vec<CosignerDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Response returned by `multisig.set_cosigners`.
pub struct SetCosignersResponse {
    /// Canonical cosigner state after applying the update.
    pub cosigners: Vec<CosignerDto>,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Parameters used by `multisig.export`.
pub struct MultisigExportParams {
    /// Identifier of the draft to export.
    pub draft_id: String,
}

#[cfg(feature = "wallet_multisig_hooks")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Result returned by `multisig.export`.
pub struct MultisigExportResponse {
    /// Identifier of the exported draft.
    pub draft_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional metadata included with the export.
    pub metadata: Option<MultisigDraftMetadataDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Policy properties previewed by the runtime.
pub struct PolicyPreviewResponse {
    /// Minimum confirmations required for spends.
    pub min_confirmations: u32,
    /// Dust threshold enforced by the policy.
    pub dust_limit: u128,
    /// Upper bound on change outputs per transaction.
    pub max_change_outputs: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional daily send limit enforced by hooks.
    pub spend_limit_daily: Option<u128>,
    /// Timeout (in seconds) before pending locks expire.
    pub pending_lock_timeout: u64,
    /// Hook configuration applied to the policy tiers.
    pub tier_hooks: PolicyTierHooks,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
/// Snapshot returned by `policy.get`.
pub struct GetPolicyResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Latest policy snapshot if one is configured.
    pub snapshot: Option<PolicySnapshotDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Parameters accepted by `policy.set`.
pub struct SetPolicyParams {
    #[serde(default)]
    /// Policy statements expressed in miniscript.
    pub statements: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Response emitted by `policy.set`.
pub struct SetPolicyResponse {
    /// Snapshot captured after persisting the policy.
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
#[serde(rename_all = "snake_case")]
pub enum LifecycleStateDto {
    Running,
    Stopped,
    AlreadyRunning,
    PortInUse,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleStatusResponse {
    pub status: LifecycleStateDto,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_in_use: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log_tail: Vec<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub checkpoint_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub checkpoint_epoch: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Parameters accepted by the `backup.export` RPC method.
pub struct BackupExportParams {
    /// Passphrase that encrypts the exported archive.
    pub passphrase: String,
    /// Confirmation of the `passphrase` field to prevent typos.
    pub confirmation: String,
    /// Whether to export metadata without the encrypted keystore content.
    #[serde(default)]
    pub metadata_only: bool,
    /// Include per-file checksums in the resulting archive manifest.
    #[serde(default = "default_include_checksums")]
    pub include_checksums: bool,
}

fn default_include_checksums() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Location and metadata returned after exporting a backup.
pub struct BackupExportResponse {
    /// Absolute path to the exported archive on disk.
    pub path: String,
    /// Metadata describing the exported wallet state.
    pub metadata: BackupMetadataDto,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Modes supported when validating a backup archive.
pub enum BackupValidationModeDto {
    /// Parse the archive without decrypting or verifying signatures.
    DryRun,
    /// Fully decrypt and verify checksums for the archive contents.
    Full,
}

impl Default for BackupValidationModeDto {
    fn default() -> Self {
        BackupValidationModeDto::Full
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Request payload for the `backup.validate` RPC method.
pub struct BackupValidateParams {
    /// Friendly name assigned to the backup.
    pub name: String,
    /// Passphrase used to decrypt the backup.
    pub passphrase: String,
    /// Validation mode controlling how deeply the backup is inspected.
    #[serde(default)]
    pub mode: BackupValidationModeDto,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Result of validating a backup archive.
pub struct BackupValidateResponse {
    /// Metadata describing the parsed backup contents.
    pub metadata: BackupMetadataDto,
    /// Whether a keystore blob was present in the archive.
    pub has_keystore: bool,
    /// Number of policy entries referenced by the backup.
    pub policy_count: usize,
    /// Number of metadata entries bundled with the backup.
    pub meta_entries: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Input accepted by the `backup.import` RPC method.
pub struct BackupImportParams {
    /// Friendly label for the backup being imported.
    pub name: String,
    /// Passphrase needed to decrypt the archive contents.
    pub passphrase: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Summary describing the outcome of importing a backup.
pub struct BackupImportResponse {
    /// Metadata associated with the imported backup.
    pub metadata: BackupMetadataDto,
    /// Whether the encrypted keystore file was restored.
    pub restored_keystore: bool,
    /// Whether the wallet policy definitions were restored.
    pub restored_policy: bool,
    /// Chain height clients should rescan from to refresh state.
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
    ProverBackendDisabled,
    ProverTimeout,
    ProverBusy,
    ProverInternal,
    ProverProofMissing,
    ProverFailed,
    ProverCancelled,
    WitnessTooLarge,
    SyncUnavailable,
    SyncError,
    IndexerUnavailable,
    RescanOutOfRange,
    RescanInProgress,
    RescanAborted,
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
            WalletRpcErrorCode::ProverBackendDisabled => {
                std::borrow::Cow::Borrowed("PROVER_BACKEND_DISABLED")
            }
            WalletRpcErrorCode::ProverTimeout => std::borrow::Cow::Borrowed("PROVER_TIMEOUT"),
            WalletRpcErrorCode::ProverBusy => std::borrow::Cow::Borrowed("PROVER_BUSY"),
            WalletRpcErrorCode::ProverInternal => std::borrow::Cow::Borrowed("PROVER_INTERNAL"),
            WalletRpcErrorCode::ProverProofMissing => {
                std::borrow::Cow::Borrowed("PROVER_PROOF_MISSING")
            }
            WalletRpcErrorCode::ProverFailed => std::borrow::Cow::Borrowed("PROVER_FAILED"),
            WalletRpcErrorCode::ProverCancelled => std::borrow::Cow::Borrowed("PROVER_CANCELLED"),
            WalletRpcErrorCode::WitnessTooLarge => std::borrow::Cow::Borrowed("WITNESS_TOO_LARGE"),
            WalletRpcErrorCode::SyncUnavailable => std::borrow::Cow::Borrowed("SYNC_UNAVAILABLE"),
            WalletRpcErrorCode::SyncError => std::borrow::Cow::Borrowed("SYNC_ERROR"),
            WalletRpcErrorCode::IndexerUnavailable => {
                std::borrow::Cow::Borrowed("INDEXER_UNAVAILABLE")
            }
            WalletRpcErrorCode::RescanOutOfRange => {
                std::borrow::Cow::Borrowed("RESCAN_OUT_OF_RANGE")
            }
            WalletRpcErrorCode::RescanInProgress => {
                std::borrow::Cow::Borrowed("RESCAN_IN_PROGRESS")
            }
            WalletRpcErrorCode::RescanAborted => std::borrow::Cow::Borrowed("RESCAN_ABORTED"),
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
            "PROVER_BACKEND_DISABLED" => WalletRpcErrorCode::ProverBackendDisabled,
            "PROVER_TIMEOUT" => WalletRpcErrorCode::ProverTimeout,
            "PROVER_BUSY" => WalletRpcErrorCode::ProverBusy,
            "PROVER_INTERNAL" => WalletRpcErrorCode::ProverInternal,
            "PROVER_PROOF_MISSING" => WalletRpcErrorCode::ProverProofMissing,
            "PROVER_FAILED" => WalletRpcErrorCode::ProverFailed,
            "PROVER_CANCELLED" => WalletRpcErrorCode::ProverCancelled,
            "WITNESS_TOO_LARGE" => WalletRpcErrorCode::WitnessTooLarge,
            "SYNC_UNAVAILABLE" => WalletRpcErrorCode::SyncUnavailable,
            "SYNC_ERROR" => WalletRpcErrorCode::SyncError,
            "INDEXER_UNAVAILABLE" => WalletRpcErrorCode::IndexerUnavailable,
            "RESCAN_OUT_OF_RANGE" => WalletRpcErrorCode::RescanOutOfRange,
            "RESCAN_IN_PROGRESS" => WalletRpcErrorCode::RescanInProgress,
            "RESCAN_ABORTED" => WalletRpcErrorCode::RescanAborted,
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
            .unwrap_or_else(|_: DeError| WalletRpcErrorCode::Custom(value.to_string()))
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
/// Snapshot describing the current sync state.
pub struct SyncStatusResponse {
    /// Whether a sync operation is currently running.
    pub syncing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Sync mode currently in effect.
    pub mode: Option<SyncModeDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Latest height observed by the sync worker.
    pub latest_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Current height reached by the ongoing scan.
    pub current_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Target height for the current scan.
    pub target_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Calculated lag between the target and current height in blocks.
    pub lag_blocks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Number of script hashes processed so far.
    pub scanned_scripthashes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Number of transactions discovered during the scan.
    pub discovered_transactions: Option<usize>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Pending height ranges waiting to be scanned.
    pub pending_ranges: Vec<(u64, u64)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Latest checkpoint details if available.
    pub checkpoints: Option<SyncCheckpointDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Timestamp of the most recent rescan.
    pub last_rescan_timestamp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Description of the last sync error.
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Node-specific issue currently blocking sync.
    pub node_issue: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// Additional hints for operators.
    pub hints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Snapshot mismatch diagnostics when sync validation fails.
    pub mismatch: Option<SyncMismatchDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncMismatchDto {
    pub height: u64,
    pub expected_balance: BalanceResponse,
    pub observed_balance: BalanceResponse,
    pub expected_nonce: u64,
    pub observed_nonce: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// Synchronization strategy requested by the wallet.
pub enum SyncModeDto {
    /// Perform a full sync from the provided start height.
    Full { start_height: u64 },
    /// Resume syncing from the provided height.
    Resume { from_height: u64 },
    /// Trigger a targeted rescan starting at `from_height`.
    Rescan { from_height: u64 },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
/// Latest checkpoint information about a running sync.
pub struct SyncCheckpointDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Block height clients should resume from.
    pub resume_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Wallet birthday height if known.
    pub birthday_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Timestamp of the last incremental scan.
    pub last_scan_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Timestamp of the last full rescan.
    pub last_full_rescan_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Timestamp of the last compact block scan.
    pub last_compact_scan_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Timestamp of the last targeted rescan.
    pub last_targeted_rescan_ts: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Lag snapshot for a tracked address.
pub struct SyncLagAddressDto {
    pub address: String,
    pub change: bool,
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_synced_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lag_blocks: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
/// Lag summary for the wallet and its addresses.
pub struct SyncLagResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_lag_blocks: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<SyncLagAddressDto>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Parameters accepted by the `sync.rescan` RPC method.
pub struct RescanParams {
    #[serde(default)]
    /// Optional height to begin the rescan from.
    pub from_height: Option<u64>,
    #[serde(default)]
    /// Optional number of blocks to scan backwards from the head.
    pub lookback_blocks: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Status returned by `sync.rescan`.
pub struct RescanResponse {
    /// Whether a rescan was scheduled.
    pub scheduled: bool,
    /// Height the rescan will start from.
    pub from_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Status returned by `rescan.status`.
pub struct RescanStatusResponse {
    /// Pending rescan start height, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduled_from: Option<u64>,
    /// Whether a rescan is actively running.
    pub active: bool,
    /// Current scan height while active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_height: Option<u64>,
    /// Target scan height while active.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_height: Option<u64>,
    /// Latest indexed height reported by the backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_height: Option<u64>,
    /// Last error reported by the scanner, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
/// Response returned by `rescan.abort`.
pub struct RescanAbortResponse {
    /// True if an active or pending rescan was cancelled.
    pub aborted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use serde_json::json;
    use std::fmt::Debug;

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
            jsonrpc: JSONRPC_VERSION.to_string(),
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
            current_height: Some(3),
            target_height: Some(10),
            lag_blocks: Some(7),
            scanned_scripthashes: Some(5),
            discovered_transactions: Some(1),
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

        let lag = SyncLagResponse {
            target_height: Some(120),
            account_lag_blocks: Some(12),
            addresses: vec![SyncLagAddressDto {
                address: "wallet1".into(),
                change: false,
                index: 0,
                last_synced_height: Some(100),
                lag_blocks: Some(20),
            }],
        };
        roundtrip(&lag);
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
            jsonrpc: JSONRPC_VERSION.to_string(),
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
    fn lifecycle_status_response_roundtrip() {
        let response = LifecycleStatusResponse {
            status: LifecycleStateDto::PortInUse,
            pid: Some(42),
            port_in_use: Some("127.0.0.1:18444".into()),
            error: Some("port occupied".into()),
            log_tail: vec!["line1".into(), "line2".into()],
        };

        roundtrip(&response);
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
