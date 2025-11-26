use crate::engine::{FeeCongestionLevel, FeeEstimateSource};
#[cfg(feature = "wallet_multisig_hooks")]
use crate::multisig::{Cosigner, MultisigDraftMetadata, MultisigScope};
use crate::wallet::{AddressEntry, AddressStatus};
use serde_json::Value;

pub use crate::interface_rpc::*;

impl JsonRpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<Value>, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }
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

impl From<AddressStatus> for AddressStatusDto {
    fn from(status: AddressStatus) -> Self {
        match status {
            AddressStatus::Unused => AddressStatusDto::Unused,
            AddressStatus::Used => AddressStatusDto::Used,
        }
    }
}

impl From<bool> for AddressBranchDto {
    fn from(change: bool) -> Self {
        if change {
            AddressBranchDto::Change
        } else {
            AddressBranchDto::Receive
        }
    }
}

impl From<AddressBranchDto> for bool {
    fn from(branch: AddressBranchDto) -> Self {
        matches!(branch, AddressBranchDto::Change)
    }
}

impl From<&AddressEntry> for AddressMetadataDto {
    fn from(entry: &AddressEntry) -> Self {
        Self {
            address: entry.address.clone(),
            change: entry.change,
            index: entry.index,
            status: entry.status.into(),
            label: entry.label.clone(),
            note: entry.note.clone(),
            first_seen_height: entry.first_seen_height,
            last_synced_height: entry.last_synced_height,
        }
    }
}

impl From<&AddressEntry> for WalletAddressDto {
    fn from(entry: &AddressEntry) -> Self {
        Self {
            address: entry.address.clone(),
            branch: entry.change.into(),
            index: entry.index,
            status: entry.status.into(),
            label: entry.label.clone(),
            note: entry.note.clone(),
            derived_at_ms: None,
            first_seen_at_ms: None,
        }
    }
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
    fn address_metadata_roundtrip() {
        let dto = AddressMetadataDto {
            address: "wallet1".to_string(),
            change: false,
            index: 7,
            status: AddressStatusDto::Used,
            label: Some("primary".to_string()),
            note: Some("note".to_string()),
            first_seen_height: Some(5),
            last_synced_height: Some(12),
        };
        roundtrip(&dto);
    }

    #[test]
    fn list_addresses_response_roundtrip() {
        let dto = AddressMetadataDto {
            address: "wallet1".to_string(),
            change: true,
            index: 3,
            status: AddressStatusDto::Unused,
            label: None,
            note: None,
            first_seen_height: None,
            last_synced_height: None,
        };
        let response = ListAddressesResponse {
            addresses: vec![dto],
            page: 0,
            page_size: 10,
            total: 1,
        };
        roundtrip(&response);
    }

    #[test]
    fn list_branch_addresses_roundtrip() {
        let address = WalletAddressDto {
            address: "wallet1".to_string(),
            branch: AddressBranchDto::Receive,
            index: 0,
            status: AddressStatusDto::Unused,
            label: Some("primary".into()),
            note: None,
            derived_at_ms: Some(1_700_000_000_000),
            first_seen_at_ms: None,
        };
        let params = ListBranchAddressesParams {
            branch: AddressBranchDto::Change,
            cursor: Some("cursor".into()),
            page_size: Some(5),
        };
        let response = ListBranchAddressesResponse {
            addresses: vec![address],
            next_cursor: Some("next".into()),
            prev_cursor: Some("prev".into()),
        };
        roundtrip(&params);
        roundtrip(&response);
    }

    #[test]
    fn update_address_metadata_roundtrip() {
        let params = UpdateAddressMetadataParams {
            address: "wallet1".into(),
            label: None,
            note: Some("note".into()),
        };
        let response = UpdateAddressMetadataResponse {
            address: WalletAddressDto {
                address: "wallet1".into(),
                branch: AddressBranchDto::Change,
                index: 2,
                status: AddressStatusDto::Used,
                label: Some("label".into()),
                note: Some("note".into()),
                derived_at_ms: None,
                first_seen_at_ms: Some(1_600_000_000_000),
            },
        };
        roundtrip(&params);
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
            locks: Vec::new(),
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
            signed: SignedTxProverBundleDto {
                tx_hex: "deadbeef".into(),
                proof_hex: Some("bead".into()),
                metadata: ProverMetadataDto {
                    backend: "mock".into(),
                    witness_bytes: 512,
                    prove_duration_ms: 42,
                    proof_required: true,
                    proof_present: true,
                    proof_bytes: Some(256),
                    proof_hash: Some("c0ffee".into()),
                },
            },
            locks: vec![PendingLockDto {
                utxo_txid: "aa".into(),
                utxo_index: 0,
                locked_at_ms: 1234,
                spending_txid: None,
                backend: "mock".into(),
                witness_bytes: 1,
                prove_duration_ms: 2,
                proof_required: true,
                proof_present: true,
                proof_bytes: None,
                proof_hash: Some("beef".into()),
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
            proof_required: true,
            proof_present: true,
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
            current_height: Some(8),
            target_height: Some(12),
            lag_blocks: Some(4),
            scanned_scripthashes: Some(4),
            discovered_transactions: Some(2),
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
                proof_required: false,
                proof_present: false,
                proof_bytes: Some(128),
                proof_hash: None,
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
