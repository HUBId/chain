use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const JSONRPC_VERSION: &str = "2.0";

#[derive(Clone, Debug, Deserialize, PartialEq)]
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

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct DeriveAddressParams {
    #[serde(default)]
    pub change: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeriveAddressResponse {
    pub address: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DraftSpendModelDto {
    Exact { amount: u128 },
    Sweep,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateTxResponse {
    pub draft_id: String,
    pub fee_rate: u64,
    pub fee: u128,
    pub total_input_value: u128,
    pub total_output_value: u128,
    pub spend_model: DraftSpendModelDto,
    pub inputs: Vec<DraftInputDto>,
    pub outputs: Vec<DraftOutputDto>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct BroadcastParams {
    pub draft_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BroadcastResponse {
    pub draft_id: String,
    pub accepted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyPreviewResponse {
    pub min_confirmations: u32,
    pub dust_limit: u128,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct SyncStatusParams;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncStatusResponse {
    pub syncing: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_scripthashes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_range: Option<(u64, u64)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RescanParams {
    pub from_height: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RescanResponse {
    pub scheduled: bool,
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
        };
        roundtrip(&response);
    }

    #[test]
    fn policy_preview_response_roundtrip() {
        let response = PolicyPreviewResponse {
            min_confirmations: 6,
            dust_limit: 546,
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
            latest_height: Some(12),
            scanned_scripthashes: Some(4),
            pending_range: Some((10, 12)),
            last_error: Some("stalled".to_string()),
        };
        roundtrip(&response);
    }

    #[test]
    fn rescan_params_roundtrip() {
        let params = RescanParams { from_height: 25 };
        roundtrip(&params);
    }

    #[test]
    fn rescan_response_roundtrip() {
        let response = RescanResponse { scheduled: true };
        roundtrip(&response);
    }
}
