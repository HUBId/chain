use std::borrow::Cow;

use serde::de::IntoDeserializer;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

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
    Custom(String),
}

impl WalletRpcErrorCode {
    pub fn as_str(&self) -> Cow<'_, str> {
        match self {
            WalletRpcErrorCode::InvalidRequest => Cow::Borrowed("INVALID_REQUEST"),
            WalletRpcErrorCode::MethodNotFound => Cow::Borrowed("METHOD_NOT_FOUND"),
            WalletRpcErrorCode::InvalidParams => Cow::Borrowed("INVALID_PARAMS"),
            WalletRpcErrorCode::InternalError => Cow::Borrowed("INTERNAL_ERROR"),
            WalletRpcErrorCode::WalletPolicyViolation => Cow::Borrowed("WALLET_POLICY_VIOLATION"),
            WalletRpcErrorCode::FeeTooLow => Cow::Borrowed("FEE_TOO_LOW"),
            WalletRpcErrorCode::FeeTooHigh => Cow::Borrowed("FEE_TOO_HIGH"),
            WalletRpcErrorCode::PendingLockConflict => Cow::Borrowed("PENDING_LOCK_CONFLICT"),
            WalletRpcErrorCode::ProverTimeout => Cow::Borrowed("PROVER_TIMEOUT"),
            WalletRpcErrorCode::ProverFailed => Cow::Borrowed("PROVER_FAILED"),
            WalletRpcErrorCode::ProverCancelled => Cow::Borrowed("PROVER_CANCELLED"),
            WalletRpcErrorCode::WitnessTooLarge => Cow::Borrowed("WITNESS_TOO_LARGE"),
            WalletRpcErrorCode::SyncUnavailable => Cow::Borrowed("SYNC_UNAVAILABLE"),
            WalletRpcErrorCode::SyncError => Cow::Borrowed("SYNC_ERROR"),
            WalletRpcErrorCode::RescanOutOfRange => Cow::Borrowed("RESCAN_OUT_OF_RANGE"),
            WalletRpcErrorCode::RescanInProgress => Cow::Borrowed("RESCAN_IN_PROGRESS"),
            WalletRpcErrorCode::DraftNotFound => Cow::Borrowed("DRAFT_NOT_FOUND"),
            WalletRpcErrorCode::DraftUnsigned => Cow::Borrowed("DRAFT_UNSIGNED"),
            WalletRpcErrorCode::NodeUnavailable => Cow::Borrowed("NODE_UNAVAILABLE"),
            WalletRpcErrorCode::NodeRejected => Cow::Borrowed("NODE_REJECTED"),
            WalletRpcErrorCode::NodePolicy => Cow::Borrowed("NODE_POLICY"),
            WalletRpcErrorCode::NodeStatsUnavailable => Cow::Borrowed("NODE_STATS_UNAVAILABLE"),
            WalletRpcErrorCode::EngineFailure => Cow::Borrowed("ENGINE_FAILURE"),
            WalletRpcErrorCode::SerializationFailure => Cow::Borrowed("SERIALIZATION_FAILURE"),
            WalletRpcErrorCode::StatePoisoned => Cow::Borrowed("STATE_POISONED"),
            WalletRpcErrorCode::Custom(other) => Cow::Borrowed(other.as_str()),
        }
    }

    pub fn as_i32(&self) -> i32 {
        match self {
            WalletRpcErrorCode::InvalidRequest => -32600,
            WalletRpcErrorCode::MethodNotFound => -32601,
            WalletRpcErrorCode::InvalidParams => -32602,
            WalletRpcErrorCode::InternalError => -32603,
            WalletRpcErrorCode::WalletPolicyViolation => -32010,
            WalletRpcErrorCode::FeeTooLow => -32011,
            WalletRpcErrorCode::FeeTooHigh => -32012,
            WalletRpcErrorCode::PendingLockConflict => -32013,
            WalletRpcErrorCode::ProverTimeout => -32014,
            WalletRpcErrorCode::ProverFailed => -32015,
            WalletRpcErrorCode::ProverCancelled => -32016,
            WalletRpcErrorCode::WitnessTooLarge => -32017,
            WalletRpcErrorCode::SyncUnavailable => -32050,
            WalletRpcErrorCode::SyncError => -32051,
            WalletRpcErrorCode::RescanOutOfRange => -32052,
            WalletRpcErrorCode::RescanInProgress => -32053,
            WalletRpcErrorCode::DraftNotFound => -32060,
            WalletRpcErrorCode::DraftUnsigned => -32061,
            WalletRpcErrorCode::NodeUnavailable => -32070,
            WalletRpcErrorCode::NodeRejected => -32071,
            WalletRpcErrorCode::NodePolicy => -32072,
            WalletRpcErrorCode::NodeStatsUnavailable => -32073,
            WalletRpcErrorCode::EngineFailure => -32080,
            WalletRpcErrorCode::SerializationFailure => -32081,
            WalletRpcErrorCode::StatePoisoned => -32082,
            WalletRpcErrorCode::Custom(_) => -32090,
        }
    }

    pub fn data_payload(&self, details: Option<Value>) -> Value {
        let mut payload = serde_json::Map::new();
        payload.insert(
            "code".to_string(),
            Value::String(self.as_str().into_owned()),
        );
        if let Some(details) = details {
            payload.insert("details".to_string(), details);
        }
        Value::Object(payload)
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
