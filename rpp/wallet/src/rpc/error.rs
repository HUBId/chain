use std::borrow::Cow;
use std::fmt;

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
    ProverBackendDisabled,
    ProverBackendMisconfigured,
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
            WalletRpcErrorCode::ProverBackendDisabled => Cow::Borrowed("PROVER_BACKEND_DISABLED"),
            WalletRpcErrorCode::ProverBackendMisconfigured => {
                Cow::Borrowed("PROVER_BACKEND_MISCONFIGURED")
            }
            WalletRpcErrorCode::ProverTimeout => Cow::Borrowed("PROVER_TIMEOUT"),
            WalletRpcErrorCode::ProverBusy => Cow::Borrowed("PROVER_BUSY"),
            WalletRpcErrorCode::ProverInternal => Cow::Borrowed("PROVER_INTERNAL"),
            WalletRpcErrorCode::ProverProofMissing => Cow::Borrowed("PROVER_PROOF_MISSING"),
            WalletRpcErrorCode::ProverFailed => Cow::Borrowed("PROVER_FAILED"),
            WalletRpcErrorCode::ProverCancelled => Cow::Borrowed("PROVER_CANCELLED"),
            WalletRpcErrorCode::WitnessTooLarge => Cow::Borrowed("WITNESS_TOO_LARGE"),
            WalletRpcErrorCode::SyncUnavailable => Cow::Borrowed("SYNC_UNAVAILABLE"),
            WalletRpcErrorCode::SyncError => Cow::Borrowed("SYNC_ERROR"),
            WalletRpcErrorCode::IndexerUnavailable => Cow::Borrowed("INDEXER_UNAVAILABLE"),
            WalletRpcErrorCode::RescanOutOfRange => Cow::Borrowed("RESCAN_OUT_OF_RANGE"),
            WalletRpcErrorCode::RescanInProgress => Cow::Borrowed("RESCAN_IN_PROGRESS"),
            WalletRpcErrorCode::RescanAborted => Cow::Borrowed("RESCAN_ABORTED"),
            WalletRpcErrorCode::DraftNotFound => Cow::Borrowed("DRAFT_NOT_FOUND"),
            WalletRpcErrorCode::DraftUnsigned => Cow::Borrowed("DRAFT_UNSIGNED"),
            WalletRpcErrorCode::NodeUnavailable => Cow::Borrowed("NODE_UNAVAILABLE"),
            WalletRpcErrorCode::NodeRejected => Cow::Borrowed("NODE_REJECTED"),
            WalletRpcErrorCode::NodePolicy => Cow::Borrowed("NODE_POLICY"),
            WalletRpcErrorCode::NodeStatsUnavailable => Cow::Borrowed("NODE_STATS_UNAVAILABLE"),
            WalletRpcErrorCode::EngineFailure => Cow::Borrowed("ENGINE_FAILURE"),
            WalletRpcErrorCode::SerializationFailure => Cow::Borrowed("SERIALIZATION_FAILURE"),
            WalletRpcErrorCode::StatePoisoned => Cow::Borrowed("STATE_POISONED"),
            WalletRpcErrorCode::RbacForbidden => Cow::Borrowed("RBAC_FORBIDDEN"),
            WalletRpcErrorCode::WatchOnlyNotEnabled => Cow::Borrowed("WATCH_ONLY_NOT_ENABLED"),
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
            WalletRpcErrorCode::ProverBackendDisabled => -32014,
            WalletRpcErrorCode::ProverBackendMisconfigured => -32022,
            WalletRpcErrorCode::ProverTimeout => -32015,
            WalletRpcErrorCode::ProverBusy => -32016,
            WalletRpcErrorCode::ProverInternal => -32017,
            WalletRpcErrorCode::ProverProofMissing => -32018,
            WalletRpcErrorCode::ProverFailed => -32019,
            WalletRpcErrorCode::ProverCancelled => -32020,
            WalletRpcErrorCode::WitnessTooLarge => -32021,
            WalletRpcErrorCode::SyncUnavailable => -32050,
            WalletRpcErrorCode::SyncError => -32051,
            WalletRpcErrorCode::IndexerUnavailable => -32054,
            WalletRpcErrorCode::RescanOutOfRange => -32052,
            WalletRpcErrorCode::RescanInProgress => -32053,
            WalletRpcErrorCode::RescanAborted => -32055,
            WalletRpcErrorCode::DraftNotFound => -32060,
            WalletRpcErrorCode::DraftUnsigned => -32061,
            WalletRpcErrorCode::NodeUnavailable => -32070,
            WalletRpcErrorCode::NodeRejected => -32071,
            WalletRpcErrorCode::NodePolicy => -32072,
            WalletRpcErrorCode::NodeStatsUnavailable => -32073,
            WalletRpcErrorCode::EngineFailure => -32080,
            WalletRpcErrorCode::SerializationFailure => -32081,
            WalletRpcErrorCode::StatePoisoned => -32082,
            WalletRpcErrorCode::RbacForbidden => -32062,
            WalletRpcErrorCode::WatchOnlyNotEnabled => -32083,
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

impl fmt::Display for WalletRpcErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            "PROVER_BACKEND_MISCONFIGURED" => WalletRpcErrorCode::ProverBackendMisconfigured,
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
            .unwrap_or_else(|_| WalletRpcErrorCode::Custom(value.to_string()))
    }
}
