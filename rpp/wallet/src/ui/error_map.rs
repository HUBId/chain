use serde_json::Value;

use crate::rpc::error::WalletRpcErrorCode;

/// Mapped error description surfaced to the UI layer.
#[derive(Debug, Clone)]
pub struct ErrorDescription {
    pub headline: String,
    pub technical: Option<String>,
}

impl ErrorDescription {
    pub fn new(headline: impl Into<String>) -> Self {
        Self {
            headline: headline.into(),
            technical: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.technical = Some(detail.into());
        self
    }
}

/// Maps an RPC error code into a user facing description.
pub fn describe_rpc_error(code: &WalletRpcErrorCode, details: Option<&Value>) -> ErrorDescription {
    let headline = match code {
        WalletRpcErrorCode::InvalidRequest => "Request could not be parsed by the daemon.",
        WalletRpcErrorCode::MethodNotFound => {
            "The requested feature is not supported by the daemon."
        }
        WalletRpcErrorCode::InvalidParams => "The daemon rejected the provided parameters.",
        WalletRpcErrorCode::InternalError => "The daemon encountered an unexpected failure.",
        WalletRpcErrorCode::WalletPolicyViolation => "Wallet policy prevented this action.",
        WalletRpcErrorCode::FeeTooLow => "Fee rate is too low for network acceptance.",
        WalletRpcErrorCode::FeeTooHigh => "Fee rate exceeds the configured safety threshold.",
        WalletRpcErrorCode::PendingLockConflict => "An existing pending lock prevents this action.",
        WalletRpcErrorCode::ProverTimeout => "The prover timed out while building the proof.",
        WalletRpcErrorCode::ProverFailed => {
            "The prover failed to construct a proof for this request."
        }
        WalletRpcErrorCode::ProverCancelled => "The prover cancelled the current operation.",
        WalletRpcErrorCode::WitnessTooLarge => {
            "The witness generated for this request is too large."
        }
        WalletRpcErrorCode::SyncUnavailable => {
            "The daemon is not tracking chain sync progress right now."
        }
        WalletRpcErrorCode::SyncError => "The daemon could not determine the current sync status.",
        WalletRpcErrorCode::RescanOutOfRange => {
            "Requested rescan range is outside the indexed history."
        }
        WalletRpcErrorCode::RescanInProgress => "A rescan is already in progress.",
        WalletRpcErrorCode::DraftNotFound => "The referenced draft transaction could not be found.",
        WalletRpcErrorCode::DraftUnsigned => {
            "The draft transaction must be signed before broadcasting."
        }
        WalletRpcErrorCode::NodeUnavailable => "The wallet node is currently unreachable.",
        WalletRpcErrorCode::NodeRejected => "The node rejected this request.",
        WalletRpcErrorCode::NodePolicy => {
            "The node refused the request due to policy restrictions."
        }
        WalletRpcErrorCode::NodeStatsUnavailable => {
            "The node did not provide the requested statistics."
        }
        WalletRpcErrorCode::EngineFailure => "The wallet engine encountered an internal error.",
        WalletRpcErrorCode::SerializationFailure => {
            "The daemon could not serialise the response payload."
        }
        WalletRpcErrorCode::StatePoisoned => "The daemon state is poisoned and requires attention.",
        WalletRpcErrorCode::Custom(code) => {
            return ErrorDescription::new(format!("Wallet RPC error: {code}"));
        }
    };

    let mut description = ErrorDescription::new(headline);
    if let Some(details) = details.and_then(stringify_details) {
        description = description.with_detail(details);
    }
    description
}

fn stringify_details(details: &Value) -> Option<String> {
    match details {
        Value::String(value) => Some(value.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(boolean) => Some(boolean.to_string()),
        Value::Array(array) => Some(format!("{}", Value::Array(array.clone()))),
        Value::Object(object) => Some(format!("{}", Value::Object(object.clone()))),
        Value::Null => None,
    }
}

/// Formats a technical message combining the RPC error string and optional details payload.
pub fn technical_details(message: &str, details: Option<&Value>) -> Option<String> {
    let mut parts = vec![message.to_string()];
    if let Some(payload) = details.and_then(stringify_details) {
        parts.push(payload);
    }
    if parts.len() == 1 {
        None
    } else {
        Some(parts.join(" — "))
    }
}
