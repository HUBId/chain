use serde::{Deserialize, Serialize};

/// Receipt returned when a pruning snapshot rebuild is triggered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotRebuildReceipt {
    /// Indicates whether the rebuild request was accepted by the service.
    pub accepted: bool,
    /// Optional details describing why a request was rejected or contextual information
    /// about the rebuild that was scheduled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl SnapshotRebuildReceipt {
    /// Creates a receipt signalling that the rebuild request was accepted.
    pub fn accepted() -> Self {
        Self {
            accepted: true,
            detail: None,
        }
    }

    /// Creates a receipt signalling that the rebuild request was rejected with a reason.
    pub fn rejected(detail: impl Into<String>) -> Self {
        Self {
            accepted: false,
            detail: Some(detail.into()),
        }
    }
}

/// Receipt returned when an on-demand pruning snapshot is requested.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotTriggerReceipt {
    /// Indicates whether the snapshot request was accepted by the service.
    pub accepted: bool,
    /// Optional detail describing why the request was rejected or extra context for the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Receipt returned when a pruning snapshot job is cancelled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCancelReceipt {
    /// Indicates whether the cancellation request was accepted by the service.
    pub accepted: bool,
    /// Optional detail describing why the request was rejected or extra context for the caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl SnapshotCancelReceipt {
    /// Creates a receipt signalling that the cancellation request was accepted.
    pub fn accepted() -> Self {
        Self {
            accepted: true,
            detail: None,
        }
    }

    /// Creates a receipt signalling that the cancellation request was rejected with a reason.
    pub fn rejected(detail: impl Into<String>) -> Self {
        Self {
            accepted: false,
            detail: Some(detail.into()),
        }
    }
}

impl SnapshotTriggerReceipt {
    /// Creates a receipt signalling that the snapshot request was accepted.
    pub fn accepted() -> Self {
        Self {
            accepted: true,
            detail: None,
        }
    }

    /// Creates a receipt signalling that the snapshot request was rejected with a reason.
    pub fn rejected(detail: impl Into<String>) -> Self {
        Self {
            accepted: false,
            detail: Some(detail.into()),
        }
    }
}
