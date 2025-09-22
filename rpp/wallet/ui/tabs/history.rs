use serde::Serialize;

use crate::types::SignedTransaction;

#[derive(Clone, Debug, Serialize)]
pub enum HistoryStatus {
    Pending { submitted_at: u64 },
    Confirmed { height: u64, timestamp: u64 },
    Pruned { pruned_height: u64 },
}

impl HistoryStatus {
    pub fn confirmation_height(&self) -> u64 {
        match self {
            HistoryStatus::Pending { .. } => u64::MAX,
            HistoryStatus::Confirmed { height, .. } => *height,
            HistoryStatus::Pruned { pruned_height } => *pruned_height,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct HistoryEntry {
    pub transaction: SignedTransaction,
    pub status: HistoryStatus,
    pub reputation_delta: i64,
}

impl HistoryEntry {
    pub fn pending(transaction: SignedTransaction, submitted_at: u64) -> Self {
        Self {
            transaction,
            status: HistoryStatus::Pending { submitted_at },
            reputation_delta: 0,
        }
    }

    pub fn confirmed(
        transaction: SignedTransaction,
        height: u64,
        timestamp: u64,
        reputation_delta: i64,
    ) -> Self {
        Self {
            transaction,
            status: HistoryStatus::Confirmed { height, timestamp },
            reputation_delta,
        }
    }

    pub fn pruned(transaction: SignedTransaction, pruned_height: u64) -> Self {
        Self {
            transaction,
            status: HistoryStatus::Pruned { pruned_height },
            reputation_delta: 0,
        }
    }
}
