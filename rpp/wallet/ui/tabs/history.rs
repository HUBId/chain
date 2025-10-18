use serde::Serialize;

use crate::runtime::node::PendingTransactionSummary;
use crate::types::SignedTransaction;
use rpp_wallet::vendor::electrs::StatusDigest;
#[cfg(feature = "backend-rpp-stark")]
use rpp_wallet::vendor::electrs::StoredVrfAudit;

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
    pub tx_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<SignedTransaction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_summary: Option<PendingTransactionSummary>,
    pub status: HistoryStatus,
    pub reputation_delta: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_digest: Option<StatusDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_envelope: Option<String>,
    #[cfg(feature = "backend-rpp-stark")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vrf_audit: Option<StoredVrfAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub double_spend: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conflict: Option<String>,
}

impl HistoryEntry {
    pub fn pending(
        tx_hash: String,
        transaction: Option<SignedTransaction>,
        summary: Option<PendingTransactionSummary>,
        submitted_at: u64,
    ) -> Self {
        Self {
            tx_hash,
            transaction,
            pending_summary: summary,
            status: HistoryStatus::Pending { submitted_at },
            reputation_delta: 0,
            status_digest: None,
            proof_envelope: None,
            #[cfg(feature = "backend-rpp-stark")]
            vrf_audit: None,
            double_spend: None,
            conflict: None,
        }
    }

    pub fn confirmed(
        tx_hash: String,
        transaction: Option<SignedTransaction>,
        height: u64,
        timestamp: u64,
        reputation_delta: i64,
    ) -> Self {
        Self {
            tx_hash,
            transaction,
            pending_summary: None,
            status: HistoryStatus::Confirmed { height, timestamp },
            reputation_delta,
            status_digest: None,
            proof_envelope: None,
            #[cfg(feature = "backend-rpp-stark")]
            vrf_audit: None,
            double_spend: None,
            conflict: None,
        }
    }

    pub fn pruned(tx_hash: String, pruned_height: u64) -> Self {
        Self {
            tx_hash,
            transaction: None,
            pending_summary: None,
            status: HistoryStatus::Pruned { pruned_height },
            reputation_delta: 0,
            status_digest: None,
            proof_envelope: None,
            #[cfg(feature = "backend-rpp-stark")]
            vrf_audit: None,
            double_spend: None,
            conflict: None,
        }
    }

    pub fn with_status_digest(mut self, digest: Option<StatusDigest>) -> Self {
        self.status_digest = digest;
        self
    }

    pub fn with_proof_envelope(mut self, envelope: Option<String>) -> Self {
        self.proof_envelope = envelope;
        self
    }

    #[cfg(feature = "backend-rpp-stark")]
    pub fn with_vrf_audit(mut self, audit: Option<StoredVrfAudit>) -> Self {
        self.vrf_audit = audit;
        self
    }

    pub fn with_double_spend(mut self, double_spend: Option<bool>) -> Self {
        self.double_spend = double_spend;
        self
    }

    pub fn with_conflict(mut self, conflict: Option<String>) -> Self {
        self.conflict = conflict;
        self
    }
}
