use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::Mutex;
use thiserror::Error;
use tracing::info;

use crate::peerstore::{
    AdmissionApproval, AdmissionAuditTrail, AdmissionPolicies, AllowlistedPeer, Peerstore,
    PeerstoreError,
};
use crate::vendor::PeerId;

/// Identifier for a pending policy change.
pub type PendingChangeId = u64;

#[derive(Debug, Error)]
pub enum DualControlError {
    #[error("pending policy change requires operations approval before submission")]
    MissingOperationsApproval,
    #[error("pending policy change already includes security approval")]
    SecurityApprovalAlreadyPresent,
    #[error("pending policy change {id} not found")]
    PendingChangeNotFound { id: PendingChangeId },
    #[error("pending policy change already has approval for role `{role}`")]
    ApprovalAlreadyProvided { role: String },
    #[error("pending change approvals must be submitted by the security role, got `{role}`")]
    UnexpectedApprovalRole { role: String },
    #[error(transparent)]
    Peerstore(#[from] PeerstoreError),
}

#[derive(Debug, Clone)]
pub struct PendingPolicyChange {
    id: PendingChangeId,
    submitted_at: SystemTime,
    allowlist: Vec<AllowlistedPeer>,
    blocklist: Vec<PeerId>,
    audit: AdmissionAuditTrail,
}

impl PendingPolicyChange {
    pub fn id(&self) -> PendingChangeId {
        self.id
    }

    pub fn submitted_at(&self) -> SystemTime {
        self.submitted_at
    }

    pub fn audit(&self) -> &AdmissionAuditTrail {
        &self.audit
    }

    pub fn allowlist(&self) -> &[AllowlistedPeer] {
        &self.allowlist
    }

    pub fn blocklist(&self) -> &[PeerId] {
        &self.blocklist
    }
}

#[derive(Debug)]
pub struct DualControlApprovalService {
    peerstore: Arc<Peerstore>,
    sequence: AtomicU64,
    pending: Mutex<HashMap<PendingChangeId, PendingPolicyChange>>,
}

impl DualControlApprovalService {
    pub fn new(peerstore: Arc<Peerstore>) -> Self {
        Self {
            peerstore,
            sequence: AtomicU64::new(0),
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub fn submit_change(
        &self,
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<PeerId>,
        audit: AdmissionAuditTrail,
    ) -> Result<PendingPolicyChange, DualControlError> {
        if !audit.has_role("operations") {
            return Err(DualControlError::MissingOperationsApproval);
        }
        if audit.has_role("security") {
            return Err(DualControlError::SecurityApprovalAlreadyPresent);
        }

        let id = self.sequence.fetch_add(1, Ordering::SeqCst) + 1;
        let change = PendingPolicyChange {
            id,
            submitted_at: SystemTime::now(),
            allowlist,
            blocklist,
            audit,
        };

        {
            let mut guard = self.pending.lock();
            guard.insert(id, change.clone());
        }

        let audit = change.audit();
        info!(
            target: "telemetry.admission",
            id = id,
            actor = %audit.actor(),
            reason = audit.reason().unwrap_or("n/a"),
            approvals = audit.approvals().len(),
            "queued_pending_admission_change"
        );

        Ok(change)
    }

    pub fn approve_change(
        &self,
        id: PendingChangeId,
        approval: AdmissionApproval,
    ) -> Result<AdmissionPolicies, DualControlError> {
        if !approval.role().eq_ignore_ascii_case("security") {
            return Err(DualControlError::UnexpectedApprovalRole {
                role: approval.role().to_string(),
            });
        }

        let change = {
            let guard = self.pending.lock();
            guard
                .get(&id)
                .cloned()
                .ok_or(DualControlError::PendingChangeNotFound { id })?
        };

        if change.audit().has_role("security") {
            return Err(DualControlError::ApprovalAlreadyProvided {
                role: "security".to_string(),
            });
        }

        let mut approvals = change.audit().approvals().to_vec();
        if approvals
            .iter()
            .any(|existing| existing.role().eq_ignore_ascii_case("security"))
        {
            return Err(DualControlError::ApprovalAlreadyProvided {
                role: "security".to_string(),
            });
        }
        approvals.push(approval.clone());

        let audit = change.audit().clone().with_approvals(approvals);

        self.peerstore.update_admission_policies(
            change.allowlist.clone(),
            change.blocklist.clone(),
            audit,
        )?;

        {
            let mut guard = self.pending.lock();
            guard.remove(&id);
        }

        info!(
            target: "telemetry.admission",
            id = id,
            approver = %approval.approver(),
            "committed_pending_admission_change"
        );

        Ok(self.peerstore.admission_policies())
    }

    pub fn pending(&self, id: PendingChangeId) -> Option<PendingPolicyChange> {
        self.pending.lock().get(&id).cloned()
    }

    pub fn list_pending(&self) -> Vec<PendingPolicyChange> {
        self.pending.lock().values().cloned().collect()
    }
}
