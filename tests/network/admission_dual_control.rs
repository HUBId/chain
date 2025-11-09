use std::sync::Arc;

use rpp_p2p::vendor::PeerId as NetworkPeerId;
use rpp_p2p::{
    AdmissionApproval, AdmissionAuditTrail, AllowlistedPeer, DualControlApprovalService,
    DualControlError, Peerstore, PeerstoreConfig, TierLevel,
};

#[test]
fn pending_change_commits_after_security_approval() {
    let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
    let service = DualControlApprovalService::new(peerstore.clone());

    let peer = NetworkPeerId::random();
    let allowlist = vec![AllowlistedPeer {
        peer,
        tier: TierLevel::Tl3,
    }];
    let audit = AdmissionAuditTrail::new("ops.oncall", Some("rotate peer"))
        .with_approvals(vec![AdmissionApproval::new("operations", "ops.oncall")]);

    let pending = service
        .submit_change(allowlist.clone(), Vec::new(), audit)
        .expect("queued pending change");

    assert!(service.pending(pending.id()).is_some());
    let policies = peerstore.admission_policies();
    assert!(policies.allowlist().is_empty());
    assert!(policies.blocklist().is_empty());

    let policies = service
        .approve_change(
            pending.id(),
            AdmissionApproval::new("security", "sec.oncall"),
        )
        .expect("approved pending change");

    assert_eq!(policies.allowlist().len(), 1);
    assert_eq!(policies.allowlist()[0].peer, allowlist[0].peer);
    assert_eq!(policies.allowlist()[0].tier, TierLevel::Tl3);
    assert!(service.pending(pending.id()).is_none());

    let (entries, _) = peerstore
        .admission_audit_entries(0, 8)
        .expect("audit entries");
    assert!(!entries.is_empty());
    let approvals = &entries.last().expect("last entry").approvals;
    assert_eq!(approvals.len(), 2);
    let mut roles: Vec<&str> = approvals
        .iter()
        .map(|record| record.role.as_str())
        .collect();
    roles.sort_unstable();
    assert_eq!(roles, vec!["operations", "security"]);
}

#[test]
fn missing_operations_approval_rejected() {
    let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("peerstore"));
    let service = DualControlApprovalService::new(peerstore);

    let peer = NetworkPeerId::random();
    let allowlist = vec![AllowlistedPeer {
        peer,
        tier: TierLevel::Tl2,
    }];
    let audit = AdmissionAuditTrail::new("ops.oncall", Some("rotate"));

    let error = service
        .submit_change(allowlist, Vec::new(), audit)
        .expect_err("missing operations approval should fail");
    assert!(matches!(error, DualControlError::MissingOperationsApproval));
}
