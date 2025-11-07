use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::{get, post},
    Router,
};
use hyper::body::to_bytes;
use parking_lot::RwLock;
use rpp_chain::api::{self, ApiContext};
use rpp_chain::runtime::RuntimeMode;
use rpp_p2p::{vendor::PeerId as NetworkPeerId, Peerstore, PeerstoreConfig, TierLevel};
use serde::Deserialize;
use serde_json::json;
use tempfile::tempdir;
use tower::ServiceExt;

#[derive(Debug, Deserialize)]
struct AuditApproval {
    role: String,
    approver: String,
}

#[derive(Debug, Deserialize)]
struct AuditEntry {
    actor: String,
    approvals: Vec<AuditApproval>,
}

#[derive(Debug, Deserialize)]
struct AuditLogResponse {
    entries: Vec<AuditEntry>,
}

#[tokio::test]
async fn dual_approval_update_records_audit_approvals() {
    let dir = tempdir().expect("tempdir");
    let peerstore_path = dir.path().join("peerstore.json");
    let peerstore =
        Arc::new(Peerstore::open(PeerstoreConfig::persistent(&peerstore_path)).expect("peerstore"));

    let context = ApiContext::new(
        Arc::new(RwLock::new(RuntimeMode::Node)),
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        false,
    )
    .with_test_peerstore(peerstore.clone());

    let app = Router::new()
        .route(
            "/p2p/admission/policies",
            post(api::update_admission_policies),
        )
        .route("/p2p/admission/audit", get(api::admission_audit_log))
        .with_state(context);

    let peer = NetworkPeerId::random();
    let request = Request::builder()
        .method("POST")
        .uri("/p2p/admission/policies")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "actor": "ops.oncall",
                "reason": "dual approval test",
                "allowlist": [{"peer_id": peer.to_string(), "tier": TierLevel::Tl3 }],
                "blocklist": [],
                "approvals": [
                    {"role": "operations", "approver": "ops.oncall"},
                    {"role": "security", "approver": "sec.oncall"}
                ]
            })
            .to_string(),
        ))
        .unwrap();

    let response = app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let audit_request = Request::builder()
        .method("GET")
        .uri("/p2p/admission/audit?limit=8")
        .body(Body::empty())
        .unwrap();

    let audit_response = app.oneshot(audit_request).await.unwrap();
    assert_eq!(audit_response.status(), StatusCode::OK);
    let body = to_bytes(audit_response.into_body()).await.unwrap();
    let payload: AuditLogResponse = serde_json::from_slice(&body).expect("audit payload");
    assert!(
        !payload.entries.is_empty(),
        "audit log should record entries"
    );
    let last = payload.entries.last().expect("last audit entry");
    assert_eq!(last.actor, "ops.oncall");
    assert_eq!(last.approvals.len(), 2);

    let mut roles = last
        .approvals
        .iter()
        .map(|approval| approval.role.as_str())
        .collect::<Vec<_>>();
    roles.sort();
    assert_eq!(roles, vec!["operations", "security"]);
}
