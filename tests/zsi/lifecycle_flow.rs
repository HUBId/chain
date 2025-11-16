#![cfg(all(feature = "wallet-integration", feature = "wallet_zsi"))]

//! These tests require the `wallet_zsi` feature. Enable with `--features wallet_zsi`.

use prover_mock_backend::MockBackend;

use rpp_wallet::cli::zsi::{execute, ZsiCli, ZsiSubcommand};
use rpp_wallet::rpc::zsi as rpc_zsi;
use rpp_wallet::zsi::{
    ConsensusApproval, LifecycleReceipt, RotateRequest, RevokeRequest, ZsiLifecycle, ZsiRecord,
    ZsiRequest,
};

fn approval() -> ConsensusApproval {
    ConsensusApproval {
        validator: "validator-1".into(),
        signature: "deadbeef".into(),
        timestamp: 7,
    }
}

fn issue_request() -> ZsiRequest {
    ZsiRequest {
        identity: "alice".into(),
        genesis_id: "genesis-1".into(),
        attestation: "initial-proof".into(),
        approvals: vec![approval()],
    }
}

#[test]
fn lifecycle_round_trip_through_cli_and_rpc() {
    let lifecycle = ZsiLifecycle::new(MockBackend::new());
    let issued = match lifecycle.issue(issue_request()).expect("issue receipt") {
        LifecycleReceipt::Issued { record, .. } => record,
        other => panic!("unexpected receipt: {other}"),
    };
    assert_eq!(issued.identity, "alice");

    // Rotate using the CLI facade.
    let cli_receipt = execute(
        MockBackend::new(),
        ZsiCli {
            command: ZsiSubcommand::Rotate {
                identity: issued.identity.clone(),
                previous_genesis: issued.genesis_id.clone(),
                previous_attestation: "initial-proof".into(),
                next_genesis: "genesis-2".into(),
                attestation: Some("rotation-proof".into()),
                approvals: issued.approvals.clone(),
            },
        },
    )
    .expect("rotate via cli");
    let rotated = match cli_receipt {
        LifecycleReceipt::Rotated { updated, .. } => updated,
        _ => panic!("unexpected cli receipt"),
    };
    assert_eq!(rotated.genesis_id, "genesis-2");

    // Revoke through the RPC surface.
    let revoke_receipt = rpc_zsi::revoke(
        MockBackend::new(),
        rpc_zsi::RevokeParams {
            identity: rotated.identity.clone(),
            reason: "compromised".into(),
            attestation: None,
        },
    )
    .expect("revoke via rpc");
    match revoke_receipt {
        LifecycleReceipt::Revoked { identity, .. } => assert_eq!(identity, rotated.identity),
        _ => panic!("unexpected revoke receipt"),
    }

    // Audit the rotated record using the RPC helper and ensure the checks mention approvals.
    let audit_receipt = rpc_zsi::audit(
        MockBackend::new(),
        rpc_zsi::AuditParams {
            identity: rotated.identity.clone(),
            genesis_id: rotated.genesis_id.clone(),
            attestation: "rotation-proof".into(),
            approvals: rotated.approvals.clone(),
        },
    )
    .expect("audit via rpc");
    match audit_receipt {
        LifecycleReceipt::Audit(report) => {
            assert_eq!(report.summary.record.identity, rotated.identity);
            assert!(report.checks.iter().any(|check| check.contains("approvals")));
        }
        _ => panic!("unexpected audit receipt"),
    }

    // Manually rotate through the library API to confirm parity with CLI/RPC flows.
    let manual_rotate = ZsiLifecycle::new(MockBackend::new())
        .rotate(RotateRequest {
            previous: rotated.clone(),
            next_genesis_id: "genesis-3".into(),
            attestation: Some("final-proof".into()),
            approvals: rotated.approvals.clone(),
        })
        .expect("manual rotation");
    match manual_rotate {
        LifecycleReceipt::Rotated { updated, .. } => {
            assert_eq!(updated.genesis_id, "genesis-3");
        }
        _ => panic!("unexpected manual rotation receipt"),
    }
}

#[test]
fn cli_issue_matches_library() {
    let cli_receipt = execute(
        MockBackend::new(),
        ZsiCli {
            command: ZsiSubcommand::Issue {
                identity: "bob".into(),
                genesis_id: "genesis-b".into(),
                attestation: "proof-b".into(),
                approvals: vec![approval()],
            },
        },
    )
    .expect("cli issue");
    match cli_receipt {
        LifecycleReceipt::Issued { record, .. } => {
            assert_eq!(record.identity, "bob");
            assert!(record.attestation_digest.len() > 10);
        }
        _ => panic!("unexpected cli issue receipt"),
    }

    let rpc_receipt = rpc_zsi::issue(
        MockBackend::new(),
        rpc_zsi::IssueParams {
            identity: "bob".into(),
            genesis_id: "genesis-b".into(),
            attestation: "proof-b".into(),
            approvals: vec![approval()],
        },
    )
    .expect("rpc issue");
    match rpc_receipt {
        LifecycleReceipt::Issued { record, .. } => {
            assert_eq!(record.identity, "bob");
        }
        _ => panic!("unexpected rpc issue receipt"),
    }
}
