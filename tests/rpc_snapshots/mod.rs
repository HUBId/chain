#[path = "../support/mod.rs"]
mod support;

use std::fs;
use std::path::{Path, PathBuf};

use axum::body::{self, Body};
use axum::http::{Method, Request as HttpRequest, header::CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use support::rpc::{Mode, build_app};
use tower::ServiceExt;

const STATUS_FIXTURE_VERSION: &str = "v1";
const LEDGER_FIXTURE_VERSION: &str = "v1";
const VALIDATORS_FIXTURE_VERSION: &str = "v1";
const TX_SUBMIT_FIXTURE_VERSION: &str = "v1";

#[derive(Debug, Clone)]
struct SnapshotCase {
    name: &'static str,
    version: &'static str,
    method: Method,
    path: &'static str,
    body: Option<Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct RpcSnapshot {
    version: String,
    request: SnapshotRequest,
    response: SnapshotResponse,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct SnapshotRequest {
    method: String,
    path: String,
    body: Option<Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct SnapshotResponse {
    status: u16,
    body: Value,
}

#[tokio::test]
async fn rpc_snapshots_match_fixtures() {
    let cases = [
        SnapshotCase {
            name: "status",
            version: STATUS_FIXTURE_VERSION,
            method: Method::GET,
            path: "/status",
            body: None,
        },
        SnapshotCase {
            name: "ledger_tip",
            version: LEDGER_FIXTURE_VERSION,
            method: Method::GET,
            path: "/ledger/2",
            body: None,
        },
        SnapshotCase {
            name: "consensus_validators",
            version: VALIDATORS_FIXTURE_VERSION,
            method: Method::GET,
            path: "/consensus/validators",
            body: None,
        },
        SnapshotCase {
            name: "tx_submit",
            version: TX_SUBMIT_FIXTURE_VERSION,
            method: Method::POST,
            path: "/tx/submit",
            body: Some(serde_json::json!({
                "from": "alice",
                "to": "bob",
                "amount": 25u64,
            })),
        },
    ];

    for case in cases {
        let app = build_app(Mode::Node);
        let actual = capture_snapshot(&case, app).await;
        verify_snapshot(&case, actual);
    }
}

async fn capture_snapshot(case: &SnapshotCase, app: axum::Router) -> RpcSnapshot {
    let mut builder = HttpRequest::builder()
        .method(case.method.clone())
        .uri(case.path);

    let body = if let Some(payload) = &case.body {
        builder = builder.header(CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(payload).expect("serialize request body"))
    } else {
        Body::empty()
    };

    let response = app
        .oneshot(builder.body(body).expect("build request"))
        .await
        .expect("dispatch request");

    let status = response.status();
    let response_body = body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("response body");
    let body_json: Value = serde_json::from_slice(&response_body).expect("json response");

    RpcSnapshot {
        version: case.version.to_string(),
        request: SnapshotRequest {
            method: case.method.as_str().to_string(),
            path: case.path.to_string(),
            body: case.body.clone(),
        },
        response: SnapshotResponse {
            status: status.as_u16(),
            body: body_json,
        },
    }
}

fn verify_snapshot(case: &SnapshotCase, actual: RpcSnapshot) {
    let path = fixture_path(case.name, case.version);
    let expected = match fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str::<RpcSnapshot>(&contents).unwrap_or_else(|error| {
            panic!(
                "Failed to parse RPC snapshot fixture {path}: {error}\nActual snapshot:\n{actual}",
                path = path.display(),
                actual = serde_json::to_string_pretty(&actual).unwrap()
            )
        }),
        Err(error) => panic!(
            "Missing RPC snapshot fixture {path}: {error}\nActual snapshot:\n{actual}",
            path = path.display(),
            error = error,
            actual = serde_json::to_string_pretty(&actual).unwrap()
        ),
    };

    if expected.version != case.version {
        panic!(
            "Fixture {path} declares version {declared} but test expects {expected}",
            path = path.display(),
            declared = expected.version,
            expected = case.version,
        );
    }

    if expected != actual {
        panic!(
            "Snapshot mismatch for {name} @ {version}.\nUpdate instructions:\n  1. Bump the fixture version constant in tests/rpc_snapshots/mod.rs.\n  2. Write the new fixture to {path}.\nActual snapshot:\n{actual}",
            name = case.name,
            version = case.version,
            path = path.display(),
            actual = serde_json::to_string_pretty(&actual).unwrap(),
        );
    }
}

fn fixture_path(name: &str, version: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("rpc_snapshots")
        .join("fixtures")
        .join(name)
        .join(format!("{version}.json"))
}
