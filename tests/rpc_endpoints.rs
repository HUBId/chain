mod support;

use axum::{
    BoxError, Json, Router,
    body::Body,
    error_handling::HandleErrorLayer,
    extract::{Path, Request as AxumRequest, State},
    http::{
        Method, Request as HttpRequest, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use support::rpc::{Mode, build_app, build_app_with_auth, build_rate_limited_app};
use tower::limit::RateLimitLayer;
use tower::{ServiceBuilder, ServiceExt};

#[tokio::test]
async fn status_returns_node_status() {
    let app = build_app(Mode::Node);

    let response = app
        .oneshot(
            HttpRequest::builder()
                .method(Method::GET)
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(payload["role"].as_str(), Some("node"));
    assert_eq!(payload["height"].as_u64(), Some(2));
    assert_eq!(payload["latest_commitment"].as_str(), Some("state-root-2"),);
}

#[tokio::test]
async fn status_rejects_offline_mode() {
    let app = build_app(Mode::Offline);

    let response = app
        .oneshot(
            HttpRequest::builder()
                .method(Method::GET)
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn status_rejects_missing_auth_token_when_required() {
    let app = build_app_with_auth(Mode::Node, Some("secret-token".to_string()));

    let response = app
        .oneshot(
            HttpRequest::builder()
                .method(Method::GET)
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn status_rejects_invalid_auth_token_when_required() {
    let app = build_app_with_auth(Mode::Node, Some("secret-token".to_string()));

    let response = app
        .oneshot(
            HttpRequest::builder()
                .method(Method::GET)
                .uri("/status")
                .header(AUTHORIZATION, "Bearer wrong-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rate_limit_exceeded_returns_429() {
    let app = build_rate_limited_app(Mode::Node, 1);

    let first = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method(Method::GET)
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .oneshot(
            HttpRequest::builder()
                .method(Method::GET)
                .uri("/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn ledger_returns_snapshot_for_height() {
    let app = build_app(Mode::Node);

    let response = app
        .oneshot(
            HttpRequest::builder()
                .method(Method::GET)
                .uri("/ledger/2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(payload["height"].as_u64(), Some(2));
    assert_eq!(
        payload["commitments"]["state_root"].as_str(),
        Some("state-root-2"),
    );
    assert_eq!(payload["snapshot"]["accounts"].as_u64(), Some(120));
    assert_eq!(payload["snapshot"]["witnesses"].as_u64(), Some(16));
}

#[tokio::test]
async fn ledger_rejects_non_numeric_height() {
    let app = build_app(Mode::Node);

    let response = app
        .oneshot(
            HttpRequest::builder()
                .method(Method::GET)
                .uri("/ledger/not-a-height")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn consensus_validators_returns_active_list() {
    let app = build_app(Mode::Node);

    let response = app
        .oneshot(
            HttpRequest::builder()
                .method(Method::GET)
                .uri("/consensus/validators")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: Value = serde_json::from_slice(&bytes).unwrap();

    let validators = payload.as_array().expect("validator list");
    assert_eq!(validators.len(), 3);
    assert_eq!(validators[0]["address"].as_str(), Some("validator-1"));
}

#[tokio::test]
async fn consensus_validators_rejects_without_node_mode() {
    let app = build_app(Mode::Wallet);

    let response = app
        .oneshot(
            HttpRequest::builder()
                .method(Method::GET)
                .uri("/consensus/validators")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tx_submit_accepts_transaction() {
    let app = build_app(Mode::Node);
    let request_body = json!({
        "from": "alice",
        "to": "bob",
        "amount": 25u64,
    });

    let response = app
        .oneshot(
            HttpRequest::builder()
                .method(Method::POST)
                .uri("/tx/submit")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let payload: Value = serde_json::from_slice(&bytes).unwrap();

    let hash = payload["hash"].as_str().expect("hash");
    assert_eq!(hash.len(), 64);
}

#[tokio::test]
async fn tx_submit_rejects_without_node_mode() {
    let app = build_app(Mode::Wallet);
    let request_body = json!({
        "from": "alice",
        "to": "bob",
        "amount": 25u64,
    });

    let response = app
        .oneshot(
            HttpRequest::builder()
                .method(Method::POST)
                .uri("/tx/submit")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}
