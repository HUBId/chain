use std::sync::Arc;
use std::time::Duration;

use axum::{
    body::Body,
    error_handling::HandleErrorLayer,
    extract::{Path, Request as AxumRequest, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        Method, Request as HttpRequest, StatusCode,
    },
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    BoxError, Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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

fn build_app(mode: Mode) -> Router {
    build_app_with_auth(mode, None)
}

fn build_app_with_auth(mode: Mode, auth_token: Option<String>) -> Router {
    let mut router = Router::new()
        .route("/status", get(status))
        .route("/ledger/{height}", get(ledger_at_height))
        .route("/consensus/validators", get(active_validators))
        .route("/tx/submit", post(submit_transaction));

    if let Some(token) = auth_token {
        router = router.layer(middleware::from_fn_with_state(
            TestAuthState { token },
            test_auth_middleware,
        ));
    }

    router.with_state(RpcState::new(mode))
}

fn build_rate_limited_app(mode: Mode, requests_per_minute: u64) -> Router {
    build_app(mode).layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(|_: BoxError| async move {
                StatusCode::TOO_MANY_REQUESTS
            }))
            .layer(RateLimitLayer::new(
                requests_per_minute,
                Duration::from_secs(60),
            )),
    )
}

#[derive(Clone)]
struct RpcState {
    inner: Arc<RpcStateInner>,
}

struct RpcStateInner {
    mode: Mode,
    ledger: mock_ledger::MockLedger,
    consensus: mock_consensus::MockConsensus,
    wallet: mock_wallet::MockWallet,
}

#[derive(Clone)]
struct TestAuthState {
    token: String,
}

async fn test_auth_middleware(
    State(state): State<TestAuthState>,
    request: AxumRequest,
    next: Next,
) -> Result<Response, StatusCode> {
    if request.method() == Method::OPTIONS {
        return Ok(next.run(request).await);
    }

    let header_value = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let token = header_value
        .strip_prefix("Bearer ")
        .unwrap_or(header_value)
        .trim();
    if token != state.token {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Node,
    Wallet,
    Offline,
}

#[derive(Serialize)]
#[serde(tag = "role", rename_all = "lowercase")]
enum StatusResponse {
    Node {
        height: u64,
        latest_commitment: String,
    },
    Wallet {
        address: String,
        balance: u64,
    },
}

#[derive(Deserialize)]
struct TxRequest {
    from: String,
    to: String,
    amount: u64,
}

#[derive(Serialize)]
struct TxResponse {
    hash: String,
}

async fn status(State(state): State<RpcState>) -> Result<Json<StatusResponse>, StatusCode> {
    match state.mode() {
        Mode::Node => Ok(Json(StatusResponse::Node {
            height: state.ledger().tip_height(),
            latest_commitment: state.ledger().latest_commitment(),
        })),
        Mode::Wallet => {
            let wallet = state.wallet().status();
            Ok(Json(StatusResponse::Wallet {
                address: wallet.address,
                balance: wallet.balance,
            }))
        }
        Mode::Offline => Err(StatusCode::FORBIDDEN),
    }
}

async fn ledger_at_height(
    State(state): State<RpcState>,
    Path(height): Path<u64>,
) -> Result<Json<mock_ledger::LedgerEntry>, StatusCode> {
    state.ensure_node()?;
    state
        .ledger()
        .snapshot(height)
        .map(Json)
        .ok_or(StatusCode::BAD_REQUEST)
}

async fn active_validators(
    State(state): State<RpcState>,
) -> Result<Json<Vec<mock_consensus::Validator>>, StatusCode> {
    state.ensure_node()?;
    Ok(Json(state.consensus().validators()))
}

async fn submit_transaction(
    State(state): State<RpcState>,
    Json(tx): Json<TxRequest>,
) -> Result<(StatusCode, Json<TxResponse>), StatusCode> {
    state.ensure_node()?;
    let hash = state.ledger().record_transaction(&tx);
    Ok((StatusCode::ACCEPTED, Json(TxResponse { hash })))
}

impl RpcState {
    fn new(mode: Mode) -> Self {
        Self {
            inner: Arc::new(RpcStateInner {
                mode,
                ledger: mock_ledger::MockLedger::sample(),
                consensus: mock_consensus::MockConsensus::sample(),
                wallet: mock_wallet::MockWallet::sample(),
            }),
        }
    }

    fn mode(&self) -> Mode {
        self.inner.mode
    }

    fn ledger(&self) -> &mock_ledger::MockLedger {
        &self.inner.ledger
    }

    fn consensus(&self) -> &mock_consensus::MockConsensus {
        &self.inner.consensus
    }

    fn wallet(&self) -> &mock_wallet::MockWallet {
        &self.inner.wallet
    }

    fn ensure_node(&self) -> Result<(), StatusCode> {
        match self.mode() {
            Mode::Node => Ok(()),
            Mode::Wallet | Mode::Offline => Err(StatusCode::FORBIDDEN),
        }
    }
}

mod mock_ledger {
    use super::TxRequest;
    use blake3::hash;
    use serde::Serialize;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[derive(Clone)]
    pub struct MockLedger {
        entries: Arc<BTreeMap<u64, LedgerEntry>>,
    }

    #[derive(Clone, Serialize)]
    pub struct LedgerEntry {
        pub height: u64,
        pub commitments: Commitments,
        pub snapshot: Snapshot,
    }

    #[derive(Clone, Serialize)]
    pub struct Commitments {
        pub state_root: String,
        pub utxo_root: String,
    }

    #[derive(Clone, Serialize)]
    pub struct Snapshot {
        pub accounts: usize,
        pub witnesses: usize,
    }

    impl MockLedger {
        pub fn sample() -> Self {
            let mut entries = BTreeMap::new();
            entries.insert(
                1,
                LedgerEntry {
                    height: 1,
                    commitments: Commitments {
                        state_root: "state-root-1".into(),
                        utxo_root: "utxo-root-1".into(),
                    },
                    snapshot: Snapshot {
                        accounts: 64,
                        witnesses: 8,
                    },
                },
            );
            entries.insert(
                2,
                LedgerEntry {
                    height: 2,
                    commitments: Commitments {
                        state_root: "state-root-2".into(),
                        utxo_root: "utxo-root-2".into(),
                    },
                    snapshot: Snapshot {
                        accounts: 120,
                        witnesses: 16,
                    },
                },
            );
            Self {
                entries: Arc::new(entries),
            }
        }

        pub fn snapshot(&self, height: u64) -> Option<LedgerEntry> {
            self.entries.get(&height).cloned()
        }

        pub fn tip_height(&self) -> u64 {
            self.entries.keys().max().copied().unwrap_or(0)
        }

        pub fn latest_commitment(&self) -> String {
            self.entries
                .get(&self.tip_height())
                .map(|entry| entry.commitments.state_root.clone())
                .unwrap_or_else(|| "state-root-0".into())
        }

        pub fn record_transaction(&self, tx: &TxRequest) -> String {
            let payload = format!("{}:{}:{}", tx.from, tx.to, tx.amount);
            hash(payload.as_bytes()).to_hex().to_string()
        }
    }
}

mod mock_consensus {
    use serde::Serialize;
    use std::sync::Arc;

    #[derive(Clone)]
    pub struct MockConsensus {
        validators: Arc<Vec<Validator>>,
    }

    #[derive(Clone, Serialize)]
    pub struct Validator {
        pub address: String,
        pub stake: u64,
        pub voting_power: u64,
    }

    impl MockConsensus {
        pub fn sample() -> Self {
            Self {
                validators: Arc::new(vec![
                    Validator {
                        address: "validator-1".into(),
                        stake: 500,
                        voting_power: 50,
                    },
                    Validator {
                        address: "validator-2".into(),
                        stake: 400,
                        voting_power: 40,
                    },
                    Validator {
                        address: "validator-3".into(),
                        stake: 350,
                        voting_power: 35,
                    },
                ]),
            }
        }

        pub fn validators(&self) -> Vec<Validator> {
            self.validators.as_ref().clone()
        }
    }
}

mod mock_wallet {
    use serde::Serialize;
    use std::sync::Arc;

    #[derive(Clone)]
    pub struct MockWallet {
        status: Arc<WalletStatus>,
    }

    #[derive(Clone, Serialize)]
    pub struct WalletStatus {
        pub address: String,
        pub balance: u64,
    }

    impl MockWallet {
        pub fn sample() -> Self {
            Self {
                status: Arc::new(WalletStatus {
                    address: "wallet-1".into(),
                    balance: 42_000,
                }),
            }
        }

        pub fn status(&self) -> WalletStatus {
            self.status.as_ref().clone()
        }
    }
}
