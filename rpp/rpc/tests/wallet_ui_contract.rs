#![cfg(feature = "wallet-integration")]

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;

use reqwest::{Client, StatusCode};
use serde_json::to_value;
use tokio::sync::oneshot;

use rpp::api::{self, ApiContext};
use rpp::runtime::config::{NetworkLimitsConfig, NetworkTlsConfig};
use rpp::runtime::RuntimeMode;
use rpp_chain::interfaces::{
    WalletUiHistoryContract, WalletUiNodeContract, WalletUiReceiveContract, WalletUiSendContract,
    WALLET_UI_HISTORY_CONTRACT, WALLET_UI_NODE_CONTRACT, WALLET_UI_RECEIVE_CONTRACT,
    WALLET_UI_SEND_CONTRACT,
};
use rpp_chain::reputation::Tier;
use rpp_chain::types::Address;
use rpp_chain::wallet::{
    ConsensusReceipt, HistoryEntry, HistoryStatus, NodeTabMetrics, ReceiveTabAddress, SendPreview,
};

use parking_lot::RwLock;

fn sample_address(label: &str) -> Address {
    format!("rpp_{label}")
}

fn sample_history_entry() -> HistoryEntry {
    HistoryEntry {
        tx_hash: "0xdeadbeef".into(),
        transaction: None,
        pending_summary: None,
        status: HistoryStatus::Confirmed {
            height: 42,
            timestamp: 1_700_000_000,
        },
        reputation_delta: 5,
        status_digest: None,
        proof_envelope: None,
        #[cfg(feature = "backend-rpp-stark")]
        vrf_audit: None,
        double_spend: None,
        conflict: None,
        pipeline: None,
    }
}

fn random_loopback() -> SocketAddr {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr
}

async fn spawn_server(
    addr: SocketAddr,
    mut limits: NetworkLimitsConfig,
) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    limits.per_ip_token_bucket.enabled = true;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (ready_tx, ready_rx) = oneshot::channel();
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
    );

    let handle = tokio::spawn(async move {
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };
        let _ = api::serve_with_shutdown(
            context,
            addr,
            None,
            None,
            limits,
            NetworkTlsConfig::default(),
            shutdown,
            Some(ready_tx),
        )
        .await;
    });

    ready_rx.await.expect("server ready").expect("server start");

    (shutdown_tx, handle)
}

#[test]
fn history_contract_is_versioned() {
    let contract = WalletUiHistoryContract {
        version: WALLET_UI_HISTORY_CONTRACT,
        entries: vec![sample_history_entry()],
        #[cfg(feature = "vendor_electrs")]
        script_metadata: None,
        #[cfg(feature = "vendor_electrs")]
        tracker: None,
    };

    let value = to_value(&contract).expect("serialize history contract");
    assert_eq!(value["version"], WALLET_UI_HISTORY_CONTRACT);
    assert_eq!(
        value["entries"].as_array().map(|entries| entries.len()),
        Some(1)
    );
}

#[test]
fn history_contract_serializes_status_fields() {
    let contract = WalletUiHistoryContract {
        version: WALLET_UI_HISTORY_CONTRACT,
        entries: vec![sample_history_entry()],
        #[cfg(feature = "vendor_electrs")]
        script_metadata: None,
        #[cfg(feature = "vendor_electrs")]
        tracker: None,
    };

    let value = to_value(&contract).expect("serialize history contract");
    let entry = &value["entries"][0];
    assert_eq!(entry["tx_hash"], "0xdeadbeef");
    assert_eq!(entry["reputation_delta"], 5);
    assert!(entry["status"]["Confirmed"].is_object());
}

#[test]
fn send_contract_wraps_preview() {
    let preview = SendPreview {
        from: sample_address("from"),
        to: sample_address("to"),
        amount: 2_500,
        fee: 25,
        memo: Some("payment".into()),
        nonce: 3,
        balance_before: 10_000,
        balance_after: 7_475,
    };
    let contract = WalletUiSendContract {
        version: WALLET_UI_SEND_CONTRACT,
        preview,
    };

    let value = to_value(&contract).expect("serialize send contract");
    assert_eq!(value["version"], WALLET_UI_SEND_CONTRACT);
    assert_eq!(value["preview"]["fee"], 25);
}

#[test]
fn send_contract_includes_recipient_and_amount() {
    let preview = SendPreview {
        from: sample_address("from"),
        to: sample_address("to"),
        amount: 2_500,
        fee: 25,
        memo: Some("payment".into()),
        nonce: 3,
        balance_before: 10_000,
        balance_after: 7_475,
    };
    let contract = WalletUiSendContract {
        version: WALLET_UI_SEND_CONTRACT,
        preview,
    };

    let value = to_value(&contract).expect("serialize send contract");
    assert_eq!(value["preview"]["from"], "rpp_from");
    assert_eq!(value["preview"]["to"], "rpp_to");
    assert_eq!(value["preview"]["amount"], 2_500);
}

#[test]
fn receive_contract_lists_addresses() {
    let addresses = vec![
        ReceiveTabAddress {
            derivation_index: 0,
            address: sample_address("receive0"),
        },
        ReceiveTabAddress {
            derivation_index: 1,
            address: sample_address("receive1"),
        },
    ];
    let contract = WalletUiReceiveContract {
        version: WALLET_UI_RECEIVE_CONTRACT,
        addresses,
    };

    let value = to_value(&contract).expect("serialize receive contract");
    assert_eq!(value["version"], WALLET_UI_RECEIVE_CONTRACT);
    assert_eq!(
        value["addresses"].as_array().map(|items| items.len()),
        Some(2)
    );
}

#[test]
fn receive_contract_serializes_indices() {
    let addresses = vec![ReceiveTabAddress {
        derivation_index: 7,
        address: sample_address("receive7"),
    }];
    let contract = WalletUiReceiveContract {
        version: WALLET_UI_RECEIVE_CONTRACT,
        addresses,
    };

    let value = to_value(&contract).expect("serialize receive contract");
    assert_eq!(value["addresses"][0]["derivation_index"], 7);
    assert_eq!(value["addresses"][0]["address"], "rpp_receive7");
}

#[test]
fn node_contract_exposes_metrics() {
    let metrics = NodeTabMetrics {
        reputation_score: 92.5,
        tier: Tier::Tl4,
        uptime_hours: 128,
        latest_block_height: 1_024,
        latest_block_hash: Some("0xabc".into()),
        total_blocks: 10_240,
        slashing_alerts: Vec::new(),
        pipeline_errors: Vec::new(),
    };
    let receipt = ConsensusReceipt {
        height: 1_024,
        block_hash: "0xabc".into(),
        proposer: sample_address("validator"),
        round: 7,
        total_power: "1000".into(),
        quorum_threshold: "667".into(),
        pre_vote_power: "700".into(),
        pre_commit_power: "690".into(),
        commit_power: "680".into(),
        observers: 3,
        quorum_reached: true,
    };
    let contract = WalletUiNodeContract {
        version: WALLET_UI_NODE_CONTRACT,
        metrics,
        consensus: Some(receipt),
        pipeline: None,
    };

    let value = to_value(&contract).expect("serialize node contract");
    assert_eq!(value["version"], WALLET_UI_NODE_CONTRACT);
    assert_eq!(value["metrics"]["tier"], "Tl4");
    assert!(value["consensus"].is_object());
}

#[test]
fn node_contract_exposes_consensus_height() {
    let metrics = NodeTabMetrics {
        reputation_score: 50.0,
        tier: Tier::Tl3,
        uptime_hours: 64,
        latest_block_height: 512,
        latest_block_hash: Some("0xdef".into()),
        total_blocks: 6_144,
        slashing_alerts: Vec::new(),
        pipeline_errors: Vec::new(),
    };
    let receipt = ConsensusReceipt {
        height: 512,
        block_hash: "0xdef".into(),
        proposer: sample_address("validator"),
        round: 1,
        total_power: "1000".into(),
        quorum_threshold: "667".into(),
        pre_vote_power: "700".into(),
        pre_commit_power: "690".into(),
        commit_power: "680".into(),
        observers: 2,
        quorum_reached: true,
    };
    let contract = WalletUiNodeContract {
        version: WALLET_UI_NODE_CONTRACT,
        metrics,
        consensus: Some(receipt),
        pipeline: None,
    };

    let value = to_value(&contract).expect("serialize node contract");
    assert_eq!(value["consensus"]["height"], 512);
    assert_eq!(value["metrics"]["latest_block_height"], 512);
}

#[tokio::test]
async fn wallet_ui_rate_limit_returns_plain_text() {
    let addr = random_loopback();
    let mut limits = NetworkLimitsConfig::default();
    limits.per_ip_token_bucket.burst = 1;
    limits.per_ip_token_bucket.replenish_per_minute = 1;

    let (shutdown_tx, handle) = spawn_server(addr, limits).await;

    let client = Client::builder().build().expect("client");
    let url = format!("http://{addr}/wallet/ui/history");

    let _first = client.get(&url).send().await.expect("first request");
    let second = client.get(&url).send().await.expect("second request");

    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let headers = second.headers();
    assert_eq!(
        headers
            .get("x-ratelimit-limit")
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    assert_eq!(
        headers
            .get("x-ratelimit-remaining")
            .and_then(|value| value.to_str().ok()),
        Some("0")
    );
    let reset = headers
        .get("x-ratelimit-reset")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .expect("reset header present");
    assert!(reset >= 1 && reset <= 120);
    assert_eq!(
        second.text().await.expect("read body"),
        "rate limit exceeded"
    );

    let _ = shutdown_tx.send(());
    let _ = handle.await;
}
