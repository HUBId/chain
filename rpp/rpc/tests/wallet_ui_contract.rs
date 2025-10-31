use serde_json::to_value;

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
    assert_eq!(value["entries"].as_array().map(|entries| entries.len()), Some(1));
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
    assert_eq!(value["addresses"].as_array().map(|items| items.len()), Some(2));
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
