#![cfg(feature = "vendor_electrs")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use rpp::consensus::BftVoteKind;
use rpp::runtime::node::{
    PendingIdentitySummary, PendingTransactionSummary, PendingUptimeSummary, PendingVoteSummary,
};
use rpp_wallet::vendor::electrs::mempool::{Mempool, MempoolSyncUpdate};
use rpp_wallet::vendor::electrs::metrics::Metrics;
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::{Script, Txid};
use rpp_wallet::vendor::electrs::types::ScriptHash;
use rpp_wallet_interface::runtime_config::{MempoolStatus, QueueWeightsConfig};
use serde::Serialize;
use serde_json::Value;

fn metrics() -> Metrics {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    Metrics::new(addr).expect("construct metrics")
}

fn sample_identity(tag: u8) -> PendingIdentitySummary {
    PendingIdentitySummary {
        wallet_addr: format!("wallet-{tag:02x}"),
        commitment: format!("commitment-{tag:02x}"),
        epoch_nonce: format!("nonce-{tag:02x}"),
        state_root: format!("state-{tag:02x}"),
        identity_root: format!("identity-{tag:02x}"),
        vrf_tag: format!("vrf-{tag:02x}"),
        attested_votes: usize::from(tag),
        gossip_confirmations: usize::from(tag) + 1,
    }
}

fn sample_vote(tag: u8) -> PendingVoteSummary {
    PendingVoteSummary {
        hash: format!("vote-hash-{tag:02x}"),
        voter: format!("voter-{tag:02x}"),
        height: u64::from(tag),
        round: u64::from(tag) + 1,
        block_hash: format!("block-{tag:02x}"),
        kind: if tag % 2 == 0 {
            BftVoteKind::PreVote
        } else {
            BftVoteKind::PreCommit
        },
    }
}

fn sample_uptime(tag: u8) -> PendingUptimeSummary {
    PendingUptimeSummary {
        identity: format!("uptime-{tag:02x}"),
        window_start: u64::from(tag) * 10,
        window_end: u64::from(tag) * 10 + 5,
        credited_hours: u64::from(tag),
    }
}

fn sample_transaction(tag: u8, fee: u64) -> PendingTransactionSummary {
    PendingTransactionSummary {
        hash: hex::encode([tag; 32]),
        from: format!("from-{tag:02x}"),
        to: format!("to-{tag:02x}"),
        amount: u128::from(tag),
        fee,
        nonce: u64::from(tag),
        proof: None,
        witness: None,
        proof_payload: None,
        #[cfg(feature = "backend-rpp-stark")]
        public_inputs_digest: None,
    }
}

fn encode_summary<T: Serialize>(summary: T) -> Value {
    serde_json::to_value(summary).expect("serialize pending summary")
}

fn make_snapshot(weights: QueueWeightsConfig, fees: &[(u8, u64)]) -> MempoolStatus {
    let transactions = fees
        .iter()
        .map(|(tag, fee)| encode_summary(sample_transaction(*tag, *fee)))
        .collect();
    MempoolStatus {
        transactions,
        identities: vec![encode_summary(sample_identity(0x11))],
        votes: vec![encode_summary(sample_vote(0x22))],
        uptime_proofs: vec![encode_summary(sample_uptime(0x33))],
        queue_weights: weights,
    }
}

#[test]
fn mempool_applies_snapshot_updates_entries() {
    let metrics = metrics();
    let mut mempool = Mempool::new(&metrics);

    let mut weights = QueueWeightsConfig::default();
    weights.priority = 0.6;
    weights.fee = 0.4;

    let snapshot = make_snapshot(weights.clone(), &[(0x10, 50), (0x20, 150)]);
    mempool.apply_sync_update(MempoolSyncUpdate::from_snapshot(snapshot.clone()));

    let stored = mempool.snapshot().expect("stored snapshot");
    assert_eq!(stored.transactions.len(), 2);
    assert_eq!(stored.identities.len(), 1);
    assert_eq!(stored.votes.len(), 1);
    assert_eq!(stored.uptime_proofs.len(), 1);

    let txid = Txid::from_bytes([0x10; 32]);
    let entry = mempool.get(&txid).expect("entry present");
    let expected_hash = ScriptHash::new(&Script::new(b"to-10".to_vec()));
    assert_eq!(entry.scripthash, expected_hash);
    assert_eq!(entry.queue_weight.priority, weights.priority);

    let histogram = mempool.histogram();
    assert!((histogram.priority() - 1.2).abs() < f64::EPSILON);
    assert!((histogram.fee() - 80.0).abs() < f64::EPSILON);
    assert_eq!(histogram.total_entries(), 2);
}

#[test]
fn mempool_rebuilds_histogram_on_new_snapshot() {
    let metrics = metrics();
    let mut mempool = Mempool::new(&metrics);

    let first = make_snapshot(QueueWeightsConfig::default(), &[(0xAA, 25)]);
    mempool.apply_sync_update(MempoolSyncUpdate::from_snapshot(first));

    let mut weights = QueueWeightsConfig::default();
    weights.priority = 0.3;
    weights.fee = 0.7;
    let second = make_snapshot(weights.clone(), &[(0xBB, 200)]);
    mempool.apply_sync_update(MempoolSyncUpdate::from_snapshot(second));

    let histogram = mempool.histogram();
    assert!((histogram.priority() - weights.priority).abs() < f64::EPSILON);
    assert!((histogram.fee() - 140.0).abs() < f64::EPSILON);
    assert_eq!(histogram.total_entries(), 1);

    let txid = Txid::from_bytes([0xBB; 32]);
    assert!(mempool.get(&txid).is_some());
    let missing = Txid::from_bytes([0xAA; 32]);
    assert!(mempool.get(&missing).is_none());
}
