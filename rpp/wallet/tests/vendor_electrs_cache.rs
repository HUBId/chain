#![cfg(feature = "vendor_electrs")]

use std::fs;
use std::path::PathBuf;

use rpp_wallet::vendor::electrs::cache::{Cache, CacheTelemetry};
use rpp_wallet::vendor::electrs::firewood_adapter::FirewoodAdapter;
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::{OutPoint, Script, Txid};
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction;
use rpp_wallet::vendor::electrs::types::{self, serialize_transaction};

const WARMUP_PREFIX: &[u8] = b"cache:test:";

fn temp_path(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("rpp-wallet-electrs-cache-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn sample_transaction(tag: u8) -> (Txid, Transaction) {
    let txid = Txid([tag; 32]);
    let input = OutPoint::new(txid, 0);
    let output = Script::new(vec![tag, tag.wrapping_add(1)]);
    let tx = Transaction::new(vec![input], vec![output], vec![tag]);
    (txid, tx)
}

#[test]
fn cache_records_hits_and_misses() {
    let telemetry = CacheTelemetry::enabled();
    let cache = Cache::new(telemetry.clone());
    let (txid, tx) = sample_transaction(0xAB);
    let serialized = serialize_transaction(&tx);

    assert!(cache.add_transaction(txid, &tx));
    assert!(!cache.add_transaction(txid, &tx));

    let hit_len = cache
        .get_transaction(&txid, |bytes| bytes.len())
        .expect("cached transaction");
    assert_eq!(hit_len, serialized.len());

    let missing = Txid([0xCD; 32]);
    assert!(cache
        .get_transaction(&missing, |bytes| bytes.len())
        .is_none());

    let snapshot = cache.telemetry().snapshot();
    assert_eq!(snapshot.hits, 1);
    assert_eq!(snapshot.misses, 1);
    assert_eq!(snapshot.entries, 1);
    assert_eq!(snapshot.stored_bytes, serialized.len() as u64);
    assert_eq!(snapshot.largest_entry_bytes, serialized.len() as u64);
}

#[test]
fn cache_warmup_roundtrip_via_firewood() {
    let dir = temp_path("warmup");
    let mut store = FirewoodAdapter::open(&dir).expect("open firewood");

    let cache = Cache::new(CacheTelemetry::enabled());
    let (txid_one, tx_one) = sample_transaction(0x11);
    let (txid_two, tx_two) = sample_transaction(0x22);

    cache.add_transaction(txid_one, &tx_one);
    cache.add_transaction(txid_two, &tx_two);

    let persisted = cache
        .persist_warmup(&mut store, WARMUP_PREFIX)
        .expect("persist warmup");
    assert_eq!(persisted, 2);

    let persist_metrics = cache.telemetry().snapshot();
    let expected_total = serialize_transaction(&tx_one).len() + serialize_transaction(&tx_two).len();
    assert_eq!(persist_metrics.warmup_persisted, 2);
    assert_eq!(persist_metrics.warmup_persisted_bytes, expected_total as u64);

    drop(store);
    let store = FirewoodAdapter::open(&dir).expect("reopen firewood");

    let warmed = Cache::new(CacheTelemetry::enabled());
    let restored = warmed
        .warm_from_firewood(&store, WARMUP_PREFIX)
        .expect("warm cache");
    assert_eq!(restored, 2);
    assert_eq!(warmed.len(), 2);

    let deserialized = warmed
        .get_transaction(&txid_one, |bytes| types::deserialize_transaction(bytes))
        .and_then(|result| result.map(|(tx, _)| tx));
    assert!(deserialized.is_some());

    let warm_metrics = warmed.telemetry().snapshot();
    assert_eq!(warm_metrics.warmup_loaded, 2);
    assert_eq!(warm_metrics.entries, 2);
    assert_eq!(warm_metrics.stored_bytes, expected_total as u64);
}
