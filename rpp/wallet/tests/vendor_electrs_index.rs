use std::fs;
use std::path::PathBuf;

use rpp_wallet::vendor::electrs::chain::Chain;
use rpp_wallet::vendor::electrs::db::{Db, WriteBatch};
use rpp_wallet::vendor::electrs::index::Index;
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::blockdata::block::Header;
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, Network, OutPoint, Script, Txid};
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction;

fn temp_path(name: &str) -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!("rpp-wallet-electrs-{name}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn sample_header(parent: BlockHash, height: u32) -> Header {
    Header::new(
        parent,
        [height as u8; 32],
        [height as u8 + 1; 32],
        [height as u8 + 2; 32],
        [height as u8 + 3; 64],
        [height as u8 + 4; 32],
        height as u64,
    )
}

fn sample_transaction(script: Script, memo: Vec<u8>) -> Transaction {
    Transaction::new(vec![OutPoint::new(Txid([1; 32]), 0)], vec![script], memo)
}

#[test]
fn firewood_snapshot_roundtrip() {
    let dir = temp_path("snapshot");
    let mut db = Db::open(&dir).expect("open db");
    let genesis = Chain::new(Network::Regtest).tip();
    let header = sample_header(genesis, 1);

    let mut batch = WriteBatch::default();
    let header_row = rpp_wallet::vendor::electrs::types::HeaderRow::new(header.clone());
    batch.put_header(1, &header_row);
    batch.put_block(1, &vec![1, 2, 3]);
    batch.set_tip(1, header.block_hash());
    db.write(batch).expect("write batch");

    let reopened = Db::open(&dir).expect("reopen db");
    let tip = reopened.read_tip().expect("tip").expect("tip set");
    assert_eq!(tip.height(), 1);
    let headers = reopened.load_headers().expect("load headers");
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[0].0, 1);
    assert_eq!(headers[0].1.block_hash(), header.block_hash());
}

#[test]
fn index_sample_chain() {
    let dir = temp_path("index");
    let mut index = Index::open(&dir, Network::Regtest).expect("open index");
    let genesis = index.chain().tip();

    let header1 = sample_header(genesis, 1);
    let tx1 = sample_transaction(Script::new(vec![0xAA, 0xBB]), b"memo-1".to_vec());
    index
        .index_block(header1.clone(), &[tx1.clone()], None)
        .expect("index block");

    let header2 = sample_header(header1.block_hash(), 2);
    let tx2 = sample_transaction(Script::new(vec![0xAA, 0xBB]), b"memo-2".to_vec());
    index
        .index_block(header2.clone(), &[tx2.clone()], None)
        .expect("index block 2");

    assert_eq!(index.chain().height(), 2);
    assert_eq!(index.chain().tip(), header2.block_hash());

    let script = Script::new(vec![0xAA, 0xBB]);
    let history = index.script_history(&script);
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].0, 1);
    assert_eq!(history[1].0, 2);
}
