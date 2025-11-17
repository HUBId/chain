#![cfg(all(
    feature = "runtime",
    feature = "backend-rpp-stark",
    feature = "vendor_electrs"
))]

use std::fs;
use std::path::PathBuf;

#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp::proofs::rpp::{
    encode_transaction_witness, AccountBalanceWitness, TransactionUtxoSnapshot, TransactionWitness,
    UtxoOutpoint,
};
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp::runtime::node::PendingTransactionSummary;
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp::runtime::types::proofs::ChainProof;
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp::runtime::types::proofs::RppStarkProof;
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp::runtime::types::transaction::Transaction as RuntimeTransaction;
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp::runtime::types::SignedTransaction;
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp::storage::state::utxo::StoredUtxo;
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp::zk::rpp_adapter::{compute_public_digest, Digest32, RppStarkHasher};
use rpp_wallet::vendor::electrs::chain::Chain;
use rpp_wallet::vendor::electrs::db::{Db, WriteBatch};
use rpp_wallet::vendor::electrs::index::Index;
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::blockdata::block::Header;
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::{
    BlockHash, Network, OutPoint, Script, Txid,
};
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction;
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp_wallet::vendor::electrs::status::ScriptHashStatus;
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp_wallet::vendor::electrs::tracker::Tracker;
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp_wallet::vendor::electrs::types::HistoryEntryWithMetadata;
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp_wallet::vendor::electrs::types::{bsl_txid, StatusDigest};
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp_wallet::vendor::electrs::types::{
    encode_ledger_script, encode_transaction_metadata, LedgerScriptPayload, RppStarkProofAudit,
    RppStarkReportSummary, ScriptHash, StoredTransactionMetadata, StoredVrfAudit,
    VrfInputDescriptor, VrfOutputDescriptor,
};
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use rpp_wallet_interface::runtime_config::{MempoolStatus, QueueWeightsConfig};
#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
use uuid::Uuid;

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

#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
fn wallet_sample_transaction_witness(
    tx_id: [u8; 32],
    utxo_index: u32,
    recipient: &str,
    amount: u128,
    fee: u64,
) -> TransactionWitness {
    let recipient_snapshot = TransactionUtxoSnapshot::new(
        UtxoOutpoint {
            tx_id,
            index: utxo_index,
        },
        StoredUtxo::new(recipient.to_string(), amount),
    );
    let sender_before =
        AccountBalanceWitness::new("sender".to_string(), amount + u128::from(fee), 1);
    let sender_after = AccountBalanceWitness::new("sender".to_string(), u128::from(fee), 2);
    let recipient_before = Some(AccountBalanceWitness::new(recipient.to_string(), 0, 0));
    let recipient_after = AccountBalanceWitness::new(recipient.to_string(), amount, 1);
    TransactionWitness::new(
        tx_id,
        fee,
        sender_before,
        sender_after,
        recipient_before,
        recipient_after,
        vec![recipient_snapshot.clone()],
        Vec::new(),
        vec![recipient_snapshot],
        vec![TransactionUtxoSnapshot::new(
            UtxoOutpoint {
                tx_id: [0xAB; 32],
                index: 0,
            },
            StoredUtxo::new(recipient.to_string(), amount),
        )],
    )
}

#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
fn wallet_hash_entry_components(witness_bytes: &[u8], digest: &Digest32) -> StatusDigest {
    let witness_len = u32::try_from(witness_bytes.len()).unwrap_or(u32::MAX);
    let mut hasher = RppStarkHasher::new();
    hasher.update(&witness_len.to_le_bytes());
    hasher.update(witness_bytes);
    hasher.update(digest.as_bytes());
    StatusDigest::from_digest(hasher.finalize())
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

#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
#[test]
fn tracker_exports_rpp_stark_metadata() {
    let dir = temp_path("metadata");
    let mut index = Index::open(&dir, Network::Regtest).expect("open index");
    let parent = index.chain().tip();
    let header = sample_header(parent, 1);

    let recipient = "wallet-recipient";
    let amount = 321u128;
    let fee = 9u64;
    let script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
        to: recipient.to_string(),
        amount,
    }));
    let tx = Transaction::new(
        vec![OutPoint::new(Txid([0x22; 32]), 0)],
        vec![script.clone()],
        Vec::new(),
    );
    let txid = bsl_txid(&tx);
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(txid.as_bytes());
    let witness = wallet_sample_transaction_witness(txid_bytes, 0, recipient, amount, fee);

    let proof = RppStarkProof::new(vec![0xAA, 0xBB], vec![0xCC, 0xDD], vec![0xEE, 0xFF]);
    let proof_bytes = serde_json::to_vec(&proof).expect("encode proof");
    let witness_bytes = encode_transaction_witness(&witness).expect("witness bytes");
    let public_digest = compute_public_digest(proof.public_inputs());
    let expected_digest = wallet_hash_entry_components(&witness_bytes, &public_digest);

    let proof_audit = RppStarkProofAudit {
        envelope: "wallet-feedface".into(),
        report: RppStarkReportSummary {
            backend: "rpp-stark".into(),
            verified: true,
            params_ok: true,
            public_ok: true,
            merkle_ok: true,
            fri_ok: true,
            composition_ok: true,
            total_bytes: proof_bytes.len() as u64,
            notes: Some("wallet-verified".into()),
            trace_query_indices: Some(vec![5, 6, 7]),
        },
    };
    let vrf_audit = StoredVrfAudit {
        input: VrfInputDescriptor {
            last_block_header: "0xwallet".into(),
            epoch: 7,
            tier_seed: "0xseed".into(),
        },
        output: VrfOutputDescriptor {
            randomness: "0xrandom".into(),
            preoutput: "0xpre".into(),
            proof: "0xproof".into(),
        },
    };

    let runtime_tx =
        RuntimeTransaction::new("sender".into(), recipient.into(), amount, fee, 42, None);
    let signed = SignedTransaction {
        id: Uuid::nil(),
        payload: runtime_tx,
        signature: "signature".into(),
        public_key: "public-key".into(),
    };
    let metadata = StoredTransactionMetadata {
        transaction: signed,
        witness: Some(witness.clone()),
        rpp_stark_proof: Some(proof_bytes.clone()),
        proof_audit: Some(proof_audit.clone()),
        vrf_audit: Some(vrf_audit.clone()),
    };
    let metadata_bytes = encode_transaction_metadata(&metadata);

    index
        .index_block(header, &[tx.clone()], Some(&vec![Some(metadata_bytes)]))
        .expect("index block with metadata");

    let tracker = Tracker::new(index);
    let scripthash = ScriptHash::new(&script);
    let mut status = ScriptHashStatus::new(scripthash);
    status
        .sync(&script, tracker.index(), tracker.chain(), None)
        .expect("sync status");

    let digest = tracker
        .get_status_digest(&status)
        .expect("status digest computed");
    assert_eq!(digest, expected_digest);

    let history: Vec<HistoryEntryWithMetadata> = tracker.get_history_with_digests(&status);
    assert_eq!(history.len(), 1);
    let entry = &history[0];
    assert_eq!(entry.entry.txid, txid);
    assert_eq!(entry.digest, Some(expected_digest));
    assert_eq!(entry.proof, Some(proof_audit.clone()));
    assert_eq!(entry.vrf, Some(vrf_audit.clone()));

    let envelopes = tracker.get_proof_envelopes(&status);
    assert_eq!(envelopes, vec![Some(proof_audit.envelope.clone())]);

    let vrf_records = tracker.get_vrf_audits(&status);
    assert_eq!(vrf_records, vec![Some(vrf_audit)]);
}

#[cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]
#[test]
fn tracker_applies_mempool_delta_with_digest_fallback() {
    let dir = temp_path("mempool-delta");
    let index = Index::open(&dir, Network::Regtest).expect("open index");
    let tracker = Tracker::new(index);

    let recipient = "delta-recipient";
    let amount = 55u128;
    let fee = 4u64;
    let script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
        to: recipient.to_string(),
        amount,
    }));
    let scripthash = ScriptHash::new(&script);

    let txid = Txid([0x42; 32]);
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(txid.as_bytes());
    let witness = wallet_sample_transaction_witness(txid_bytes, 0, recipient, amount, fee);

    let proof = RppStarkProof::new(vec![0x11, 0x22], vec![0x33, 0x44], vec![0x55, 0x66]);
    let digest = compute_public_digest(proof.public_inputs());
    let witness_bytes = encode_transaction_witness(&witness).expect("encode witness");
    let expected_digest = wallet_hash_entry_components(&witness_bytes, &digest);

    let pending = PendingTransactionSummary {
        hash: hex::encode(txid.as_bytes()),
        from: "sender".into(),
        to: recipient.into(),
        amount,
        fee,
        nonce: 9,
        proof: Some(ChainProof::RppStark(proof)),
        witness: Some(witness),
        proof_payload: None,
        public_inputs_digest: None,
    };

    let mempool = MempoolStatus {
        transactions: vec![serde_json::to_value(&pending).expect("serialize pending summary")],
        identities: Vec::new(),
        votes: Vec::new(),
        uptime_proofs: Vec::new(),
        queue_weights: QueueWeightsConfig::default(),
    };

    let mut status = ScriptHashStatus::new(scripthash);
    status
        .sync(&script, tracker.index(), tracker.chain(), Some(&mempool))
        .expect("sync status with mempool");

    assert_eq!(status.mempool_delta(), amount as i64);

    let history = tracker.get_history_with_digests(&status);
    assert_eq!(history.len(), 1, "one mempool entry expected");
    let entry = &history[0];
    assert_eq!(entry.entry.txid, txid);
    assert_eq!(entry.digest, Some(expected_digest));
}
