#![cfg(all(feature = "backend-rpp-stark", feature = "vendor_electrs"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use serde::Deserialize;
use tempfile::TempDir;
use uuid::Uuid;

use rpp::errors::{ChainError, ChainResult};
use rpp::proofs::rpp::{
    encode_transaction_witness, AccountBalanceWitness, TransactionUtxoSnapshot, TransactionWitness,
    UtxoOutpoint,
};
use rpp::runtime::config::NodeConfig;
use rpp::runtime::node::Node;
use rpp::runtime::orchestration::PipelineOrchestrator;
use rpp::runtime::sync::{PayloadProvider, ReconstructionRequest, RuntimeRecursiveProofVerifier};
use rpp::runtime::types::{BlockPayload, SignedTransaction};
use rpp::storage::state::utxo::StoredUtxo;
use rpp::zk::rpp_adapter::{compute_public_digest, Digest32, RppStarkHasher};

use rpp_wallet::config::{
    CacheConfig, ElectrsConfig, FeatureGates, NetworkSelection, P2pConfig, TrackerConfig,
};
use rpp_wallet::vendor::electrs::firewood_adapter::RuntimeAdapters;
use rpp_wallet::vendor::electrs::init::initialize;
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::blockdata::block::Header;
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, OutPoint, Script, Txid};
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction;
use rpp_wallet::vendor::electrs::status::ScriptHashStatus;
use rpp_wallet::vendor::electrs::types::HistoryEntryWithMetadata;
use rpp_wallet::vendor::electrs::types::{
    bsl_txid, encode_ledger_memo, encode_ledger_script, encode_transaction_metadata,
    LedgerMemoPayload, LedgerScriptPayload, RppStarkProofAudit, RppStarkReportSummary, ScriptHash,
    StatusDigest, StoredTransactionMetadata, StoredVrfAudit, VrfInputDescriptor,
    VrfOutputDescriptor,
};

use rpp::runtime::types::proofs::RppStarkProof;

#[derive(Debug, Deserialize)]
struct WalletSection {
    network: NetworkSelection,
    runtime: bool,
    tracker: bool,
}

#[derive(Debug, Deserialize)]
struct BlockSection {
    count: u32,
    recipient: String,
    amount: u128,
    fee: u64,
    memo: String,
}

#[derive(Debug, Deserialize)]
struct ProofSection {
    envelope: String,
    report_notes: String,
}

#[derive(Debug, Deserialize)]
struct WalletTrackerScenario {
    wallet: WalletSection,
    blocks: BlockSection,
    proof: ProofSection,
}

impl WalletTrackerScenario {
    fn load_from_disk() -> Result<Self> {
        let path = scenario_path();
        let payload = fs::read_to_string(path)?;
        Ok(toml::from_str(&payload)?)
    }
}

#[test]
fn vendor_electrs_tracker_end_to_end() -> Result<()> {
    let scenario = WalletTrackerScenario::load_from_disk()?;
    assert_eq!(
        scenario.blocks.count, 1,
        "scenario is defined for a single demo block"
    );

    let temp = TempDir::new()?;
    let firewood_dir = temp.path().join("firewood");
    let index_dir = temp.path().join("index");
    fs::create_dir_all(&firewood_dir)?;
    fs::create_dir_all(&index_dir)?;

    let runtime = build_runtime_adapters(temp.path());
    let config = ElectrsConfig {
        network: scenario.wallet.network,
        features: FeatureGates {
            runtime: scenario.wallet.runtime,
            tracker: scenario.wallet.tracker,
        },
        cache: CacheConfig::default(),
        tracker: TrackerConfig::default(),
        p2p: P2pConfig::default(),
    };

    let mut handles = initialize(&config, &firewood_dir, &index_dir, Some(runtime))?;

    let mut tracker = handles.tracker.take().expect("tracker enabled in scenario");
    let daemon = handles.daemon.take().expect("runtime enabled in scenario");

    assert_eq!(
        tracker.chain().height(),
        0,
        "fresh tracker starts at genesis"
    );
    assert!(
        daemon.tip()?.as_bytes().len() == 32,
        "daemon exposes tip hash"
    );

    let parent = tracker.chain().tip();
    let header = sample_header(parent, 1);
    let (script, tx, metadata_bytes, expected_digest, proof_audit, vrf_audit) =
        build_transaction_bundle(&scenario);

    let block_metadata = vec![Some(metadata_bytes.clone())];
    tracker
        .index_mut()
        .index_block(header.clone(), &[tx.clone()], Some(&block_metadata))?;

    assert_eq!(tracker.chain().height(), scenario.blocks.count as usize);

    let scripthash = ScriptHash::new(&script);
    let mut status = ScriptHashStatus::new(scripthash);
    assert!(
        tracker.update_scripthash_status(&mut status, &script)?,
        "status digest should change after indexing"
    );

    let balance = tracker.get_balance(&status);
    assert!(balance.confirmed >= scenario.blocks.amount as i64);

    let unspent = tracker.get_unspent(&status);
    assert_eq!(unspent.len(), 1, "one UTXO expected after deposit block");

    let digest = tracker
        .get_status_digest(&status)
        .expect("status digest produced");
    assert_eq!(digest, expected_digest, "digest matches proof witness");

    let history: Vec<HistoryEntryWithMetadata> = tracker.get_history_with_digests(&status);
    assert_eq!(history.len(), scenario.blocks.count as usize);
    let entry = &history[0];
    assert_eq!(entry.digest, Some(expected_digest));
    let audit = entry.proof.as_ref().expect("proof metadata present");
    assert_eq!(audit.envelope, scenario.proof.envelope);
    assert_eq!(
        audit.report.notes.as_ref().expect("report carries notes"),
        &scenario.proof.report_notes
    );
    let vrf = entry.vrf.as_ref().expect("vrf metadata present");
    assert_eq!(vrf.output.randomness, "0xrandom");

    let envelopes = tracker.get_proof_envelopes(&status);
    assert_eq!(envelopes, vec![Some(scenario.proof.envelope.clone())]);

    let vrf_audits = tracker.get_vrf_audits(&status);
    assert_eq!(vrf_audits, vec![Some(vrf_audit)]);

    tracker.status()?;

    Ok(())
}

fn scenario_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios/wallet_tracker_rpp.toml")
}

fn build_transaction_bundle(
    scenario: &WalletTrackerScenario,
) -> (
    Script,
    Transaction,
    Vec<u8>,
    StatusDigest,
    RppStarkProofAudit,
    StoredVrfAudit,
) {
    let script_payload = LedgerScriptPayload::Recipient {
        to: scenario.blocks.recipient.clone(),
        amount: scenario.blocks.amount,
    };
    let script = Script::new(encode_ledger_script(&script_payload));
    let memo_payload = LedgerMemoPayload {
        nonce: 42,
        memo: Some(scenario.blocks.memo.clone()),
        signature: "wallet-signature".into(),
        public_key: "wallet-pk".into(),
    };
    let memo = encode_ledger_memo(&memo_payload);
    let tx = Transaction::new(
        vec![OutPoint::new(Txid([0x22; 32]), 0)],
        vec![script.clone()],
        memo,
    );
    let txid = bsl_txid(&tx);
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(txid.as_bytes());

    let witness = wallet_sample_transaction_witness(
        txid_bytes,
        &scenario.blocks.recipient,
        scenario.blocks.amount,
        scenario.blocks.fee,
    );

    let proof = RppStarkProof::new(vec![0xAA, 0xBB], vec![0xCC, 0xDD], vec![0xEE, 0xFF]);
    let proof_bytes = serde_json::to_vec(&proof).expect("encode proof");
    let witness_bytes = encode_transaction_witness(&witness).expect("witness bytes");
    let public_digest = compute_public_digest(proof.public_inputs());
    let expected_digest = wallet_hash_entry_components(&witness_bytes, &public_digest);

    let proof_audit = RppStarkProofAudit {
        envelope: scenario.proof.envelope.clone(),
        report: RppStarkReportSummary {
            backend: "rpp-stark".into(),
            verified: true,
            params_ok: true,
            public_ok: true,
            merkle_ok: true,
            fri_ok: true,
            composition_ok: true,
            total_bytes: proof_bytes.len() as u64,
            notes: Some(scenario.proof.report_notes.clone()),
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

    let runtime_tx = rpp::runtime::types::transaction::Transaction::new(
        "sender".into(),
        scenario.blocks.recipient.clone(),
        scenario.blocks.amount,
        scenario.blocks.fee,
        42,
        None,
    );
    let signed = SignedTransaction {
        id: Uuid::nil(),
        payload: runtime_tx,
        signature: "signature".into(),
        public_key: "public-key".into(),
    };
    let metadata = StoredTransactionMetadata {
        transaction: signed,
        witness: Some(witness),
        rpp_stark_proof: Some(proof_bytes),
        proof_audit: Some(proof_audit.clone()),
        vrf_audit: Some(vrf_audit.clone()),
    };
    let metadata_bytes = encode_transaction_metadata(&metadata);

    (
        script,
        tx,
        metadata_bytes,
        expected_digest,
        proof_audit,
        vrf_audit,
    )
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

fn wallet_sample_transaction_witness(
    tx_id: [u8; 32],
    recipient: &str,
    amount: u128,
    fee: u64,
) -> TransactionWitness {
    let recipient_snapshot = TransactionUtxoSnapshot::new(
        UtxoOutpoint { tx_id, index: 0 },
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

fn wallet_hash_entry_components(witness_bytes: &[u8], digest: &Digest32) -> StatusDigest {
    let witness_len = u32::try_from(witness_bytes.len()).unwrap_or(u32::MAX);
    let mut hasher = RppStarkHasher::new();
    hasher.update(&witness_len.to_le_bytes());
    hasher.update(witness_bytes);
    hasher.update(digest.as_bytes());
    StatusDigest::from_digest(hasher.finalize())
}

fn build_runtime_adapters(base: &Path) -> RuntimeAdapters {
    let mut config = NodeConfig::default();
    config.data_dir = base.join("node/data");
    config.key_path = base.join("node/keys/node.toml");
    config.p2p_key_path = base.join("node/keys/p2p.toml");
    config.vrf_key_path = base.join("node/keys/vrf.toml");
    config.snapshot_dir = base.join("node/snapshots");
    config.proof_cache_dir = base.join("node/proofs");

    let node = Node::new(config).expect("node");
    let node_handle = node.handle();
    let storage = node_handle.storage();

    let (orchestrator, _shutdown) = PipelineOrchestrator::new(node_handle.clone(), None);
    let provider = Arc::new(DummyPayloadProvider::default());
    let proof_verifier = Arc::new(RuntimeRecursiveProofVerifier::default());

    RuntimeAdapters::new(
        Arc::new(storage.clone()),
        node_handle,
        orchestrator,
        provider,
        proof_verifier,
    )
}

#[derive(Default)]
struct DummyPayloadProvider;

impl PayloadProvider for DummyPayloadProvider {
    fn fetch_payload(&self, request: &ReconstructionRequest) -> ChainResult<BlockPayload> {
        Err(ChainError::Config(format!(
            "no payload available for height {}",
            request.height
        )))
    }
}
