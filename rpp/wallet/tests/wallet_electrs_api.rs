#![cfg(all(feature = "vendor_electrs", feature = "backend-rpp-stark"))]

use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use parking_lot::RwLock;
use reqwest::Client;
use serde::Deserialize;
use tempfile::TempDir;
use tokio::time::sleep;
use uuid::Uuid;

use rpp::api::{self, ApiContext};
use rpp::config::NodeConfig;
use rpp::crypto::{load_keypair, sign_message};
use rpp::interfaces::WalletHistoryResponse;
use rpp::orchestration::PipelineOrchestrator;
use rpp::proofs::rpp::{
    encode_transaction_witness, AccountBalanceWitness, TransactionUtxoSnapshot, TransactionWitness,
    UtxoOutpoint,
};
use rpp::runtime::config::FeatureGates as NodeFeatureGates;
use rpp::runtime::node::Node;
use rpp::runtime::sync::{PayloadProvider, ReconstructionRequest, RuntimeRecursiveProofVerifier};
use rpp::runtime::types::proofs::{ChainProof, RppStarkProof};
use rpp::runtime::types::transaction::SignedTransaction;
use rpp::runtime::types::transaction::Transaction as RuntimeTransaction;
use rpp::runtime::types::TransactionProofBundle;
use rpp::runtime::RuntimeMetrics;
use rpp::runtime::{RuntimeMetrics, RuntimeMode};
use rpp::storage::state::utxo::StoredUtxo;
use rpp::wallet::config::{
    CacheConfig, ElectrsConfig, FeatureGates, NetworkSelection as WalletNetworkSelection,
    P2pConfig, TrackerConfig,
};
use rpp::wallet::ui::tabs::history::{HistoryEntry, HistoryStatus};
use rpp::wallet::ui::wallet::{TrackerState, Wallet};
use rpp::wallet::vendor::electrs::firewood_adapter::RuntimeAdapters;
use rpp::wallet::vendor::electrs::init::initialize;
use rpp::wallet::vendor::electrs::rpp_ledger::bitcoin::blockdata::block::Header;
use rpp::wallet::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, OutPoint, Script, Txid};
use rpp::wallet::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction as LedgerTransaction;
use rpp::wallet::vendor::electrs::types::{
    bsl_txid, encode_ledger_memo, encode_ledger_script, encode_transaction_metadata,
    LedgerMemoPayload, LedgerScriptPayload, RppStarkProofAudit, RppStarkReportSummary,
    StatusDigest, StoredTransactionMetadata, StoredVrfAudit, VrfInputDescriptor,
    VrfOutputDescriptor,
};
use rpp::zk::rpp_adapter::{compute_public_digest, Digest32, RppStarkHasher};

#[derive(Debug, Deserialize)]
struct WalletSection {
    network: WalletNetworkSelection,
    runtime: bool,
    tracker: bool,
}

#[derive(Debug, Deserialize)]
struct BlockSection {
    count: u32,
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
        let payload = fs::read_to_string(scenario_path())?;
        Ok(toml::from_str(&payload)?)
    }
}

struct TrackerBundle {
    ledger_transaction: LedgerTransaction,
    metadata_bytes: Vec<u8>,
    expected_digest: StatusDigest,
    proof_audit: RppStarkProofAudit,
    vrf_audit: StoredVrfAudit,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_tracker_history_surfaces_via_api() -> Result<()> {
    let scenario = WalletTrackerScenario::load_from_disk()?;
    assert_eq!(scenario.blocks.count, 1, "scenario expects a single block");

    let temp = TempDir::new()?;
    let firewood_dir = temp.path().join("firewood");
    let index_dir = temp.path().join("index");
    fs::create_dir_all(&firewood_dir)?;
    fs::create_dir_all(&index_dir)?;

    let (runtime, node_config) = build_runtime_adapters(temp.path());

    let electrs_config = ElectrsConfig {
        network: scenario.wallet.network,
        features: FeatureGates {
            runtime: scenario.wallet.runtime,
            tracker: scenario.wallet.tracker,
        },
        cache: CacheConfig::default(),
        tracker: TrackerConfig::default(),
        p2p: P2pConfig::default(),
    };

    let handles = initialize(
        &electrs_config,
        &firewood_dir,
        &index_dir,
        Some(runtime.clone()),
    )?;
    let storage = (*runtime.storage()).clone();
    let wallet_keypair = load_keypair(&node_config.key_path)?;
    let wallet = Wallet::with_electrs(
        storage,
        wallet_keypair.clone(),
        RuntimeMetrics::noop(),
        electrs_config.clone(),
        handles,
    )?;

    let bundle = build_transaction_bundle(&scenario, wallet.address());

    {
        let mut guard = wallet.electrs_handles();
        let handles = guard.as_mut().expect("electrs handles attached");
        let tracker = handles.tracker.as_mut().expect("tracker available");
        let parent = tracker.chain().tip();
        let header = sample_header(parent, scenario.blocks.count);
        tracker.index_mut().index_block(
            header,
            &[bundle.ledger_transaction.clone()],
            Some(&vec![Some(bundle.metadata_bytes.clone())]),
        )?;
    }

    let account_nonce = wallet.account_summary()?.nonce;
    let pending_tx = RuntimeTransaction::new(
        wallet.address().clone(),
        "pending-recipient".into(),
        scenario.blocks.amount / 2,
        scenario.blocks.fee,
        account_nonce + 1,
        Some("pending".into()),
    );
    let pending_signature = sign_message(&wallet_keypair, &pending_tx.canonical_bytes());
    let pending_signed =
        SignedTransaction::new(pending_tx, pending_signature, &wallet_keypair.public);
    let pending_bundle = TransactionProofBundle::new(
        pending_signed,
        ChainProof::RppStark(RppStarkProof::new(
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
        )),
        None,
        None,
    );
    runtime.node().submit_transaction(pending_bundle)?;

    {
        let mut guard = wallet.electrs_handles();
        let handles = guard.as_mut().expect("electrs handles attached");
        let tracker = handles.tracker.as_mut().expect("tracker available");
        let daemon = handles.daemon.as_ref().expect("daemon available");
        tracker.sync(daemon)?;
    }

    sleep(Duration::from_millis(200)).await;

    let history = wallet.history()?;
    assert!(
        history
            .iter()
            .any(|entry| matches!(entry.status, HistoryStatus::Pending { .. })),
        "mempool entry should surface as pending history"
    );
    let confirmed = history
        .iter()
        .find(|entry| matches!(entry.status, HistoryStatus::Confirmed { .. }))
        .expect("confirmed entry present");
    assert_eq!(
        confirmed.status_digest.as_ref().map(StatusDigest::to_hex),
        Some(bundle.expected_digest.to_hex()),
        "confirmed entry should expose tracker digest"
    );
    assert_eq!(
        confirmed.proof_envelope.as_deref(),
        Some(scenario.proof.envelope.as_str()),
        "confirmed entry should wire proof envelope"
    );
    assert_eq!(
        confirmed.vrf_audit.as_ref(),
        Some(&bundle.vrf_audit),
        "confirmed entry should retain VRF audit metadata"
    );

    let metadata = wallet
        .script_status_metadata()
        .expect("script metadata available")
        .pop()
        .expect("tracker metadata present");
    assert_ne!(
        metadata.mempool_delta, 0,
        "mempool delta should reflect pending transaction"
    );
    assert_eq!(
        metadata.status_digest.as_ref().map(StatusDigest::to_hex),
        Some(bundle.expected_digest.to_hex()),
        "metadata digest should match tracker digest"
    );
    assert_eq!(
        metadata
            .proof_envelopes
            .first()
            .and_then(|value| value.as_ref()),
        Some(&scenario.proof.envelope),
        "script metadata should surface proof envelope"
    );
    assert_eq!(
        metadata.vrf_audits.first().and_then(|value| value.as_ref()),
        Some(&bundle.vrf_audit),
        "script metadata should surface VRF audit"
    );

    let tracker_state = wallet
        .tracker_handle()
        .expect("tracker handle exposed")
        .state();
    let snapshot = match tracker_state {
        TrackerState::Ready(snapshot) => snapshot,
        other => panic!("tracker snapshot not ready: {other:?}"),
    };
    assert!(
        snapshot.mempool_fingerprint.is_some(),
        "tracker snapshot should include mempool fingerprint"
    );
    assert!(
        snapshot
            .scripts
            .iter()
            .any(|script| script.status_digest.as_deref() == Some(&bundle.expected_digest.to_hex())),
        "tracker snapshot should advertise digest"
    );

    let mode = Arc::new(RwLock::new(RuntimeMode::Wallet));
    let context = ApiContext::new(
        mode,
        None,
        Some(Arc::new(wallet.clone())),
        None,
        None,
        false,
        true,
    );

    let addr = random_loopback()?;
    let server_context = context.clone();
    let server = tokio::spawn(async move {
        // ignore failures triggered by aborting the server at the end of the test
        let _ = api::serve(server_context, addr, None, None).await;
    });

    sleep(Duration::from_millis(100)).await;

    let client = Client::builder().build()?;
    let base = format!("http://{}", addr);
    let wallet_history: WalletHistoryResponse = client
        .get(format!("{}/wallet/history", base))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let ui_history: WalletHistoryResponse = client
        .get(format!("{}/ui/history", base))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    server.abort();

    assert_eq!(
        history.len(),
        wallet_history.entries.len(),
        "RPC history should mirror wallet history entries"
    );
    assert_eq!(
        history.len(),
        ui_history.entries.len(),
        "UI history should mirror wallet history entries"
    );
    assert!(
        wallet_history
            .entries
            .iter()
            .zip(ui_history.entries.iter())
            .all(|(left, right)| history_entries_match(left, right)),
        "UI and RPC history entries should be identical"
    );
    assert!(
        wallet_history
            .entries
            .iter()
            .any(|entry| matches!(entry.status, HistoryStatus::Pending { .. })),
        "RPC history should expose pending transaction"
    );
    let rpc_confirmed = wallet_history
        .entries
        .iter()
        .find(|entry| matches!(entry.status, HistoryStatus::Confirmed { .. }))
        .expect("RPC confirmed entry present");
    assert_eq!(
        rpc_confirmed
            .status_digest
            .as_ref()
            .map(StatusDigest::to_hex),
        Some(bundle.expected_digest.to_hex()),
        "RPC confirmed digest should remain stable"
    );
    assert_eq!(
        rpc_confirmed.proof_envelope.as_deref(),
        Some(scenario.proof.envelope.as_str()),
        "RPC confirmed entry should carry proof envelope"
    );

    let script_metadata = wallet_history
        .script_metadata
        .as_ref()
        .expect("tracker metadata provided");
    assert!(
        script_metadata
            .iter()
            .any(|meta| meta.status_digest.as_ref().map(StatusDigest::to_hex)
                == Some(bundle.expected_digest.to_hex())),
        "RPC metadata should advertise digest"
    );
    assert!(
        script_metadata.iter().any(|meta| meta.mempool_delta != 0),
        "RPC metadata should expose mempool delta"
    );
    assert_eq!(
        script_metadata
            .first()
            .and_then(|meta| meta.proof_envelopes.first())
            .and_then(|value| value.as_ref()),
        Some(&scenario.proof.envelope),
        "RPC metadata should surface proof envelope"
    );
    assert_eq!(
        script_metadata
            .first()
            .and_then(|meta| meta.vrf_audits.first())
            .and_then(|value| value.as_ref()),
        Some(&bundle.vrf_audit),
        "RPC metadata should surface VRF audit"
    );

    let tracker_snapshot = wallet_history
        .tracker
        .as_ref()
        .expect("tracker snapshot provided");
    assert!(
        tracker_snapshot.mempool_fingerprint.is_some(),
        "tracker snapshot should carry mempool fingerprint"
    );
    assert!(
        tracker_snapshot
            .scripts
            .iter()
            .any(|script| script.status_digest.as_deref() == Some(&bundle.expected_digest.to_hex())),
        "tracker snapshot should publish digest"
    );

    Ok(())
}

fn history_entries_match(left: &HistoryEntry, right: &HistoryEntry) -> bool {
    left.tx_hash == right.tx_hash
        && std::mem::discriminant(&left.status) == std::mem::discriminant(&right.status)
        && left.status_digest.as_ref().map(StatusDigest::to_hex)
            == right.status_digest.as_ref().map(StatusDigest::to_hex)
        && left.proof_envelope == right.proof_envelope
        && left.vrf_audit == right.vrf_audit
}

fn scenario_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios/wallet_tracker_rpp.toml")
}

fn build_transaction_bundle(scenario: &WalletTrackerScenario, recipient: &str) -> TrackerBundle {
    let script_payload = LedgerScriptPayload::Recipient {
        to: recipient.to_string(),
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
    let ledger_tx = LedgerTransaction::new(
        vec![OutPoint::new(Txid([0x11; 32]), 0)],
        vec![script.clone()],
        memo,
    );
    let txid = bsl_txid(&ledger_tx);
    let mut txid_bytes = [0u8; 32];
    txid_bytes.copy_from_slice(txid.as_bytes());

    let witness = wallet_sample_transaction_witness(
        txid_bytes,
        recipient,
        scenario.blocks.amount,
        scenario.blocks.fee,
    );
    let witness_bytes = encode_transaction_witness(&witness).expect("encode witness");
    let proof = RppStarkProof::new(vec![0xAA, 0xBB], vec![0xCC, 0xDD], vec![0xEE, 0xFF]);
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
            total_bytes: 0,
            notes: Some(scenario.proof.report_notes.clone()),
            trace_query_indices: Some(vec![1, 2, 3]),
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

    let runtime_tx = RuntimeTransaction::new(
        "sender".into(),
        recipient.to_string(),
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
        rpp_stark_proof: Some(serde_json::to_vec(&proof).expect("encode proof")),
        proof_audit: Some(proof_audit.clone()),
        vrf_audit: Some(vrf_audit.clone()),
    };
    let metadata_bytes = encode_transaction_metadata(&metadata);

    TrackerBundle {
        ledger_transaction: ledger_tx,
        metadata_bytes,
        expected_digest,
        proof_audit,
        vrf_audit,
    }
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

fn build_runtime_adapters(base: &Path) -> (RuntimeAdapters, NodeConfig) {
    let mut config = NodeConfig::default();
    config.data_dir = base.join("node/data");
    config.key_path = base.join("node/keys/node.toml");
    config.p2p_key_path = base.join("node/keys/p2p.toml");
    config.vrf_key_path = base.join("node/keys/vrf.toml");
    config.snapshot_dir = base.join("node/snapshots");
    config.proof_cache_dir = base.join("node/proofs");
    config.rollout.feature_gates = NodeFeatureGates {
        pruning: false,
        recursive_proofs: false,
        reconstruction: false,
        consensus_enforcement: false,
    };

    let config_clone = config.clone();
    let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
    let node_handle = node.handle();
    let storage = node_handle.storage();
    let (orchestrator, _shutdown) = PipelineOrchestrator::new(node_handle.clone(), None);
    let provider = Arc::new(DummyPayloadProvider::default());
    let verifier = Arc::new(RuntimeRecursiveProofVerifier::default());

    let adapters = RuntimeAdapters::new(
        Arc::new(storage.clone()),
        node_handle,
        orchestrator,
        provider,
        verifier,
    );

    (adapters, config_clone)
}

fn random_loopback() -> Result<SocketAddr> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

#[derive(Default)]
struct DummyPayloadProvider;

impl PayloadProvider for DummyPayloadProvider {
    fn fetch_payload(
        &self,
        request: &ReconstructionRequest,
    ) -> rpp::errors::ChainResult<rpp::runtime::types::BlockPayload> {
        Err(rpp::errors::ChainError::Config(format!(
            "no payload available for height {}",
            request.height
        )))
    }
}
