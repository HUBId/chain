use std::collections::{btree_map::Entry as BTreeEntry, BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::proof_backend::Blake2sHasher;
use ed25519_dalek::Keypair;
use malachite::Natural;
use parking_lot::{Mutex, RwLock};
use serde::{de::DeserializeOwned, Serialize};
#[cfg(feature = "vendor_electrs")]
use serde_json;
#[cfg(feature = "vendor_electrs")]
use std::path::Path;
use tokio::sync::{broadcast, watch, Mutex as AsyncMutex};
use tokio::task::{self, JoinHandle};
use tokio::time;

use crate::config::NodeConfig;
use crate::consensus::evaluate_vrf;
use crate::crypto::{
    address_from_public_key, generate_vrf_keypair, sign_message, vrf_public_key_from_hex,
    vrf_public_key_to_hex, vrf_secret_key_from_hex, vrf_secret_key_to_hex, StoredVrfKeypair,
    VrfKeypair,
};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::{Ledger, ReputationAudit, DEFAULT_EPOCH_LENGTH};
use crate::node::NodeHandle;
use crate::orchestration::{
    FlowSnapshot, PipelineDashboardSnapshot, PipelineError, PipelineOrchestrator, PipelineStage,
};
use crate::proof_system::ProofProver;
use crate::reputation::{
    minimum_transaction_tier, transaction_tier_requirement, Tier, TierRequirementError,
};
use crate::rpp::{UtxoOutpoint, UtxoRecord};
use crate::state::StoredUtxo;
use crate::storage::ledger::SlashingEvent;
use crate::storage::Storage;
use crate::stwo::proof::ProofPayload;
use crate::stwo::prover::WalletProver;
use crate::types::{
    Account, Address, ChainProof, IdentityDeclaration, IdentityGenesis, IdentityProof,
    SignedTransaction, Transaction, TransactionProofBundle, UptimeClaim, UptimeProof,
};
use crate::runtime::{ProofKind, RuntimeMetrics};
#[cfg(feature = "vendor_electrs")]
use crate::runtime::node::PendingTransactionSummary;
#[cfg(feature = "vendor_electrs")]
use log::debug;
use log::warn;
#[cfg(feature = "vendor_electrs")]
use rpp::runtime::node::MempoolStatus;
#[cfg(feature = "vendor_electrs")]
use rpp_p2p::GossipTopic;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::config::ElectrsConfig;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::firewood_adapter::RuntimeAdapters;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::init::{initialize, ElectrsHandles};
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::Script;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::types::{
    encode_ledger_script, LedgerScriptPayload, ScriptHash, StatusDigest,
};
#[cfg(all(feature = "vendor_electrs", feature = "backend-rpp-stark"))]
use rpp_wallet::vendor::electrs::StoredVrfAudit;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::{
    HistoryEntry as ElectrsHistoryEntry, HistoryEntryWithMetadata, ScriptHashStatus,
};
#[cfg(feature = "vendor_electrs")]
use sha2::{Digest, Sha256};

use super::{start_node, WalletNodeRuntime};

use super::tabs::{
    HistoryEntry, HistoryStatus, NodeTabMetrics, PipelineHistoryStatus, ReceiveTabAddress,
    SendPreview,
};

const IDENTITY_WORKFLOW_KEY: &[u8] = b"wallet_identity_workflow";
const IDENTITY_VRF_KEY: &[u8] = b"wallet_identity_vrf_keypair";
const NODE_RUNTIME_CONFIG_KEY: &[u8] = b"wallet_node_runtime_config";
#[cfg(feature = "vendor_electrs")]
const ELECTRS_CONFIG_KEY: &[u8] = b"wallet_electrs_config";
#[cfg(feature = "vendor_electrs")]
type ElectrsHandlesGuard<'a> =
    parking_lot::lock_api::MutexGuard<'a, parking_lot::RawMutex, Option<ElectrsHandles>>;

const PIPELINE_ERROR_LIMIT: usize = 32;
const PIPELINE_SLASHING_LIMIT: usize = 16;
const PIPELINE_SLASHING_POLL_SECS: u64 = 30;

#[derive(Clone, Debug, Default, Serialize)]
pub struct PipelineFeedState {
    pub dashboard: PipelineDashboardSnapshot,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<PipelineError>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slashing_events: Vec<SlashingEvent>,
}

fn publish_pipeline_state<F>(
    state: &Arc<RwLock<PipelineFeedState>>,
    tx: &watch::Sender<PipelineFeedState>,
    mut update: F,
) where
    F: FnMut(&mut PipelineFeedState),
{
    let snapshot = {
        let mut guard = state.write();
        update(&mut guard);
        guard.clone()
    };
    let _ = tx.send(snapshot);
}

#[cfg(feature = "vendor_electrs")]
#[derive(Clone)]
struct WalletScriptStatus {
    script: Script,
    status: ScriptHashStatus,
}

#[cfg(feature = "vendor_electrs")]
async fn tracker_sync_loop(
    handles: Arc<Mutex<Option<ElectrsHandles>>>,
    statuses: Arc<RwLock<Vec<WalletScriptStatus>>>,
    snapshot: Arc<RwLock<Option<TrackerSnapshot>>>,
    mut shutdown: watch::Receiver<bool>,
    mut block_rx: Option<broadcast::Receiver<Vec<u8>>>,
    mut finality_rx: Option<watch::Receiver<PipelineDashboardSnapshot>>,
) {
    let mut interval = time::interval(Duration::from_secs(5));
    let mut last_finality_height = finality_rx
        .as_ref()
        .and_then(|receiver| highest_commit_height(&receiver.borrow()));
    loop {
        let mut finality_closed = false;
        let should_sync = match (block_rx.as_mut(), finality_rx.as_mut()) {
            (Some(receiver), Some(finality)) => {
                tokio::select! {
                    _ = interval.tick() => true,
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                        false
                    }
                    message = receiver.recv() => match message {
                        Ok(_) => true,
                        Err(broadcast::error::RecvError::Lagged(_)) => true,
                        Err(broadcast::error::RecvError::Closed) => {
                            block_rx = None;
                            true
                        }
                    },
                    res = finality.changed() => match res {
                        Ok(_) => detect_finality_update(finality, &mut last_finality_height),
                        Err(_) => {
                            finality_closed = true;
                            false
                        }
                    },
                }
            }
            (Some(receiver), None) => {
                tokio::select! {
                    _ = interval.tick() => true,
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                        false
                    }
                    message = receiver.recv() => match message {
                        Ok(_) => true,
                        Err(broadcast::error::RecvError::Lagged(_)) => true,
                        Err(broadcast::error::RecvError::Closed) => {
                            block_rx = None;
                            true
                        }
                    },
                }
            }
            (None, Some(finality)) => {
                tokio::select! {
                    _ = interval.tick() => true,
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                        false
                    }
                    res = finality.changed() => match res {
                        Ok(_) => detect_finality_update(finality, &mut last_finality_height),
                        Err(_) => {
                            finality_closed = true;
                            false
                        }
                    },
                }
            }
            (None, None) => {
                tokio::select! {
                    _ = interval.tick() => true,
                    changed = shutdown.changed() => {
                        if changed.is_err() || *shutdown.borrow() {
                            break;
                        }
                        false
                    }
                }
            }
        };

        if finality_closed {
            finality_rx = None;
            last_finality_height = None;
        }

        if !should_sync {
            continue;
        }

        run_tracker_iteration(&handles, &statuses, &snapshot);
    }
}

#[cfg(feature = "vendor_electrs")]
fn highest_commit_height(snapshot: &PipelineDashboardSnapshot) -> Option<u64> {
    snapshot
        .flows
        .iter()
        .filter_map(|flow| flow.commit_height)
        .max()
}

#[cfg(feature = "vendor_electrs")]
fn detect_finality_update(
    receiver: &watch::Receiver<PipelineDashboardSnapshot>,
    last_height: &mut Option<u64>,
) -> bool {
    let snapshot = receiver.borrow();
    match (highest_commit_height(&snapshot), *last_height) {
        (Some(current), Some(previous)) if current > previous => {
            *last_height = Some(current);
            true
        }
        (Some(current), None) => {
            *last_height = Some(current);
            true
        }
        (Some(current), Some(previous)) if current < previous => {
            *last_height = Some(current);
            true
        }
        (Some(_), Some(_)) => false,
        (None, Some(_)) => {
            *last_height = None;
            false
        }
        (None, None) => false,
    }
}

#[cfg(feature = "vendor_electrs")]
fn run_tracker_iteration(
    handles: &Arc<Mutex<Option<ElectrsHandles>>>,
    statuses: &Arc<RwLock<Vec<WalletScriptStatus>>>,
    snapshot: &Arc<RwLock<Option<TrackerSnapshot>>>,
) {
    let mut guard = handles.lock();
    let Some(inner) = guard.as_mut() else {
        debug!(target: "wallet::tracker", "electrs handles unavailable");
        return;
    };
    let (tracker, daemon) = match (inner.tracker.as_mut(), inner.daemon.as_ref()) {
        (Some(tracker), Some(daemon)) => (tracker, daemon),
        _ => {
            debug!(target: "wallet::tracker", "tracker or daemon handle missing");
            return;
        }
    };

    if let Err(err) = tracker.sync(daemon) {
        warn!(target: "wallet::tracker", "tracker sync failed: {err}");
        return;
    }

    let mut script_snapshots = Vec::new();
    {
        let mut entries = statuses.write();
        for entry in entries.iter_mut() {
            if let Err(err) = tracker.update_scripthash_status(&mut entry.status, &entry.script) {
                warn!(
                    target: "wallet::tracker",
                    "failed to update script hash status: {err}"
                );
                continue;
            }
            let digest = tracker.get_status_digest(&entry.status);
            let hash_hex = hex::encode(entry.status.scripthash().0.as_ref());
            script_snapshots.push(TrackedScriptSnapshot {
                script_hash: hash_hex,
                status_digest: digest,
            });
        }
    }

    let mempool_fingerprint = tracker.mempool_status().and_then(|status| {
        compute_mempool_fingerprint(status)
            .map_err(|err| {
                warn!(target: "wallet::tracker", "mempool fingerprint error: {err}");
                err
            })
            .ok()
    });

    *snapshot.write() = Some(TrackerSnapshot {
        scripts: script_snapshots,
        mempool_fingerprint,
    });
}

#[cfg(feature = "vendor_electrs")]
fn compute_mempool_fingerprint(status: &MempoolStatus) -> Result<[u8; 32], serde_json::Error> {
    let encoded = serde_json::to_vec(status)?;
    Ok(Sha256::digest(&encoded).into())
}

#[cfg(feature = "vendor_electrs")]
#[derive(Clone, Debug, Serialize)]
pub struct TrackedScriptSnapshot {
    pub script_hash: String,
    pub status_digest: Option<StatusDigest>,
}

#[cfg(feature = "vendor_electrs")]
#[derive(Clone, Debug, Serialize)]
pub struct TrackerSnapshot {
    pub scripts: Vec<TrackedScriptSnapshot>,
    pub mempool_fingerprint: Option<[u8; 32]>,
}

#[cfg(feature = "vendor_electrs")]
#[derive(Clone)]
pub struct WalletTrackerHandle {
    handles: Arc<Mutex<Option<ElectrsHandles>>>,
    snapshot: Arc<RwLock<Option<TrackerSnapshot>>>,
}

#[cfg(feature = "vendor_electrs")]
#[derive(Clone, Debug)]
pub enum TrackerState {
    Disabled,
    Pending,
    Ready(TrackerSnapshot),
}

#[cfg(feature = "vendor_electrs")]
impl WalletTrackerHandle {
    pub fn state(&self) -> TrackerState {
        let tracker_enabled = {
            let guard = self.handles.lock();
            guard
                .as_ref()
                .and_then(|handles| handles.tracker.as_ref())
                .is_some()
        };
        if !tracker_enabled {
            return TrackerState::Disabled;
        }

        match self.snapshot.read().clone() {
            Some(snapshot) => TrackerState::Ready(snapshot),
            None => TrackerState::Pending,
        }
    }
}

#[cfg(feature = "vendor_electrs")]
#[derive(Clone, Debug, Serialize)]
pub struct ScriptStatusMetadata {
    pub script_hash: String,
    pub confirmed_balance: u64,
    pub mempool_delta: i64,
    pub status_digest: Option<StatusDigest>,
    pub proof_envelopes: Vec<Option<String>>,
    #[cfg(feature = "backend-rpp-stark")]
    pub vrf_audits: Vec<Option<StoredVrfAudit>>,
}

#[cfg(feature = "vendor_electrs")]
struct TrackerHistoryView {
    entry: ElectrsHistoryEntry,
    status_digest: Option<StatusDigest>,
    proof_envelope: Option<String>,
    #[cfg(feature = "backend-rpp-stark")]
    vrf_audit: Option<StoredVrfAudit>,
}

#[cfg(feature = "vendor_electrs")]
fn collect_tracker_history(status: &ScriptHashStatus) -> Vec<TrackerHistoryView> {
    #[cfg(feature = "backend-rpp-stark")]
    {
        status
            .history_with_digests()
            .into_iter()
            .map(|with_meta: HistoryEntryWithMetadata| TrackerHistoryView {
                proof_envelope: with_meta.proof.map(|audit| audit.envelope),
                vrf_audit: with_meta.vrf,
                status_digest: with_meta.digest,
                entry: with_meta.entry,
            })
            .collect()
    }

    #[cfg(not(feature = "backend-rpp-stark"))]
    {
        status
            .get_history()
            .iter()
            .cloned()
            .map(|entry| TrackerHistoryView {
                entry,
                status_digest: None,
                proof_envelope: None,
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct WalletNodeRuntimeStatus {
    pub running: bool,
    pub config: Option<NodeConfig>,
    pub address: Option<Address>,
}

#[derive(Clone)]
pub struct Wallet {
    storage: Storage,
    keypair: Arc<Keypair>,
    address: Address,
    metrics: Arc<RuntimeMetrics>,
    node_runtime: Arc<AsyncMutex<Option<WalletNodeRuntime>>>,
    node_handle: Arc<RwLock<Option<NodeHandle>>>,
    pipeline_feed: Arc<RwLock<PipelineFeedState>>,
    pipeline_feed_tx: watch::Sender<PipelineFeedState>,
    pipeline_feed_task: Arc<Mutex<Option<JoinHandle<()>>>>,
    pipeline_feed_shutdown: Arc<Mutex<Option<watch::Sender<bool>>>>,
    #[cfg(feature = "vendor_electrs")]
    electrs_handles: Arc<Mutex<Option<ElectrsHandles>>>,
    #[cfg(feature = "vendor_electrs")]
    electrs_config: Arc<RwLock<Option<ElectrsConfig>>>,
    #[cfg(feature = "vendor_electrs")]
    tracker_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    #[cfg(feature = "vendor_electrs")]
    tracker_shutdown: Arc<Mutex<Option<watch::Sender<bool>>>>,
    #[cfg(feature = "vendor_electrs")]
    tracker_statuses: Arc<RwLock<Vec<WalletScriptStatus>>>,
    #[cfg(feature = "vendor_electrs")]
    tracker_snapshot: Arc<RwLock<Option<TrackerSnapshot>>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WalletAccountSummary {
    pub address: Address,
    pub balance: u128,
    pub nonce: u64,
    pub reputation_score: f64,
    pub tier: Tier,
    pub uptime_hours: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mempool_delta: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusReceipt {
    pub height: u64,
    pub block_hash: String,
    pub proposer: Address,
    pub round: u64,
    pub total_power: String,
    pub quorum_threshold: String,
    pub pre_vote_power: String,
    pub pre_commit_power: String,
    pub commit_power: String,
    pub observers: u64,
    pub quorum_reached: bool,
}

impl Wallet {
    pub fn new(storage: Storage, keypair: Keypair, metrics: Arc<RuntimeMetrics>) -> Self {
        let address = address_from_public_key(&keypair.public);
        let (pipeline_feed_tx, _pipeline_feed_rx) = watch::channel(PipelineFeedState::default());
        Self {
            storage,
            keypair: Arc::new(keypair),
            address,
            metrics,
            node_runtime: Arc::new(AsyncMutex::new(None)),
            node_handle: Arc::new(RwLock::new(None)),
            pipeline_feed: Arc::new(RwLock::new(PipelineFeedState::default())),
            pipeline_feed_tx,
            pipeline_feed_task: Arc::new(Mutex::new(None)),
            pipeline_feed_shutdown: Arc::new(Mutex::new(None)),
            #[cfg(feature = "vendor_electrs")]
            electrs_handles: Arc::new(Mutex::new(None)),
            #[cfg(feature = "vendor_electrs")]
            electrs_config: Arc::new(RwLock::new(None)),
            #[cfg(feature = "vendor_electrs")]
            tracker_tasks: Arc::new(Mutex::new(Vec::new())),
            #[cfg(feature = "vendor_electrs")]
            tracker_shutdown: Arc::new(Mutex::new(None)),
            #[cfg(feature = "vendor_electrs")]
            tracker_statuses: Arc::new(RwLock::new(Vec::new())),
            #[cfg(feature = "vendor_electrs")]
            tracker_snapshot: Arc::new(RwLock::new(None)),
        }
    }

    #[cfg(feature = "vendor_electrs")]
    pub fn with_electrs(
        storage: Storage,
        keypair: Keypair,
        metrics: Arc<RuntimeMetrics>,
        config: ElectrsConfig,
        handles: ElectrsHandles,
    ) -> ChainResult<Self> {
        let wallet = Self::new(storage, keypair, metrics);
        wallet.persist_electrs_config(&config)?;
        wallet.attach_electrs_handles(handles)?;
        Ok(wallet)
    }

    fn stark_prover(&self) -> WalletProver<'_> {
        WalletProver::new(&self.storage)
    }

    pub(crate) fn load_ledger_from_accounts(
        &self,
        accounts: Vec<Account>,
    ) -> ChainResult<(Ledger, bool)> {
        let utxo_snapshot = self.storage.load_utxo_snapshot()?;
        let has_snapshot = utxo_snapshot.is_some();
        let ledger = Ledger::load(
            accounts,
            utxo_snapshot.unwrap_or_default(),
            DEFAULT_EPOCH_LENGTH,
        );
        Ok((ledger, has_snapshot))
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn firewood_state_root(&self) -> ChainResult<String> {
        Ok(hex::encode(self.storage.state_root()?))
    }

    #[cfg(feature = "vendor_electrs")]
    fn tracker_block_timestamp(&self, height: usize) -> Option<u64> {
        let guard = self.electrs_handles.lock();
        let tracker = guard
            .as_ref()
            .and_then(|handles| handles.tracker.as_ref())?;
        tracker
            .chain()
            .get_block_header(height)
            .map(|header| header.timestamp)
    }

    fn legacy_history(&self) -> ChainResult<Vec<HistoryEntry>> {
        let blocks = self.storage.load_blockchain()?;
        let mut history = Vec::new();
        for block in blocks {
            for tx in block.transactions {
                if tx.payload.from == self.address || tx.payload.to == self.address {
                    let tx_hash = hex::encode(tx.hash());
                    let entry = HistoryEntry::confirmed(
                        tx_hash,
                        Some(tx.clone()),
                        block.header.height,
                        block.header.timestamp,
                        self.estimate_reputation_delta(&tx),
                    );
                    history.push(entry);
                }
            }
        }
        history.sort_by_key(|entry| entry.status.confirmation_height());
        Ok(history)
    }

    #[cfg(feature = "vendor_electrs")]
    fn history_from_tracker(&self) -> ChainResult<Option<Vec<HistoryEntry>>> {
        let mut handles_guard = self.electrs_handles.lock();
        let tracker = match handles_guard
            .as_ref()
            .and_then(|handles| handles.tracker.as_ref())
        {
            Some(tracker) => tracker,
            None => return Ok(None),
        };

        let mempool_status = tracker.mempool_status().cloned();
        drop(handles_guard);

        let mut mempool: HashMap<String, PendingTransactionSummary> = mempool_status
            .map(|status| {
                status
                    .transactions
                    .into_iter()
                    .map(|summary| (summary.hash.clone(), summary))
                    .collect()
            })
            .unwrap_or_default();

        let statuses = self.tracker_statuses.read();
        if statuses.is_empty() && mempool.is_empty() {
            return Ok(Some(Vec::new()));
        }

        let mut aggregated: BTreeMap<String, (u8, HistoryEntry)> = BTreeMap::new();
        for wallet_status in statuses.iter() {
            for view in collect_tracker_history(&wallet_status.status) {
                let tx_hash = view.entry.txid_hex();
                let entry = self.history_entry_from_view(&tx_hash, &view, &mut mempool)?;
                let priority = history_priority(&entry);
                match aggregated.entry(tx_hash) {
                    BTreeEntry::Vacant(slot) => {
                        slot.insert((priority, entry));
                    }
                    BTreeEntry::Occupied(mut slot) => {
                        let (existing_priority, existing_entry) = slot.get_mut();
                        if priority > *existing_priority {
                            let mut merged = entry;
                            merge_history_metadata(&mut merged, existing_entry);
                            *existing_priority = priority;
                            *existing_entry = merged;
                        } else {
                            merge_history_metadata(existing_entry, &entry);
                        }
                    }
                }
            }
        }

        let mut history: Vec<HistoryEntry> =
            aggregated.into_values().map(|(_, entry)| entry).collect();

        if !mempool.is_empty() {
            let submitted_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            for (tx_hash, summary) in mempool.into_iter() {
                let signed_tx = Self::signed_transaction_from_summary(&summary);
                let mut entry =
                    HistoryEntry::pending(tx_hash, signed_tx.clone(), Some(summary), submitted_at);
                if let Some(tx) = signed_tx {
                    entry.reputation_delta = self.estimate_reputation_delta(&tx);
                }
                history.push(entry);
            }
        }
        history.sort_by_key(|entry| entry.status.confirmation_height());
        Ok(Some(history))
    }

    fn annotate_history_with_pipeline(&self, history: &mut [HistoryEntry]) {
        if history.is_empty() {
            return;
        }
        let feed_state = self.pipeline_feed.read().clone();
        if feed_state.dashboard.flows.is_empty() {
            return;
        }
        let flow_index: HashMap<String, FlowSnapshot> = feed_state
            .dashboard
            .flows
            .into_iter()
            .map(|flow| (flow.hash.clone(), flow))
            .collect();
        for entry in history.iter_mut() {
            if let Some(flow) = flow_index.get(&entry.tx_hash) {
                let timed_out = detect_pipeline_timeout(entry, flow);
                entry.pipeline = Some(PipelineHistoryStatus {
                    flow: flow.clone(),
                    timed_out,
                });
            }
        }
    }

    #[cfg(feature = "vendor_electrs")]
    fn history_entry_from_view(
        &self,
        tx_hash: &str,
        view: &TrackerHistoryView,
        mempool: &mut HashMap<String, PendingTransactionSummary>,
    ) -> ChainResult<HistoryEntry> {
        if let Some(height) = view.entry.confirmed_height() {
            let (transaction, timestamp, pruned) =
                self.lookup_confirmed_transaction(height as u64, view.entry.txid().as_bytes())?;
            let mut entry = match (pruned, transaction) {
                (true, _) => HistoryEntry::pruned(tx_hash.to_string(), height as u64),
                (false, Some(tx)) => {
                    let reputation_delta = self.estimate_reputation_delta(&tx);
                    HistoryEntry::confirmed(
                        tx_hash.to_string(),
                        Some(tx),
                        height as u64,
                        timestamp,
                        reputation_delta,
                    )
                }
                (false, None) => HistoryEntry::pruned(tx_hash.to_string(), height as u64),
            };
            entry = apply_tracker_metadata(entry, view);
            return Ok(entry);
        }

        let summary = mempool.remove(tx_hash);
        let signed_tx = summary
            .as_ref()
            .and_then(|pending| Self::signed_transaction_from_summary(pending));
        let submitted_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut entry = HistoryEntry::pending(
            tx_hash.to_string(),
            signed_tx.clone(),
            summary,
            submitted_at,
        );
        if let Some(tx) = signed_tx {
            entry.reputation_delta = self.estimate_reputation_delta(&tx);
        }
        entry = apply_tracker_metadata(entry, view);
        Ok(entry)
    }

    #[cfg(feature = "vendor_electrs")]
    fn lookup_confirmed_transaction(
        &self,
        height: u64,
        txid: &[u8; 32],
    ) -> ChainResult<(Option<SignedTransaction>, u64, bool)> {
        if let Some(block) = self.storage.read_block(height)? {
            let timestamp = block.header.timestamp;
            if block.pruned {
                return Ok((None, timestamp, true));
            }
            for tx in block.transactions {
                if tx.hash() == *txid {
                    return Ok((Some(tx), timestamp, false));
                }
            }
            return Ok((None, timestamp, false));
        }

        let timestamp = self.tracker_block_timestamp(height as usize).unwrap_or(0);
        Ok((None, timestamp, true))
    }

    #[cfg(feature = "vendor_electrs")]
    fn signed_transaction_from_summary(
        summary: &PendingTransactionSummary,
    ) -> Option<SignedTransaction> {
        if let Some(witness) = summary.witness.clone() {
            return Some(witness.signed_tx);
        }
        if let Some(payload) = summary.proof_payload.clone() {
            if let ProofPayload::Transaction(witness) = payload {
                return Some(witness.signed_tx);
            }
        }
        if let Some(proof) = summary.proof.clone() {
            match proof {
                ChainProof::Stwo(stwo) => {
                    if let ProofPayload::Transaction(witness) = stwo.payload {
                        return Some(witness.signed_tx);
                    }
                }
                #[cfg(feature = "backend-plonky3")]
                ChainProof::Plonky3(_) => {}
                #[cfg(feature = "backend-rpp-stark")]
                ChainProof::RppStark(_) => {}
            }
        }
        None
    }

    #[cfg(feature = "vendor_electrs")]
    pub fn script_status_metadata(&self) -> Option<Vec<ScriptStatusMetadata>> {
        let guard = self.electrs_handles.lock();
        if guard
            .as_ref()
            .and_then(|handles| handles.tracker.as_ref())
            .is_none()
        {
            return None;
        }
        drop(guard);

        let statuses = self.tracker_statuses.read();
        let mut metadata = Vec::with_capacity(statuses.len());
        for entry in statuses.iter() {
            let script_hash = hex::encode(entry.status.scripthash().0.as_bytes());
            let status_digest = entry.status.status_digest();
            let confirmed_balance = entry.status.confirmed_balance();
            let mempool_delta = entry.status.mempool_delta();
            let proof_envelopes: Vec<Option<String>> = {
                #[cfg(feature = "backend-rpp-stark")]
                {
                    entry.status.proof_envelopes()
                }
                #[cfg(not(feature = "backend-rpp-stark"))]
                {
                    Vec::new()
                }
            };
            #[cfg(feature = "backend-rpp-stark")]
            let vrf_audits = entry.status.vrf_audits();
            metadata.push(ScriptStatusMetadata {
                script_hash,
                confirmed_balance,
                mempool_delta,
                status_digest,
                proof_envelopes,
                #[cfg(feature = "backend-rpp-stark")]
                vrf_audits,
            });
        }
        Some(metadata)
    }

    #[cfg(feature = "vendor_electrs")]
    pub fn persist_electrs_config(&self, config: &ElectrsConfig) -> ChainResult<()> {
        let mut encoded = serde_json::to_vec(config).map_err(|err| {
            ChainError::Config(format!(
                "failed to encode wallet electrs config for persistence: {err}"
            ))
        })?;
        if encoded.is_empty() {
            encoded = b"{}".to_vec();
        }
        self.storage
            .write_metadata_blob(ELECTRS_CONFIG_KEY, encoded)?;
        *self.electrs_config.write() = Some(config.clone());
        Ok(())
    }

    #[cfg(feature = "vendor_electrs")]
    pub fn load_electrs_config(&self) -> ChainResult<Option<ElectrsConfig>> {
        if let Some(config) = self.electrs_config.read().clone() {
            return Ok(Some(config));
        }
        let maybe_bytes = self.storage.read_metadata_blob(ELECTRS_CONFIG_KEY)?;
        let Some(bytes) = maybe_bytes else {
            return Ok(None);
        };
        let config: ElectrsConfig = serde_json::from_slice(&bytes).map_err(|err| {
            ChainError::Config(format!(
                "failed to decode wallet electrs config from persistence: {err}"
            ))
        })?;
        *self.electrs_config.write() = Some(config.clone());
        Ok(Some(config))
    }

    #[cfg(feature = "vendor_electrs")]
    pub fn reload_electrs_handles(
        &self,
        firewood_dir: impl AsRef<Path>,
        index_dir: impl AsRef<Path>,
        runtime_adapters: Option<RuntimeAdapters>,
    ) -> ChainResult<()> {
        let Some(config) = self.load_electrs_config()? else {
            return Ok(());
        };
        let handles =
            initialize(&config, firewood_dir, index_dir, runtime_adapters).map_err(|err| {
                ChainError::Config(format!(
                    "failed to reinitialise wallet electrs handles: {err}"
                ))
            })?;
        self.attach_electrs_handles(handles)
    }

    #[cfg(feature = "vendor_electrs")]
    pub fn electrs_handles(&self) -> ElectrsHandlesGuard<'_> {
        self.electrs_handles.lock()
    }

    #[cfg(feature = "vendor_electrs")]
    pub fn attach_electrs_handles(&self, handles: ElectrsHandles) -> ChainResult<()> {
        self.stop_tracker_tasks();
        let statuses = self.build_wallet_script_statuses()?;
        {
            let mut guard = self.electrs_handles.lock();
            *guard = Some(handles);
        }
        *self.tracker_statuses.write() = statuses;

        let (runtime_adapters, tracker_subscription) = {
            let guard = self.electrs_handles.lock();
            let runtime = guard
                .as_ref()
                .and_then(|handles| handles.firewood.runtime().cloned());
            let subscription = guard
                .as_ref()
                .and_then(|handles| handles.tracker.as_ref())
                .map(|tracker| {
                    (
                        tracker.p2p_notifications_enabled(),
                        tracker.notification_topic(),
                    )
                });
            (runtime, subscription)
        };

        let block_notifications = match (runtime_adapters.as_ref(), tracker_subscription) {
            (Some(adapters), Some((true, topic))) => {
                Some(adapters.node().subscribe_witness_gossip(topic))
            }
            (None, Some((true, topic))) => {
                warn!(
                    target: "wallet::tracker",
                    "tracker gossip topic {topic} requested but runtime adapters unavailable"
                );
                None
            }
            _ => None,
        };

        let finality_notifications = if tracker_subscription.is_some() {
            runtime_adapters
                .as_ref()
                .map(|adapters| adapters.orchestrator().subscribe_dashboard())
        } else {
            None
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        *self.tracker_shutdown.lock() = Some(shutdown_tx);

        let handles_arc = Arc::clone(&self.electrs_handles);
        let statuses_arc = Arc::clone(&self.tracker_statuses);
        let snapshot_arc = Arc::clone(&self.tracker_snapshot);
        let block_rx = block_notifications;
        let finality_rx = finality_notifications;

        let task = tokio::spawn(async move {
            tracker_sync_loop(
                handles_arc,
                statuses_arc,
                snapshot_arc,
                shutdown_rx,
                block_rx,
                finality_rx,
            )
            .await;
        });
        self.tracker_tasks.lock().push(task);

        Ok(())
    }

    #[cfg(feature = "vendor_electrs")]
    pub fn tracker_snapshot(&self) -> Option<TrackerSnapshot> {
        self.tracker_snapshot.read().clone()
    }

    #[cfg(feature = "vendor_electrs")]
    pub fn tracker_handle(&self) -> Option<WalletTrackerHandle> {
        let tracker_available = {
            let guard = self.electrs_handles.lock();
            guard
                .as_ref()
                .and_then(|handles| handles.tracker.as_ref())
                .is_some()
        };
        if !tracker_available {
            return None;
        }

        Some(WalletTrackerHandle {
            handles: Arc::clone(&self.electrs_handles),
            snapshot: Arc::clone(&self.tracker_snapshot),
        })
    }

    #[cfg(feature = "vendor_electrs")]
    fn stop_tracker_tasks(&self) {
        if let Some(sender) = self.tracker_shutdown.lock().take() {
            let _ = sender.send(true);
        }
        let mut handles = self.tracker_tasks.lock();
        while let Some(handle) = handles.pop() {
            handle.abort();
        }
        self.tracker_statuses.write().clear();
        *self.tracker_snapshot.write() = None;
    }

    #[cfg(feature = "vendor_electrs")]
    fn build_wallet_script_statuses(&self) -> ChainResult<Vec<WalletScriptStatus>> {
        let mut statuses = Vec::new();
        for record in self.unspent_utxos(&self.address)? {
            let script = Script::new(encode_ledger_script(&LedgerScriptPayload::Recipient {
                to: record.owner.clone(),
                amount: record.value,
            }));
            let scripthash = ScriptHash::new(&script);
            statuses.push(WalletScriptStatus {
                script,
                status: ScriptHashStatus::new(scripthash),
            });
        }
        Ok(statuses)
    }

    pub fn persist_node_runtime_config(&self, config: &NodeConfig) -> ChainResult<()> {
        let mut encoded = serde_json::to_vec(config).map_err(|err| {
            ChainError::Config(format!(
                "failed to encode wallet node runtime config for persistence: {err}"
            ))
        })?;
        if encoded.is_empty() {
            encoded = b"{}".to_vec();
        }
        self.storage
            .write_metadata_blob(NODE_RUNTIME_CONFIG_KEY, encoded)
    }

    pub fn configure_node_runtime(&self, config: &NodeConfig) -> ChainResult<()> {
        config.ensure_directories()?;
        self.persist_node_runtime_config(config)
    }

    pub fn load_node_runtime_config(&self) -> ChainResult<Option<NodeConfig>> {
        let maybe_bytes = self.storage.read_metadata_blob(NODE_RUNTIME_CONFIG_KEY)?;
        let Some(bytes) = maybe_bytes else {
            return Ok(None);
        };
        let config: NodeConfig = serde_json::from_slice(&bytes).map_err(|err| {
            ChainError::Config(format!(
                "failed to decode wallet node runtime config: {err}"
            ))
        })?;
        Ok(Some(config))
    }

    pub async fn start_node_runtime(&self) -> ChainResult<WalletNodeRuntimeStatus> {
        let mut guard = self.node_runtime.lock().await;
        if let Some(runtime) = guard.as_ref() {
            return Ok(WalletNodeRuntimeStatus {
                running: true,
                config: Some(runtime.config().clone()),
                address: Some(runtime.address().to_string()),
            });
        }

        let config = self.load_node_runtime_config()?.ok_or_else(|| {
            ChainError::Config("wallet node runtime configuration not found".into())
        })?;
        config.ensure_directories()?;
        let runtime = start_node(config.clone()).await?;
        let handle = runtime.node_handle();
        *self.node_handle.write() = Some(handle);
        let address = runtime.address().to_string();
        let status = WalletNodeRuntimeStatus {
            running: true,
            config: Some(config.clone()),
            address: Some(address),
        };
        *guard = Some(runtime);
        Ok(status)
    }

    pub async fn stop_node_runtime(&self) -> ChainResult<WalletNodeRuntimeStatus> {
        let mut guard = self.node_runtime.lock().await;
        let Some(runtime) = guard.take() else {
            self.stop_pipeline_feed();
            let config = self.load_node_runtime_config()?;
            return Ok(WalletNodeRuntimeStatus {
                running: false,
                config,
                address: None,
            });
        };
        let config = runtime.config().clone();
        *self.node_handle.write() = None;
        runtime.shutdown().await?;
        self.stop_pipeline_feed();
        Ok(WalletNodeRuntimeStatus {
            running: false,
            config: Some(config),
            address: None,
        })
    }

    pub fn node_runtime_running(&self) -> bool {
        self.node_handle.read().is_some()
    }

    pub fn node_runtime_handle(&self) -> Option<NodeHandle> {
        self.node_handle.read().clone()
    }

    pub fn node_runtime_status(&self) -> ChainResult<WalletNodeRuntimeStatus> {
        let config = self.load_node_runtime_config()?;
        if let Some(handle) = self.node_handle.read().clone() {
            return Ok(WalletNodeRuntimeStatus {
                running: true,
                config,
                address: Some(handle.address().to_string()),
            });
        }
        Ok(WalletNodeRuntimeStatus {
            running: false,
            config,
            address: None,
        })
    }

    pub fn pipeline_feed_handle(&self) -> Arc<RwLock<PipelineFeedState>> {
        Arc::clone(&self.pipeline_feed)
    }

    pub fn pipeline_feed_snapshot(&self) -> PipelineFeedState {
        self.pipeline_feed.read().clone()
    }

    pub fn subscribe_pipeline_feed(
        &self,
        orchestrator: &PipelineOrchestrator,
    ) -> watch::Receiver<PipelineFeedState> {
        self.ensure_pipeline_subscription(orchestrator);
        self.pipeline_feed_tx.subscribe()
    }

    fn ensure_pipeline_subscription(&self, orchestrator: &PipelineOrchestrator) {
        {
            let mut guard = self.pipeline_feed_task.lock();
            if let Some(handle) = guard.as_ref() {
                if !handle.is_finished() {
                    return;
                }
            }
            guard.take();
        }

        if let Some(sender) = self.pipeline_feed_shutdown.lock().take() {
            let _ = sender.send(true);
        }

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        *self.pipeline_feed_shutdown.lock() = Some(shutdown_tx);

        let mut dashboard_rx = orchestrator.subscribe_dashboard();
        let mut errors_rx = orchestrator.subscribe_errors();
        let pipeline_state = Arc::clone(&self.pipeline_feed);
        let pipeline_tx = self.pipeline_feed_tx.clone();
        let node_handle = Arc::clone(&self.node_handle);

        let initial_snapshot = dashboard_rx.borrow().clone();
        publish_pipeline_state(&pipeline_state, &self.pipeline_feed_tx, move |state| {
            state.dashboard = initial_snapshot;
        });

        let initial_handle = { self.node_handle.read().clone() };
        if let Some(handle) = initial_handle {
            match handle.slashing_events(PIPELINE_SLASHING_LIMIT) {
                Ok(events) => {
                    publish_pipeline_state(&pipeline_state, &self.pipeline_feed_tx, move |state| {
                        state.slashing_events = events;
                    });
                }
                Err(err) => {
                    warn!(target: "wallet::pipeline", ?err, "failed to prime slashing alerts");
                }
            }
        }

        let task = tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            let mut slashing_interval =
                time::interval(Duration::from_secs(PIPELINE_SLASHING_POLL_SECS));
            loop {
                tokio::select! {
                    res = shutdown_rx.changed() => {
                        match res {
                            Ok(_) => {
                                if *shutdown_rx.borrow() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    res = dashboard_rx.changed() => match res {
                        Ok(_) => {
                            let snapshot = dashboard_rx.borrow().clone();
                            publish_pipeline_state(&pipeline_state, &pipeline_tx, move |state| {
                                state.dashboard = snapshot;
                            });
                        }
                        Err(_) => break,
                    },
                    res = errors_rx.recv() => match res {
                        Ok(error) => {
                            publish_pipeline_state(&pipeline_state, &pipeline_tx, move |state| {
                                if state.errors.len() >= PIPELINE_ERROR_LIMIT {
                                    state.errors.remove(0);
                                }
                                state.errors.push(error);
                            });
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            warn!(target: "wallet::pipeline", "lagged on pipeline error stream");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                    _ = slashing_interval.tick() => {
                        let maybe_handle = { node_handle.read().clone() };
                        if let Some(handle) = maybe_handle {
                            let events = match task::spawn_blocking(move || handle.slashing_events(PIPELINE_SLASHING_LIMIT)).await {
                                Ok(Ok(events)) => events,
                                Ok(Err(err)) => {
                                    warn!(target: "wallet::pipeline", ?err, "failed to fetch slashing events");
                                    continue;
                                }
                                Err(err) => {
                                    warn!(target: "wallet::pipeline", ?err, "slashing event poll cancelled");
                                    continue;
                                }
                            };
                            publish_pipeline_state(&pipeline_state, &pipeline_tx, move |state| {
                                state.slashing_events = events;
                            });
                        }
                    }
                }
            }
        });
        *self.pipeline_feed_task.lock() = Some(task);
    }

    fn stop_pipeline_feed(&self) {
        if let Some(sender) = self.pipeline_feed_shutdown.lock().take() {
            let _ = sender.send(true);
        }
        if let Some(handle) = self.pipeline_feed_task.lock().take() {
            handle.abort();
        }
        publish_pipeline_state(&self.pipeline_feed, &self.pipeline_feed_tx, |state| {
            *state = PipelineFeedState::default();
        });
    }

    pub fn persist_identity_workflow_state<T: Serialize>(&self, state: &T) -> ChainResult<()> {
        let encoded = serde_json::to_vec(state).map_err(|err| {
            ChainError::Config(format!(
                "failed to encode identity workflow state for persistence: {err}"
            ))
        })?;
        self.storage
            .write_metadata_blob(IDENTITY_WORKFLOW_KEY, encoded)
    }

    pub fn load_identity_workflow_state<T: DeserializeOwned>(&self) -> ChainResult<Option<T>> {
        let maybe_bytes = self.storage.read_metadata_blob(IDENTITY_WORKFLOW_KEY)?;
        match maybe_bytes {
            Some(bytes) => {
                let state = serde_json::from_slice(&bytes).map_err(|err| {
                    ChainError::Config(format!(
                        "failed to decode persisted identity workflow state: {err}"
                    ))
                })?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    pub fn clear_identity_workflow_state(&self) -> ChainResult<()> {
        self.storage.delete_metadata_blob(IDENTITY_WORKFLOW_KEY)
    }

    fn persist_identity_vrf_keypair(&self, keypair: &VrfKeypair) -> ChainResult<()> {
        let stored = StoredVrfKeypair {
            public_key: vrf_public_key_to_hex(&keypair.public),
            secret_key: vrf_secret_key_to_hex(&keypair.secret),
        };
        let encoded = serde_json::to_vec(&stored).map_err(|err| {
            ChainError::Config(format!(
                "failed to encode VRF keypair for wallet persistence: {err}"
            ))
        })?;
        self.storage.write_metadata_blob(IDENTITY_VRF_KEY, encoded)
    }

    fn load_identity_vrf_keypair(&self) -> ChainResult<Option<VrfKeypair>> {
        let maybe_bytes = self.storage.read_metadata_blob(IDENTITY_VRF_KEY)?;
        let Some(bytes) = maybe_bytes else {
            return Ok(None);
        };
        let stored: StoredVrfKeypair = serde_json::from_slice(&bytes).map_err(|err| {
            ChainError::Config(format!(
                "failed to decode persisted VRF keypair for wallet: {err}"
            ))
        })?;
        let secret = vrf_secret_key_from_hex(&stored.secret_key)?;
        let public = vrf_public_key_from_hex(&stored.public_key)?;
        Ok(Some(VrfKeypair { public, secret }))
    }

    fn load_or_generate_identity_vrf_keypair(&self) -> ChainResult<VrfKeypair> {
        if let Some(keypair) = self.load_identity_vrf_keypair()? {
            return Ok(keypair);
        }
        let keypair = generate_vrf_keypair()?;
        self.persist_identity_vrf_keypair(&keypair)?;
        Ok(keypair)
    }

    pub fn build_identity_declaration(&self) -> ChainResult<IdentityDeclaration> {
        let accounts = self.storage.load_accounts()?;
        let mut tip_height = 0;
        if let Some(metadata) = self.storage.tip()? {
            tip_height = metadata.height.saturating_add(1);
        }
        let (ledger, _) = self.load_ledger_from_accounts(accounts)?;
        ledger.sync_epoch_for_height(tip_height);
        let epoch_nonce = ledger.current_epoch_nonce();
        let state_root = hex::encode(ledger.state_root());
        let identity_root = hex::encode(ledger.identity_root());

        let wallet_pk = hex::encode(self.keypair.public.to_bytes());
        let wallet_addr = self.address.clone();
        let vrf_keypair = self.load_or_generate_identity_vrf_keypair()?;
        let vrf = evaluate_vrf(&epoch_nonce, 0, &wallet_addr, 0, Some(&vrf_keypair.secret))?;
        let commitment_proof = ledger.identity_commitment_proof(&wallet_addr);
        let genesis = IdentityGenesis {
            wallet_pk,
            wallet_addr,
            vrf_public_key: vrf_public_key_to_hex(&vrf_keypair.public),
            vrf_proof: vrf.clone(),
            epoch_nonce: hex::encode(epoch_nonce),
            state_root,
            identity_root,
            initial_reputation: 0,
            commitment_proof: commitment_proof.clone(),
        };

        let prover = self.stark_prover();
        let witness = prover.build_identity_witness(&genesis)?;
        let commitment_hex = witness.commitment.clone();
        let start = Instant::now();
        let proof = prover.prove_identity(witness)?;
        let duration = start.elapsed();
        self.record_proof_generation(&proof, None, duration);
        let identity_proof = IdentityProof {
            commitment: commitment_hex,
            zk_proof: proof,
        };
        let declaration = IdentityDeclaration {
            genesis,
            proof: identity_proof,
        };
        declaration.verify()?;
        Ok(declaration)
    }

    pub fn account_summary(&self) -> ChainResult<WalletAccountSummary> {
        let account = self
            .storage
            .read_account(&self.address)?
            .ok_or_else(|| ChainError::Config("wallet account not found".into()))?;
        Ok(self.summarize_account(&account))
    }

    pub fn account_by_address(&self, address: &Address) -> ChainResult<Option<Account>> {
        self.storage.read_account(address)
    }

    pub fn account_summary_for(
        &self,
        address: &Address,
    ) -> ChainResult<Option<WalletAccountSummary>> {
        let account = match self.account_by_address(address)? {
            Some(account) => account,
            None => return Ok(None),
        };
        Ok(Some(self.summarize_account(&account)))
    }

    pub fn accounts_snapshot(&self) -> ChainResult<Vec<Account>> {
        self.storage.load_accounts()
    }

    pub fn persist_utxo_snapshot(
        &self,
        snapshot: &[(UtxoOutpoint, StoredUtxo)],
    ) -> ChainResult<()> {
        self.storage.persist_utxo_snapshot(snapshot)
    }

    pub fn unspent_utxos(&self, owner: &Address) -> ChainResult<Vec<UtxoRecord>> {
        let accounts = self.storage.load_accounts()?;
        let (ledger, has_snapshot) = self.load_ledger_from_accounts(accounts)?;
        if !has_snapshot {
            return Err(ChainError::Config(
                "wallet utxo snapshot not available".into(),
            ));
        }
        Ok(ledger.utxos_for_owner(owner))
    }

    pub fn build_transaction(
        &self,
        to: Address,
        amount: u128,
        fee: u64,
        memo: Option<String>,
    ) -> ChainResult<Transaction> {
        let account = self
            .storage
            .read_account(&self.address)?
            .ok_or_else(|| ChainError::Transaction("wallet account not found".into()))?;
        let accounts = self.storage.load_accounts()?;
        let (ledger, _) = self.load_ledger_from_accounts(accounts)?;
        let thresholds = ledger.reputation_params().tier_thresholds;
        let minimum_tier = minimum_transaction_tier(&thresholds);
        let derived_tier = transaction_tier_requirement(&account.reputation, &thresholds)
            .map_err(map_tier_requirement_error)?;
        if account.reputation.tier < minimum_tier {
            return Err(ChainError::Transaction(format!(
                "wallet reputation tier {:?} below governance minimum {:?}",
                account.reputation.tier, minimum_tier
            )));
        }
        let required_tier = derived_tier.max(minimum_tier);
        if account.reputation.tier < required_tier {
            return Err(ChainError::Transaction(format!(
                "wallet reputation tier {:?} below required {:?}",
                account.reputation.tier, required_tier
            )));
        }
        let total = amount
            .checked_add(fee as u128)
            .ok_or_else(|| ChainError::Transaction("amount overflow".into()))?;
        if account.balance < total {
            return Err(ChainError::Transaction("insufficient balance".into()));
        }
        let nonce = account.nonce + 1;
        Ok(Transaction::new(
            self.address.clone(),
            to,
            amount,
            fee,
            nonce,
            memo,
        ))
    }

    pub fn preview_send(
        &self,
        to: Address,
        amount: u128,
        fee: u64,
        memo: Option<String>,
    ) -> ChainResult<SendPreview> {
        let account = self
            .storage
            .read_account(&self.address)?
            .ok_or_else(|| ChainError::Transaction("wallet account not found".into()))?;
        let total = amount
            .checked_add(fee as u128)
            .ok_or_else(|| ChainError::Transaction("amount overflow".into()))?;
        let remaining_balance = account.balance.saturating_sub(total);
        Ok(SendPreview {
            from: self.address.clone(),
            to,
            amount,
            fee,
            memo,
            nonce: account.nonce + 1,
            balance_before: account.balance,
            balance_after: remaining_balance,
        })
    }

    pub fn sign_transaction(&self, tx: Transaction) -> SignedTransaction {
        let signature = sign_message(&self.keypair, &tx.canonical_bytes());
        SignedTransaction::new(tx, signature, &self.keypair.public)
    }

    pub fn prove_transaction(&self, tx: &SignedTransaction) -> ChainResult<TransactionProofBundle> {
        let prover = self.stark_prover();
        let witness = prover.build_transaction_witness(tx)?;
        let start = Instant::now();
        let proof = prover.prove_transaction(witness.clone())?;
        let duration = start.elapsed();
        let proof_payload = match &proof {
            ChainProof::Stwo(stark) => Some(stark.payload.clone()),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => None,
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => None,
        };
        let payload_bytes = proof_payload
            .as_ref()
            .and_then(Self::proof_payload_size_from_payload);
        self.record_proof_generation(&proof, payload_bytes, duration);
        Ok(TransactionProofBundle::new(
            tx.clone(),
            proof,
            Some(witness),
            proof_payload,
        ))
    }

    pub fn generate_uptime_proof(&self) -> ChainResult<UptimeProof> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window_end = now;
        let window_start = window_end.saturating_sub(3600);
        let node_clock = now;

        let tip_metadata = self.storage.tip()?;
        let (tip_height, head_hash) = match tip_metadata {
            Some(meta) => (meta.height, meta.hash),
            None => (0, hex::encode([0u8; 32])),
        };

        let accounts = self.storage.load_accounts()?;
        let (ledger, _) = self.load_ledger_from_accounts(accounts)?;
        ledger.sync_epoch_for_height(tip_height);
        let epoch = ledger.current_epoch().max(1);

        let claim = UptimeClaim {
            wallet_address: self.address.clone(),
            node_clock,
            epoch,
            head_hash,
            window_start,
            window_end,
        };
        let prover = self.stark_prover();
        let witness = prover.build_uptime_witness(&claim)?;
        let start = Instant::now();
        let proof = prover.prove_uptime(witness)?;
        let duration = start.elapsed();
        self.record_proof_generation(&proof, None, duration);
        Ok(UptimeProof::new(claim, proof))
    }

    pub fn history(&self) -> ChainResult<Vec<HistoryEntry>> {
        #[cfg(feature = "vendor_electrs")]
        if let Some(mut history) = self.history_from_tracker()? {
            self.annotate_history_with_pipeline(&mut history);
            return Ok(history);
        }

        let mut history = self.legacy_history()?;
        self.annotate_history_with_pipeline(&mut history);
        Ok(history)
    }

    fn summarize_account(&self, account: &Account) -> WalletAccountSummary {
        let mut summary = WalletAccountSummary {
            address: account.address.clone(),
            balance: account.balance,
            nonce: account.nonce,
            reputation_score: account.reputation.score,
            tier: account.reputation.tier.clone(),
            uptime_hours: account.reputation.timetokes.hours_online,
            mempool_delta: None,
        };

        #[cfg(feature = "vendor_electrs")]
        if account.address == self.address {
            summary.mempool_delta = self.script_status_metadata().map(|entries| {
                entries
                    .into_iter()
                    .map(|meta| meta.mempool_delta)
                    .sum::<i64>()
            });
        }

        summary
    }

    fn estimate_reputation_delta(&self, tx: &SignedTransaction) -> i64 {
        if tx.payload.to == self.address {
            1
        } else if tx.payload.from == self.address {
            -1
        } else {
            0
        }
    }

    pub fn receive_addresses(&self, count: usize) -> Vec<ReceiveTabAddress> {
        (0..count)
            .map(|index| self.derive_address(index as u32))
            .collect()
    }

    pub fn derive_address(&self, index: u32) -> ReceiveTabAddress {
        let mut seed = Vec::new();
        seed.extend_from_slice(self.address.as_bytes());
        seed.extend_from_slice(&index.to_be_bytes());
        let hash: [u8; 32] = Blake2sHasher::hash(&seed).into();
        ReceiveTabAddress {
            derivation_index: index,
            address: hex::encode(hash),
        }
    }

    pub fn node_metrics(&self) -> ChainResult<NodeTabMetrics> {
        let account = self
            .storage
            .read_account(&self.address)?
            .ok_or_else(|| ChainError::Config("wallet account not found".into()))?;
        let feed_state = self.pipeline_feed.read().clone();
        #[cfg(feature = "vendor_electrs")]
        let tracker_metrics = {
            let guard = self.electrs_handles.lock();
            guard
                .as_ref()
                .and_then(|handles| handles.tracker.as_ref())
                .map(|tracker| {
                    let height = tracker.chain().height() as u64;
                    let hash = hex::encode(tracker.chain().tip().as_bytes());
                    (height, Some(hash), height.saturating_add(1))
                })
        };
        #[cfg(not(feature = "vendor_electrs"))]
        let tracker_metrics: Option<(u64, Option<String>, u64)> = None;

        let (latest_block_height, latest_block_hash, total_blocks) =
            if let Some(metrics) = tracker_metrics {
                metrics
            } else {
                let tip = self.storage.tip()?;
                let latest_height = tip.as_ref().map(|meta| meta.height).unwrap_or(0);
                let latest_hash = tip.as_ref().map(|meta| meta.hash.clone());
                let total = self.storage.load_blockchain()?.len() as u64;
                (latest_height, latest_hash, total)
            };
        Ok(NodeTabMetrics {
            reputation_score: account.reputation.score,
            tier: account.reputation.tier.clone(),
            uptime_hours: account.reputation.timetokes.hours_online,
            latest_block_height,
            latest_block_hash,
            total_blocks,
            slashing_alerts: feed_state.slashing_events,
            pipeline_errors: feed_state.errors,
        })
    }

    pub fn pipeline_dashboard(
        &self,
        orchestrator: &PipelineOrchestrator,
    ) -> PipelineDashboardSnapshot {
        self.ensure_pipeline_subscription(orchestrator);
        self.pipeline_feed.read().dashboard.clone()
    }

    pub async fn wait_for_pipeline_stage(
        &self,
        orchestrator: &PipelineOrchestrator,
        hash: &str,
        stage: PipelineStage,
        timeout: Duration,
    ) -> ChainResult<()> {
        orchestrator.wait_for_stage(hash, stage, timeout).await
    }

    pub fn shutdown_pipeline(&self, orchestrator: &PipelineOrchestrator) {
        orchestrator.shutdown();
        self.stop_pipeline_feed();
    }

    pub fn latest_consensus_receipt(&self) -> ChainResult<Option<ConsensusReceipt>> {
        let tip = match self.storage.tip()? {
            Some(tip) => tip,
            None => return Ok(None),
        };
        let block = match self.storage.read_block(tip.height)? {
            Some(block) => block,
            None => return Ok(None),
        };
        let certificate = &block.consensus;
        let commit =
            Natural::from_str(&certificate.commit_power).unwrap_or_else(|_| Natural::from(0u32));
        let quorum = Natural::from_str(&certificate.quorum_threshold)
            .unwrap_or_else(|_| Natural::from(0u32));
        Ok(Some(ConsensusReceipt {
            height: block.header.height,
            block_hash: block.hash.clone(),
            proposer: block.header.proposer.clone(),
            round: certificate.round,
            total_power: certificate.total_power.clone(),
            quorum_threshold: certificate.quorum_threshold.clone(),
            pre_vote_power: certificate.pre_vote_power.clone(),
            pre_commit_power: certificate.pre_commit_power.clone(),
            commit_power: certificate.commit_power.clone(),
            observers: certificate.observers,
            quorum_reached: commit >= quorum && commit > Natural::from(0u32),
        }))
    }

    pub fn reputation_audit(&self) -> ChainResult<ReputationAudit> {
        let account = self
            .storage
            .read_account(&self.address)?
            .ok_or_else(|| ChainError::Config("wallet account not found".into()))?;
        Ok(ReputationAudit::from_account(&account))
    }

    fn record_proof_generation(
        &self,
        proof: &ChainProof,
        payload_bytes: Option<u64>,
        duration: Duration,
    ) {
        if let Some(kind) = Self::metrics_proof_kind(proof) {
            self.metrics
                .record_proof_generation_duration(kind, duration);
            let size = payload_bytes
                .or_else(|| Self::proof_payload_size_from_proof(proof));
            if let Some(bytes) = size {
                self.metrics.record_proof_generation_size(kind, bytes);
            }
        }
    }

    fn metrics_proof_kind(proof: &ChainProof) -> Option<ProofKind> {
        match proof {
            ChainProof::Stwo(_) => Some(ProofKind::Stwo),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => Some(ProofKind::Plonky3),
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => None,
        }
    }

    fn proof_payload_size_from_proof(proof: &ChainProof) -> Option<u64> {
        match proof {
            ChainProof::Stwo(stark) => Self::proof_payload_size_from_payload(&stark.payload),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(value) => serde_json::to_vec(value).ok().map(|bytes| bytes.len() as u64),
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(proof) => Some(proof.total_len() as u64),
        }
    }

    fn proof_payload_size_from_payload(payload: &ProofPayload) -> Option<u64> {
        bincode::serialize(payload)
            .map(|bytes| bytes.len() as u64)
            .ok()
    }
}

fn map_tier_requirement_error(err: TierRequirementError) -> ChainError {
    match err {
        TierRequirementError::MissingZsiValidation => {
            ChainError::Transaction("wallet identity must be ZSI-validated".into())
        }
        TierRequirementError::InsufficientTimetoke {
            required,
            available,
        } => ChainError::Transaction(format!(
            "wallet timetoke balance {available}h below required {required}h"
        )),
    }
}

fn detect_pipeline_timeout(entry: &HistoryEntry, flow: &FlowSnapshot) -> Option<bool> {
    if !matches!(entry.status, HistoryStatus::Pending { .. }) {
        return None;
    }
    if flow.stages.is_empty() || !flow.stages.contains_key(&PipelineStage::MempoolAccepted) {
        return Some(true);
    }
    None
}

#[cfg(feature = "vendor_electrs")]
fn history_priority(entry: &HistoryEntry) -> u8 {
    match entry.status {
        HistoryStatus::Confirmed { .. } => 3,
        HistoryStatus::Pruned { .. } => 2,
        HistoryStatus::Pending { .. } => 1,
    }
}

#[cfg(feature = "vendor_electrs")]
fn merge_history_metadata(existing: &mut HistoryEntry, other: &HistoryEntry) {
    if existing.transaction.is_none() {
        existing.transaction = other.transaction.clone();
    }
    if existing.pending_summary.is_none() {
        existing.pending_summary = other.pending_summary.clone();
    }
    if existing.status_digest.is_none() {
        existing.status_digest = other.status_digest.clone();
    }
    if existing.proof_envelope.is_none() {
        existing.proof_envelope = other.proof_envelope.clone();
    }
    if existing.double_spend.is_none() {
        existing.double_spend = other.double_spend;
    }
    if existing.reputation_delta == 0 {
        existing.reputation_delta = other.reputation_delta;
    }
    if matches!(existing.status, HistoryStatus::Pending { .. })
        && !matches!(other.status, HistoryStatus::Pending { .. })
    {
        existing.status = other.status.clone();
    }
    #[cfg(feature = "backend-rpp-stark")]
    if existing.vrf_audit.is_none() {
        existing.vrf_audit = other.vrf_audit.clone();
    }
    if existing.conflict.is_none() {
        existing.conflict = other.conflict.clone();
    }
}

#[cfg(feature = "vendor_electrs")]
fn apply_tracker_metadata(mut entry: HistoryEntry, view: &TrackerHistoryView) -> HistoryEntry {
    if view.status_digest.is_some() {
        entry.status_digest = view.status_digest;
    }
    if view.proof_envelope.is_some() {
        entry.proof_envelope = view.proof_envelope.clone();
    }
    if let Some(double_spend) = view.entry.double_spend() {
        entry.double_spend = Some(double_spend);
    }
    #[cfg(feature = "backend-rpp-stark")]
    if let Some(audit) = view.vrf_audit.clone() {
        entry.vrf_audit = Some(audit);
    }
    #[cfg(feature = "backend-rpp-stark")]
    if let Some(conflict) = view.entry.conflict() {
        entry.conflict = Some(conflict.to_string());
    }
    entry
}
