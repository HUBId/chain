use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::Keypair;
use malachite::Natural;
use parking_lot::RwLock;
#[cfg(feature = "vendor_electrs")]
use parking_lot::Mutex;
#[cfg(feature = "vendor_electrs")]
use tokio::sync::broadcast;
#[cfg(feature = "vendor_electrs")]
use tokio::sync::watch;
use serde::{Serialize, de::DeserializeOwned};
use crate::proof_backend::Blake2sHasher;
use tokio::sync::Mutex as AsyncMutex;
#[cfg(feature = "vendor_electrs")]
use serde_json;
#[cfg(feature = "vendor_electrs")]
use std::path::Path;
#[cfg(feature = "vendor_electrs")]
use tokio::task::JoinHandle;
#[cfg(feature = "vendor_electrs")]
use tokio::time;

use crate::config::NodeConfig;
use crate::consensus::evaluate_vrf;
use crate::crypto::{
    StoredVrfKeypair, VrfKeypair, address_from_public_key, generate_vrf_keypair, sign_message,
    vrf_public_key_from_hex, vrf_public_key_to_hex, vrf_secret_key_from_hex, vrf_secret_key_to_hex,
};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::{DEFAULT_EPOCH_LENGTH, Ledger, ReputationAudit};
use crate::node::NodeHandle;
use crate::orchestration::{PipelineDashboardSnapshot, PipelineOrchestrator, PipelineStage};
use crate::proof_system::ProofProver;
use crate::reputation::Tier;
use crate::rpp::{UtxoOutpoint, UtxoRecord};
use crate::state::StoredUtxo;
use crate::storage::Storage;
use crate::stwo::prover::WalletProver;
use crate::types::{
    Account, Address, IdentityDeclaration, IdentityGenesis, IdentityProof, SignedTransaction,
    Transaction, TransactionProofBundle, UptimeClaim, UptimeProof,
};
#[cfg(feature = "vendor_electrs")]
use log::{debug, warn};
#[cfg(feature = "vendor_electrs")]
use rpp::runtime::node::MempoolStatus;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::config::ElectrsConfig;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::firewood_adapter::RuntimeAdapters;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::init::{initialize, ElectrsHandles};
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::ScriptHashStatus;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::rpp_ledger::bitcoin::Script;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::types::{
    LedgerScriptPayload, ScriptHash, StatusDigest, encode_ledger_script,
};
#[cfg(feature = "vendor_electrs")]
use sha2::{Digest, Sha256};
#[cfg(feature = "vendor_electrs")]
use rpp_p2p::GossipTopic;

use super::workflows::synthetic_account_utxos;
use super::{WalletNodeRuntime, start_node};

use super::tabs::{HistoryEntry, HistoryStatus, NodeTabMetrics, ReceiveTabAddress, SendPreview};

const IDENTITY_WORKFLOW_KEY: &[u8] = b"wallet_identity_workflow";
const IDENTITY_VRF_KEY: &[u8] = b"wallet_identity_vrf_keypair";
const NODE_RUNTIME_CONFIG_KEY: &[u8] = b"wallet_node_runtime_config";
#[cfg(feature = "vendor_electrs")]
const ELECTRS_CONFIG_KEY: &[u8] = b"wallet_electrs_config";
#[cfg(feature = "vendor_electrs")]
type ElectrsHandlesGuard<'a> =
    parking_lot::lock_api::MutexGuard<'a, parking_lot::RawMutex, Option<ElectrsHandles>>;

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
) {
    let mut interval = time::interval(Duration::from_secs(5));
    loop {
        let should_sync = if let Some(receiver) = block_rx.as_mut() {
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
        } else {
            tokio::select! {
                _ = interval.tick() => true,
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                    false
                }
            }
        };

        if !should_sync {
            continue;
        }

        run_tracker_iteration(&handles, &statuses, &snapshot);
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
        compute_mempool_fingerprint(status).map_err(|err| {
            warn!(target: "wallet::tracker", "mempool fingerprint error: {err}");
            err
        }).ok()
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
#[derive(Clone, Debug)]
pub struct TrackedScriptSnapshot {
    pub script_hash: String,
    pub status_digest: Option<StatusDigest>,
}

#[cfg(feature = "vendor_electrs")]
#[derive(Clone, Debug)]
pub struct TrackerSnapshot {
    pub scripts: Vec<TrackedScriptSnapshot>,
    pub mempool_fingerprint: Option<[u8; 32]>,
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
    node_runtime: Arc<AsyncMutex<Option<WalletNodeRuntime>>>,
    node_handle: Arc<RwLock<Option<NodeHandle>>>,
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
    pub fn new(storage: Storage, keypair: Keypair) -> Self {
        let address = address_from_public_key(&keypair.public);
        Self {
            storage,
            keypair: Arc::new(keypair),
            address,
            node_runtime: Arc::new(AsyncMutex::new(None)),
            node_handle: Arc::new(RwLock::new(None)),
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
        config: ElectrsConfig,
        handles: ElectrsHandles,
    ) -> ChainResult<Self> {
        let wallet = Self::new(storage, keypair);
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
    pub fn persist_electrs_config(&self, config: &ElectrsConfig) -> ChainResult<()> {
        let mut encoded = serde_json::to_vec(config).map_err(|err| {
            ChainError::Config(format!(
                "failed to encode wallet electrs config for persistence: {err}"
            ))
        })?;
        if encoded.is_empty() {
            encoded = b"{}".to_vec();
        }
        self.storage.write_metadata_blob(ELECTRS_CONFIG_KEY, encoded)?;
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
        let handles = initialize(&config, firewood_dir, index_dir, runtime_adapters)
            .map_err(|err| {
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

        let runtime_adapters = {
            let guard = self.electrs_handles.lock();
            guard
                .as_ref()
                .and_then(|handles| handles.firewood.runtime().cloned())
        };

        let block_notifications = match runtime_adapters {
            Some(adapters) => match adapters.node().subscribe_witness_gossip(GossipTopic::Blocks) {
                Ok(receiver) => Some(receiver),
                Err(err) => {
                    warn!(
                        target: "wallet::tracker",
                        "failed to subscribe to runtime gossip: {err}"
                    );
                    None
                }
            },
            None => None,
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        *self.tracker_shutdown.lock() = Some(shutdown_tx);

        let handles_arc = Arc::clone(&self.electrs_handles);
        let statuses_arc = Arc::clone(&self.tracker_statuses);
        let snapshot_arc = Arc::clone(&self.tracker_snapshot);
        let block_rx = block_notifications;

        let task = tokio::spawn(async move {
            tracker_sync_loop(
                handles_arc,
                statuses_arc,
                snapshot_arc,
                shutdown_rx,
                block_rx,
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
        let proof = prover.prove_identity(witness)?;
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
        Ok(WalletAccountSummary {
            address: account.address.clone(),
            balance: account.balance,
            nonce: account.nonce,
            reputation_score: account.reputation.score,
            tier: account.reputation.tier.clone(),
            uptime_hours: account.reputation.timetokes.hours_online,
        })
    }

    pub fn account_by_address(&self, address: &Address) -> ChainResult<Option<Account>> {
        self.storage.read_account(address)
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
        let mut records = ledger.utxos_for_owner(owner);
        if records.is_empty() && !has_snapshot {
            if let Some(account) = ledger.get_account(owner) {
                records = synthetic_account_utxos(owner, account.balance);
            }
        }
        Ok(records)
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
        let proof = prover.prove_transaction(witness.clone())?;
        let proof_payload = match &proof {
            ChainProof::Stwo(stark) => Some(stark.payload.clone()),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => None,
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => None,
        };
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
        let epoch = ledger.current_epoch();

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
        let proof = prover.prove_uptime(witness)?;
        Ok(UptimeProof::new(claim, proof))
    }

    pub fn history(&self) -> ChainResult<Vec<HistoryEntry>> {
        let blocks = self.storage.load_blockchain()?;
        let mut history = Vec::new();
        for block in blocks {
            for tx in &block.transactions {
                if tx.payload.from == self.address || tx.payload.to == self.address {
                    let status = HistoryStatus::Confirmed {
                        height: block.header.height,
                        timestamp: block.header.timestamp,
                    };
                    history.push(HistoryEntry {
                        transaction: tx.clone(),
                        status,
                        reputation_delta: self.estimate_reputation_delta(tx),
                    });
                }
            }
        }
        history.sort_by_key(|entry| entry.status.confirmation_height());
        Ok(history)
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
        let tip = self.storage.tip()?;
        let account = self
            .storage
            .read_account(&self.address)?
            .ok_or_else(|| ChainError::Config("wallet account not found".into()))?;
        Ok(NodeTabMetrics {
            reputation_score: account.reputation.score,
            tier: account.reputation.tier.clone(),
            uptime_hours: account.reputation.timetokes.hours_online,
            latest_block_height: tip.as_ref().map(|meta| meta.height).unwrap_or(0),
            latest_block_hash: tip.as_ref().map(|meta| meta.hash.clone()),
            total_blocks: self.storage.load_blockchain()?.len() as u64,
        })
    }

    pub fn pipeline_dashboard(
        &self,
        orchestrator: &PipelineOrchestrator,
    ) -> PipelineDashboardSnapshot {
        let receiver = orchestrator.subscribe_dashboard();
        receiver.borrow().clone()
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
        Ok(ReputationAudit {
            address: account.address.clone(),
            balance: account.balance,
            stake: account.stake.to_string(),
            score: account.reputation.score,
            tier: account.reputation.tier.clone(),
            uptime_hours: account.reputation.timetokes.hours_online,
            consensus_success: account.reputation.consensus_success,
            peer_feedback: account.reputation.peer_feedback,
            last_decay_timestamp: account.reputation.last_decay_timestamp,
            zsi_validated: account.reputation.zsi.validated,
            zsi_commitment: account.reputation.zsi.public_key_commitment.clone(),
            zsi_reputation_proof: account.reputation.zsi.reputation_proof.clone(),
        })
    }
}
