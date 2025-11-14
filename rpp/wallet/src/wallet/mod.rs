use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::wallet::{
    PolicyTierHooks, WalletFeeConfig, WalletPolicyConfig, WalletProverConfig,
};
use crate::db::{
    PendingLock, PendingLockMetadata, PolicySnapshot, TxCacheEntry, UtxoRecord, WalletStore,
    WalletStoreError,
};
use crate::engine::signing::{
    build_wallet_prover, ProverError as EngineProverError, ProverOutput, WalletProver,
};
use crate::engine::{
    DraftTransaction, EngineError, FeeQuote, SpendModel, WalletBalance, WalletEngine,
};
use crate::indexer::IndexerClient;
use crate::modes::watch_only::{WatchOnlyRecord, WatchOnlyStatus};
use crate::node_client::{BlockFeeSummary, ChainHead, MempoolInfo, NodeClient, NodeClientError};
use crate::proof_backend::Blake2sHasher;
use rpp::runtime::node::MempoolStatus;

mod runtime;

pub use self::runtime::{WalletSyncCoordinator, WalletSyncError};

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("engine error: {0}")]
    Engine(#[from] EngineError),
    #[error("prover error: {0}")]
    Prover(#[from] EngineProverError),
    #[error("node error: {0}")]
    Node(#[from] NodeClientError),
    #[error("sync error: {0}")]
    Sync(#[from] WalletSyncError),
    #[error("watch-only restriction: {0}")]
    WatchOnly(#[from] WatchOnlyError),
}

#[derive(Debug, thiserror::Error)]
pub enum WatchOnlyError {
    #[error("watch-only state unavailable")]
    StatePoisoned,
    #[error("watch-only mode does not permit signing or proving drafts")]
    SigningDisabled,
    #[error("watch-only mode does not permit broadcasting unsigned drafts")]
    BroadcastDisabled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletMode {
    Full { root_seed: [u8; 32] },
    WatchOnly(WatchOnlyRecord),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyPreview {
    pub min_confirmations: u32,
    pub dust_limit: u128,
    pub max_change_outputs: u32,
    pub spend_limit_daily: Option<u128>,
    pub pending_lock_timeout: u64,
    pub tier_hooks: PolicyTierHooks,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletPaths {
    pub keystore: PathBuf,
    pub backup: PathBuf,
}

impl WalletPaths {
    pub fn new(keystore: PathBuf, backup: PathBuf) -> Self {
        Self { keystore, backup }
    }

    pub fn for_data_dir(base: &Path) -> Self {
        Self {
            keystore: base.join("keystore.toml"),
            backup: base.join("backups"),
        }
    }
}

pub struct Wallet {
    store: Arc<WalletStore>,
    engine: Arc<WalletEngine>,
    node_client: Arc<dyn NodeClient>,
    prover: Arc<dyn WalletProver>,
    identifier: String,
    keystore_path: PathBuf,
    backup_path: PathBuf,
    watch_only: Arc<RwLock<Option<WatchOnlyRecord>>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TelemetryCounter {
    pub name: String,
    pub value: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TelemetryCounters {
    pub enabled: bool,
    pub counters: Vec<TelemetryCounter>,
}

impl Wallet {
    const DEFAULT_POLICY_LABEL: &'static str = "default";

    fn watch_only_read(
        &self,
    ) -> Result<RwLockReadGuard<'_, Option<WatchOnlyRecord>>, WatchOnlyError> {
        self.watch_only
            .read()
            .map_err(|_| WatchOnlyError::StatePoisoned)
    }

    fn watch_only_write(
        &self,
    ) -> Result<RwLockWriteGuard<'_, Option<WatchOnlyRecord>>, WatchOnlyError> {
        self.watch_only
            .write()
            .map_err(|_| WatchOnlyError::StatePoisoned)
    }

    fn ensure_signing_allowed(&self) -> Result<(), WatchOnlyError> {
        let guard = self.watch_only_read()?;
        if guard.is_some() {
            Err(WatchOnlyError::SigningDisabled)
        } else {
            Ok(())
        }
    }

    fn ensure_broadcast_allowed(&self) -> Result<(), WatchOnlyError> {
        let guard = self.watch_only_read()?;
        if guard.is_some() {
            Err(WatchOnlyError::BroadcastDisabled)
        } else {
            Ok(())
        }
    }

    pub fn new(
        store: Arc<WalletStore>,
        mode: WalletMode,
        policy: WalletPolicyConfig,
        fees: WalletFeeConfig,
        prover_config: WalletProverConfig,
        node_client: Arc<dyn NodeClient>,
        paths: WalletPaths,
    ) -> Result<Self, WalletError> {
        let (root_seed, watch_only_record, prover): (
            [u8; 32],
            Option<WatchOnlyRecord>,
            Arc<dyn WalletProver>,
        ) = match mode {
            WalletMode::Full { root_seed } => {
                if store.watch_only_record().map_err(store_error)?.is_some() {
                    let mut batch = store.batch().map_err(store_error)?;
                    batch.clear_watch_only();
                    batch.commit().map_err(store_error)?;
                }
                (root_seed, None, build_wallet_prover(&prover_config)?)
            }
            WalletMode::WatchOnly(record) => {
                let seed = record.derive_seed();
                let mut batch = store.batch().map_err(store_error)?;
                batch.put_watch_only(&record).map_err(store_error)?;
                batch.commit().map_err(store_error)?;
                let prover: Arc<dyn WalletProver> = Arc::new(DisabledWatchOnlyProver::default());
                (seed, Some(record), prover)
            }
        };
        let engine = Arc::new(WalletEngine::new(
            Arc::clone(&store),
            root_seed,
            policy,
            fees,
        )?);
        let identifier = engine.identifier();
        let WalletPaths { keystore, backup } = paths;
        Ok(Self {
            store,
            engine,
            node_client,
            prover,
            identifier,
            keystore_path: keystore,
            backup_path: backup,
            watch_only: Arc::new(RwLock::new(watch_only_record)),
        })
    }

    pub fn is_watch_only(&self) -> bool {
        self.watch_only_read()
            .map(|guard| guard.is_some())
            .unwrap_or(true)
    }

    pub fn watch_only_status(&self) -> Result<WatchOnlyStatus, WatchOnlyError> {
        let record = self.watch_only_read()?.clone();
        Ok(WatchOnlyStatus::from(record))
    }

    pub fn enable_watch_only(
        &self,
        record: WatchOnlyRecord,
    ) -> Result<WatchOnlyStatus, WalletError> {
        let mut batch = self.store.batch().map_err(store_error)?;
        batch.put_watch_only(&record).map_err(store_error)?;
        batch.commit().map_err(store_error)?;
        let mut guard = self.watch_only_write()?;
        *guard = Some(record.clone());
        Ok(WatchOnlyStatus::from(Some(record)))
    }

    pub fn disable_watch_only(&self) -> Result<WatchOnlyStatus, WalletError> {
        let mut batch = self.store.batch().map_err(store_error)?;
        batch.clear_watch_only();
        batch.commit().map_err(store_error)?;
        let mut guard = self.watch_only_write()?;
        *guard = None;
        Ok(WatchOnlyStatus::default())
    }

    pub fn address(&self) -> &str {
        &self.identifier
    }

    pub fn balance(&self) -> Result<WalletBalance, WalletError> {
        Ok(self.engine.balance()?)
    }

    pub fn list_utxos(&self) -> Result<Vec<UtxoRecord<'static>>, WalletError> {
        Ok(self.engine.list_utxos()?)
    }

    pub fn list_transactions(&self) -> Result<Vec<([u8; 32], TxCacheEntry<'static>)>, WalletError> {
        Ok(self.engine.list_transactions()?)
    }

    pub fn derive_address(&self, change: bool) -> Result<String, WalletError> {
        let derived = if change {
            self.engine.next_internal_address()?
        } else {
            self.engine.next_external_address()?
        };
        Ok(derived.address)
    }

    pub fn create_draft(
        &self,
        to: String,
        amount: u128,
        fee_rate: Option<u64>,
    ) -> Result<DraftTransaction, WalletError> {
        Ok(self
            .engine
            .create_draft(to, amount, fee_rate, Some(self.node_client.as_ref()))?)
    }

    pub fn pending_locks(&self) -> Result<Vec<PendingLock>, WalletError> {
        Ok(self.engine.pending_locks()?)
    }

    pub fn release_stale_locks(&self) -> Result<Vec<PendingLock>, WalletError> {
        Ok(self.engine.release_stale_locks()?)
    }

    pub fn release_pending_locks(&self) -> Result<Vec<PendingLock>, WalletError> {
        Ok(self.engine.release_pending_locks()?)
    }

    pub fn abort_draft(&self, draft: &DraftTransaction) -> Result<Vec<PendingLock>, WalletError> {
        Ok(self
            .engine
            .release_locks_for_inputs(draft.inputs.iter().map(|input| &input.outpoint))?)
    }

    pub fn policy_preview(&self) -> PolicyPreview {
        let policy = self.engine.policy_engine();
        PolicyPreview {
            min_confirmations: policy.min_confirmations(),
            dust_limit: policy.dust_limit(),
            max_change_outputs: policy.max_change_outputs(),
            spend_limit_daily: policy.daily_limit(),
            pending_lock_timeout: self.engine.pending_lock_timeout(),
            tier_hooks: self.engine.tier_hooks().clone(),
        }
    }

    pub fn get_policy_snapshot(&self) -> Result<Option<PolicySnapshot>, WalletError> {
        self.store
            .get_policy_snapshot(Self::DEFAULT_POLICY_LABEL)
            .map_err(store_error)
    }

    pub fn set_policy_snapshot(
        &self,
        statements: Vec<String>,
    ) -> Result<PolicySnapshot, WalletError> {
        let mut batch = self.store.batch().map_err(store_error)?;
        let next_revision = self
            .get_policy_snapshot()?
            .map(|snapshot| snapshot.revision.saturating_add(1))
            .unwrap_or(1);
        let snapshot = PolicySnapshot::new(next_revision, current_timestamp_ms(), statements);
        batch
            .put_policy_snapshot(Self::DEFAULT_POLICY_LABEL, &snapshot)
            .map_err(store_error)?;
        batch.commit().map_err(store_error)?;
        Ok(snapshot)
    }

    pub fn sign_and_prove(&self, draft: &DraftTransaction) -> Result<ProverOutput, WalletError> {
        self.ensure_signing_allowed()?;
        match self.prover.prove(draft) {
            Ok(output) => {
                let txid = lock_fingerprint(draft);
                let proof_bytes = output
                    .proof
                    .as_ref()
                    .map(|bytes| bytes.as_slice().len() as u64);
                let metadata = PendingLockMetadata::new(
                    output.backend.clone(),
                    output.witness_bytes as u64,
                    output.duration_ms,
                    proof_bytes,
                );
                self.engine.attach_locks_to_txid(
                    draft.inputs.iter().map(|input| &input.outpoint),
                    txid,
                    Some(metadata),
                )?;
                Ok(output)
            }
            Err(err) => {
                self.engine
                    .release_locks_for_inputs(draft.inputs.iter().map(|input| &input.outpoint))?;
                Err(err.into())
            }
        }
    }

    pub fn broadcast(&self, draft: &DraftTransaction) -> Result<(), WalletError> {
        self.ensure_broadcast_allowed()?;
        let txid = lock_fingerprint(draft);
        match self.node_client.submit_tx(draft) {
            Ok(()) => {
                self.engine.release_locks_by_txid(&txid)?;
                Ok(())
            }
            Err(err) => {
                self.engine
                    .release_locks_for_inputs(draft.inputs.iter().map(|input| &input.outpoint))?;
                Err(err.into())
            }
        }
    }

    pub fn broadcast_raw(&self, tx_bytes: &[u8]) -> Result<(), WalletError> {
        Ok(self.node_client.submit_raw_tx(tx_bytes)?)
    }

    pub fn estimate_fee(&self, confirmation_target: u16) -> Result<u64, WalletError> {
        Ok(self.node_client.estimate_fee(confirmation_target)?)
    }

    pub fn chain_head(&self) -> Result<ChainHead, WalletError> {
        Ok(self.node_client.chain_head()?)
    }

    pub fn mempool_status(&self) -> Result<MempoolStatus, WalletError> {
        Ok(self.node_client.mempool_status()?)
    }

    pub fn mempool_info(&self) -> Result<MempoolInfo, WalletError> {
        Ok(self.node_client.mempool_info()?)
    }

    pub fn recent_blocks(&self, limit: usize) -> Result<Vec<BlockFeeSummary>, WalletError> {
        Ok(self.node_client.recent_blocks(limit)?)
    }

    pub fn telemetry_counters(&self) -> TelemetryCounters {
        TelemetryCounters::default()
    }

    pub fn store(&self) -> Arc<WalletStore> {
        Arc::clone(&self.store)
    }

    pub fn keystore_path(&self) -> &PathBuf {
        &self.keystore_path
    }

    pub fn backup_dir(&self) -> &PathBuf {
        &self.backup_path
    }

    pub fn engine(&self) -> &WalletEngine {
        self.engine.as_ref()
    }

    pub fn engine_handle(&self) -> Arc<WalletEngine> {
        Arc::clone(&self.engine)
    }

    pub fn latest_fee_quote(&self) -> Option<FeeQuote> {
        self.engine.fee_estimator().last_quote()
    }

    pub fn start_sync_coordinator(
        &self,
        indexer_client: Arc<dyn IndexerClient>,
    ) -> Result<WalletSyncCoordinator, WalletError> {
        WalletSyncCoordinator::start(self.engine_handle(), indexer_client).map_err(Into::into)
    }
}

#[derive(Default)]
struct DisabledWatchOnlyProver;

impl WalletProver for DisabledWatchOnlyProver {
    fn backend(&self) -> &'static str {
        "watch-only"
    }

    fn prove(&self, _draft: &DraftTransaction) -> Result<ProverOutput, EngineProverError> {
        Err(EngineProverError::Unsupported(
            "watch-only mode does not support proving",
        ))
    }
}

fn lock_fingerprint(draft: &DraftTransaction) -> [u8; 32] {
    let mut material = Vec::new();
    for input in &draft.inputs {
        material.extend_from_slice(&input.outpoint.txid);
        material.extend_from_slice(&input.outpoint.index.to_be_bytes());
        material.extend_from_slice(&input.value.to_be_bytes());
        material.extend_from_slice(&input.confirmations.to_be_bytes());
    }
    for output in &draft.outputs {
        material.extend_from_slice(output.address.as_bytes());
        material.extend_from_slice(&output.value.to_be_bytes());
        material.push(output.change as u8);
    }
    material.extend_from_slice(&draft.fee_rate.to_be_bytes());
    material.extend_from_slice(&draft.fee.to_be_bytes());
    match &draft.spend_model {
        SpendModel::Exact { amount } => {
            material.push(0);
            material.extend_from_slice(&amount.to_be_bytes());
        }
        SpendModel::Sweep => material.push(1),
        SpendModel::Account { debit } => {
            material.push(2);
            material.extend_from_slice(&debit.to_be_bytes());
        }
    }
    Blake2sHasher::hash(&material).into()
}

fn store_error(error: WalletStoreError) -> WalletError {
    WalletError::Engine(error.into())
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::sync::Arc;
    use std::time::Duration;

    use tempfile::tempdir;

    use crate::config::wallet::{WalletFeeConfig, WalletPolicyConfig, WalletProverConfig};
    use crate::db::{UtxoOutpoint, UtxoRecord};
    use crate::engine::WalletEngine;
    use crate::modes::watch_only::WatchOnlyRecord;
    use crate::node_client::{NodeClient, StubNodeClient};
    use crate::wallet::WatchOnlyError;

    struct SleepyWalletProver {
        jobs: ProverJobManager,
        sleep: Duration,
    }

    impl SleepyWalletProver {
        fn new(timeout_secs: u64, sleep: Duration) -> Self {
            let mut config = WalletProverConfig::default();
            config.job_timeout_secs = timeout_secs;
            config.max_concurrency = 1;
            Self {
                jobs: ProverJobManager::new(&config),
                sleep,
            }
        }
    }

    impl WalletProver for SleepyWalletProver {
        fn backend(&self) -> &'static str {
            "sleepy"
        }

        fn prove(&self, _draft: &DraftTransaction) -> Result<ProverOutput, ProverError> {
            let sleep = self.sleep;
            self.jobs.run_job(move || {
                std::thread::sleep(sleep);
                Ok(ProverOutput {
                    backend: "sleepy".into(),
                    proof: None,
                    witness_bytes: 0,
                    duration_ms: sleep.as_millis() as u64,
                })
            })
        }
    }

    fn seed_store_with_utxo(store: &Arc<WalletStore>, value: u128) {
        let mut batch = store.batch().expect("wallet batch");
        let utxo = UtxoRecord::new(
            UtxoOutpoint::new([42u8; 32], 0),
            "wallet.utxo".into(),
            value,
            Cow::Owned(vec![]),
            Some(1),
        );
        batch.put_utxo(&utxo).expect("insert utxo");
        batch.commit().expect("commit utxo");
    }

    fn sample_wallet_configs() -> (WalletPolicyConfig, WalletFeeConfig) {
        (WalletPolicyConfig::default(), WalletFeeConfig::default())
    }

    fn build_wallet_with_prover(
        store: Arc<WalletStore>,
        policy: WalletPolicyConfig,
        fees: WalletFeeConfig,
        prover: Arc<dyn WalletProver>,
        node_client: Arc<dyn NodeClient>,
    ) -> Wallet {
        let engine = Arc::new(
            WalletEngine::new(Arc::clone(&store), [7u8; 32], policy, fees).expect("engine"),
        );
        let identifier = engine.identifier();
        Wallet {
            store,
            engine,
            node_client,
            prover,
            identifier,
            watch_only: Arc::new(RwLock::new(None)),
        }
    }

    fn make_draft(wallet: &Wallet, amount: u128) -> DraftTransaction {
        wallet
            .create_draft("wallet.recipient".into(), amount, None)
            .expect("draft")
    }

    fn runtime_guard() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
    }

    #[cfg(feature = "prover-mock")]
    #[test]
    fn mock_backend_records_metadata_on_pending_locks() {
        let runtime = runtime_guard();
        let _guard = runtime.enter();

        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        seed_store_with_utxo(&store, 50_000);

        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let mut config = WalletProverConfig::default();
        config.max_witness_bytes = 1_000_000;
        let keystore = tempdir.path().join("keystore.toml");
        let backup = tempdir.path().join("backups");
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [3u8; 32],
            },
            policy,
            fees,
            config,
            Arc::clone(&node_client),
            WalletPaths::new(keystore, backup),
        )
        .expect("wallet");

        let draft = make_draft(&wallet, 10_000);
        let locks_before = wallet.pending_locks().expect("locks");
        assert!(!locks_before.is_empty());

        let output = wallet.sign_and_prove(&draft).expect("mock prove");
        assert_eq!(output.backend, "mock");
        assert!(output.proof.is_some());

        let locks = wallet.pending_locks().expect("locks after prove");
        assert_eq!(locks.len(), locks_before.len());
        let proof_bytes = output
            .proof
            .as_ref()
            .map(|bytes| bytes.as_ref().len() as u64);
        assert!(locks.iter().all(|lock| {
            lock.spending_txid.is_some()
                && lock.metadata.backend == "mock"
                && lock.metadata.witness_bytes == output.witness_bytes as u64
                && lock.metadata.prove_duration_ms == output.duration_ms
                && lock.metadata.proof_bytes == proof_bytes
        }));
        drop(tempdir);
    }

    #[cfg(feature = "prover-stwo")]
    #[test]
    fn stwo_backend_records_metadata_on_pending_locks() {
        let runtime = runtime_guard();
        let _guard = runtime.enter();

        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        seed_store_with_utxo(&store, 75_000);

        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let mut config = WalletProverConfig::default();
        config.enabled = true;
        config.mock_fallback = false;
        config.job_timeout_secs = 30;
        let keystore = tempdir.path().join("keystore.toml");
        let backup = tempdir.path().join("backups");
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [5u8; 32],
            },
            policy,
            fees,
            config,
            Arc::clone(&node_client),
            WalletPaths::new(keystore, backup),
        )
        .expect("wallet");

        let draft = make_draft(&wallet, 15_000);
        let locks_before = wallet.pending_locks().expect("locks");
        assert!(!locks_before.is_empty());

        let output = wallet.sign_and_prove(&draft).expect("stwo prove");
        assert_eq!(output.backend, "stwo");
        assert!(output.proof.is_some());

        let locks = wallet.pending_locks().expect("locks after prove");
        assert_eq!(locks.len(), locks_before.len());
        let proof_bytes = output
            .proof
            .as_ref()
            .map(|bytes| bytes.as_ref().len() as u64);
        assert!(locks.iter().all(|lock| {
            lock.spending_txid.is_some()
                && lock.metadata.backend == "stwo"
                && lock.metadata.witness_bytes == output.witness_bytes as u64
                && lock.metadata.prove_duration_ms == output.duration_ms
                && lock.metadata.proof_bytes == proof_bytes
        }));
        drop(tempdir);
    }

    #[test]
    fn timed_out_job_releases_pending_locks() {
        let runtime = runtime_guard();
        let _guard = runtime.enter();

        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        seed_store_with_utxo(&store, 60_000);

        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let prover: Arc<dyn WalletProver> =
            Arc::new(SleepyWalletProver::new(1, Duration::from_millis(1_500)));
        let wallet = build_wallet_with_prover(
            Arc::clone(&store),
            policy,
            fees,
            prover,
            Arc::clone(&node_client),
        );

        let draft = make_draft(&wallet, 20_000);
        assert!(!wallet.pending_locks().expect("locks before").is_empty());

        let err = wallet.sign_and_prove(&draft).expect_err("timeout error");
        assert!(matches!(
            err,
            WalletError::Prover(ProverError::Timeout(secs)) if secs == 1
        ));

        assert!(wallet.pending_locks().expect("locks after").is_empty());
        drop(tempdir);
    }

    #[cfg(feature = "prover-mock")]
    #[test]
    fn mock_backend_rejects_large_witnesses_and_releases_locks() {
        let runtime = runtime_guard();
        let _guard = runtime.enter();

        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        seed_store_with_utxo(&store, 55_000);

        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let mut config = WalletProverConfig::default();
        config.max_witness_bytes = 1;
        let keystore = tempdir.path().join("keystore.toml");
        let backup = tempdir.path().join("backups");
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [9u8; 32],
            },
            policy,
            fees,
            config,
            Arc::clone(&node_client),
            WalletPaths::new(keystore, backup),
        )
        .expect("wallet");

        let draft = make_draft(&wallet, 12_000);
        assert!(!wallet.pending_locks().expect("locks before").is_empty());

        let err = wallet
            .sign_and_prove(&draft)
            .expect_err("witness too large");
        assert!(matches!(
            err,
            WalletError::Prover(ProverError::WitnessTooLarge { limit, .. }) if limit == 1
        ));
        assert!(wallet.pending_locks().expect("locks after").is_empty());
        drop(tempdir);
    }

    #[test]
    fn watch_only_mode_persists_state_and_blocks_signing() {
        let runtime = runtime_guard();
        let _guard = runtime.enter();

        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        seed_store_with_utxo(&store, 40_000);

        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let keystore = tempdir.path().join("keystore.toml");
        let backup = tempdir.path().join("backups");
        let record = WatchOnlyRecord::new("wpkh(external)").with_birthday_height(Some(120));
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::WatchOnly(record.clone()),
            policy,
            fees,
            WalletProverConfig::default(),
            Arc::clone(&node_client),
            WalletPaths::new(keystore, backup),
        )
        .expect("wallet");

        assert!(wallet.is_watch_only());
        assert_eq!(store.watch_only_record().unwrap(), Some(record.clone()));

        let status = wallet.watch_only_status().expect("watch-only status");
        assert!(status.enabled);
        assert_eq!(status.birthday_height, Some(120));

        let balance = wallet.balance().expect("balance");
        assert!(balance.total() > 0);

        let draft = make_draft(&wallet, 10_000);
        let err = wallet.sign_and_prove(&draft).expect_err("sign blocked");
        assert!(matches!(
            err,
            WalletError::WatchOnly(WatchOnlyError::SigningDisabled)
        ));

        let err = wallet.broadcast(&draft).expect_err("broadcast blocked");
        assert!(matches!(
            err,
            WalletError::WatchOnly(WatchOnlyError::BroadcastDisabled)
        ));

        wallet
            .broadcast_raw(&[0u8, 1, 2])
            .expect("raw broadcast permitted");

        let disabled = wallet.disable_watch_only().expect("disable watch-only");
        assert!(!disabled.enabled);
        assert!(store.watch_only_record().unwrap().is_none());
        assert!(!wallet.is_watch_only());

        let reenabled = wallet
            .enable_watch_only(record.clone())
            .expect("re-enable watch-only");
        assert!(reenabled.enabled);
        assert_eq!(store.watch_only_record().unwrap(), Some(record));
    }

    #[cfg(feature = "prover-stwo")]
    #[test]
    fn stwo_backend_rejects_large_witnesses_and_releases_locks() {
        let runtime = runtime_guard();
        let _guard = runtime.enter();

        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        seed_store_with_utxo(&store, 65_000);

        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let mut config = WalletProverConfig::default();
        config.enabled = true;
        config.mock_fallback = false;
        config.max_witness_bytes = 1;
        let keystore = tempdir.path().join("keystore.toml");
        let backup = tempdir.path().join("backups");
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [11u8; 32],
            },
            policy,
            fees,
            config,
            Arc::clone(&node_client),
            WalletPaths::new(keystore, backup),
        )
        .expect("wallet");

        let draft = make_draft(&wallet, 18_000);
        assert!(!wallet.pending_locks().expect("locks before").is_empty());

        let err = wallet
            .sign_and_prove(&draft)
            .expect_err("witness too large");
        assert!(matches!(
            err,
            WalletError::Prover(ProverError::WitnessTooLarge { limit, .. }) if limit == 1
        ));
        assert!(wallet.pending_locks().expect("locks after").is_empty());
        drop(tempdir);
    }
}
