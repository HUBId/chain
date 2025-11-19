use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::wallet::{
    PolicyTierHooks, WalletFeeConfig, WalletHwConfig, WalletPolicyConfig, WalletProverBackend,
    WalletProverConfig, WalletZsiConfig,
};
use crate::db::{
    PendingLock, PendingLockMetadata, PolicySnapshot, StoredZsiArtifact, TxCacheEntry, UtxoRecord,
    WalletStore, WalletStoreError,
};
use crate::engine::signing::{
    build_wallet_prover, DraftProverContext, ProveResult, ProverError as EngineProverError,
    ProverIdentity, ProverMeta, WalletProver, WitnessPlan,
};
use crate::engine::{
    DerivationPath, DraftBundle, DraftTransaction, EngineError, FeeQuote, SpendModel,
    WalletBalance, WalletEngine,
};
#[cfg(feature = "wallet_hw")]
use crate::hw::{
    HardwareDevice, HardwarePublicKey, HardwareSignRequest, HardwareSignature, HardwareSigner,
    HardwareSignerError,
};
use crate::indexer::IndexerClient;
use crate::modes::watch_only::{WatchOnlyRecord, WatchOnlyStatus};
#[cfg(feature = "wallet_multisig_hooks")]
use crate::multisig::{
    clear_cosigner_registry, clear_scope, load_cosigner_registry, load_scope,
    store_cosigner_registry, store_scope, CosignerRegistry, MultisigError, MultisigScope,
};
use crate::node_client::MempoolStatus;
use crate::node_client::{BlockFeeSummary, ChainHead, MempoolInfo, NodeClient, NodeClientError};
use crate::proof_backend::{
    BackendError as WalletProverBackendError, Blake2sHasher, IdentityPublicInputs, ProofBackend,
    ProofBytes, WitnessBytes,
};
use crate::telemetry::{TelemetryCounters, WalletActionTelemetry};
#[cfg(feature = "wallet_zsi")]
use crate::zsi::ZsiBinder;
use crate::zsi::{self, LifecycleProof, ZsiOperation, ZsiRecord};
use crate::{WalletService, WalletServiceResult};
use prover_backend_interface::BackendError as ZsiBackendError;
use serde::{Deserialize, Serialize};

mod runtime;

pub use self::runtime::{WalletSyncCoordinator, WalletSyncError};

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("engine error: {0}")]
    Engine(#[from] EngineError),
    #[error("wallet prover backend disabled")]
    ProverBackendDisabled,
    #[error("wallet prover job timed out after {timeout_secs} seconds")]
    ProverTimeout { timeout_secs: u64 },
    #[error("wallet prover job was cancelled")]
    ProverCancelled,
    #[error("wallet prover is busy")]
    ProverBusy,
    #[error("wallet prover witness too large ({size} bytes > limit {limit})")]
    ProverWitnessTooLarge { size: usize, limit: u64 },
    #[error("wallet prover internal error: {reason}")]
    ProverInternal { reason: String },
    #[error("wallet prover requires proofs but backend returned none")]
    ProofMissing,
    #[error("node error: {0}")]
    Node(#[from] NodeClientError),
    #[error("sync error: {0}")]
    Sync(#[from] WalletSyncError),
    #[error("watch-only restriction: {0}")]
    WatchOnly(#[from] WatchOnlyError),
    #[cfg(feature = "wallet_multisig_hooks")]
    #[error("multisig error: {0}")]
    Multisig(#[from] MultisigError),
    #[error("wallet multisig support disabled at build time")]
    MultisigDisabled,
    #[error("zsi error: {0}")]
    Zsi(#[from] ZsiError),
    #[error("wallet hardware support disabled at build time")]
    HardwareFeatureDisabled,
    #[cfg(feature = "wallet_hw")]
    #[error("hardware signer error: {0}")]
    Hardware(#[from] HardwareSignerError),
    #[cfg(feature = "wallet_hw")]
    #[error("hardware signer not configured")]
    HardwareUnavailable,
    #[cfg(feature = "wallet_hw")]
    #[error("hardware signer state unavailable")]
    HardwareStatePoisoned,
    #[cfg(feature = "wallet_hw")]
    #[error("wallet hardware support disabled by configuration")]
    HardwareDisabled,
}

impl From<EngineProverError> for WalletError {
    fn from(error: EngineProverError) -> Self {
        match error {
            EngineProverError::Backend(inner) => map_prover_backend_error(inner),
            EngineProverError::Serialization(message) => {
                prover_internal(format!("serialization error: {message}"))
            }
            EngineProverError::Unsupported(context) => map_unsupported_backend(context),
            EngineProverError::Runtime(message) => {
                prover_internal(format!("runtime error: {message}"))
            }
            EngineProverError::Timeout(timeout_secs) => WalletError::ProverTimeout { timeout_secs },
            EngineProverError::Cancelled => WalletError::ProverCancelled,
            EngineProverError::Busy => WalletError::ProverBusy,
            EngineProverError::WitnessTooLarge { size, limit } => {
                WalletError::ProverWitnessTooLarge { size, limit }
            }
        }
    }
}

fn prover_internal(reason: impl Into<String>) -> WalletError {
    WalletError::ProverInternal {
        reason: reason.into(),
    }
}

const BACKEND_DISABLED_REASON: &str = "wallet prover backend disabled";

fn map_unsupported_backend(context: &'static str) -> WalletError {
    if context == BACKEND_DISABLED_REASON {
        WalletError::ProverBackendDisabled
    } else {
        prover_internal(format!("unsupported prover backend: {context}"))
    }
}

fn map_prover_backend_error(error: WalletProverBackendError) -> WalletError {
    match error {
        WalletProverBackendError::Unsupported(context) => map_unsupported_backend(context),
        WalletProverBackendError::Failure(reason) => {
            prover_internal(format!("backend failure: {reason}"))
        }
        WalletProverBackendError::Serialization(err) => {
            prover_internal(format!("backend serialization error: {err}"))
        }
    }
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

#[derive(Debug, thiserror::Error)]
pub enum ZsiError {
    #[error("zsi workflows disabled by configuration")]
    Disabled,
    #[error("zsi backend not configured")]
    BackendUnavailable,
    #[error("zsi backend unsupported")]
    Unsupported,
    #[error("zsi backend error: {0}")]
    Backend(#[from] ZsiBackendError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalletMode {
    Full { root_seed: [u8; 32] },
    WatchOnly(WatchOnlyRecord),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiProofRequest {
    pub operation: ZsiOperation,
    pub record: ZsiRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiVerifyRequest {
    pub operation: ZsiOperation,
    pub record: ZsiRecord,
    #[serde(with = "serde_bytes")]
    pub proof: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZsiBinding {
    pub operation: ZsiOperation,
    pub record: ZsiRecord,
    #[serde(with = "serde_bytes")]
    pub witness: Vec<u8>,
    pub inputs: IdentityPublicInputs,
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
    prover_config: WalletProverConfig,
    identifier: String,
    keystore_path: PathBuf,
    backup_path: PathBuf,
    watch_only: Arc<RwLock<Option<WatchOnlyRecord>>>,
    telemetry: Arc<WalletActionTelemetry>,
    zsi: WalletZsiState,
    hw_config: WalletHwConfig,
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
        hw_config: WalletHwConfig,
        zsi_config: WalletZsiConfig,
        zsi_backend: Option<Arc<dyn ProofBackend>>,
        node_client: Arc<dyn NodeClient>,
        paths: WalletPaths,
        telemetry: Arc<WalletActionTelemetry>,
    ) -> Result<Self, WalletError> {
        if hw_config.enabled && !cfg!(feature = "wallet_hw") {
            return Err(WalletError::HardwareFeatureDisabled);
        }
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
        let zsi = WalletZsiState::new(zsi_config, zsi_backend)?;
        Ok(Self {
            store,
            engine,
            node_client,
            prover,
            prover_config: prover_config.clone(),
            identifier,
            keystore_path: keystore,
            backup_path: backup,
            watch_only: Arc::new(RwLock::new(watch_only_record)),
            telemetry,
            zsi,
            hw_config,
        })
    }

    pub fn hardware_enabled(&self) -> bool {
        self.hw_config.enabled
    }

    #[cfg(feature = "wallet_hw")]
    fn ensure_hardware_enabled(&self) -> Result<(), WalletError> {
        if self.hw_config.enabled {
            Ok(())
        } else {
            Err(WalletError::HardwareDisabled)
        }
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
    ) -> Result<DraftBundle, WalletError> {
        Ok(self
            .engine
            .create_draft(to, amount, fee_rate, Some(self.node_client.as_ref()))?)
    }

    #[cfg(feature = "wallet_multisig_hooks")]
    pub fn multisig_scope(&self) -> Result<Option<MultisigScope>, WalletError> {
        load_scope(&self.store)
            .map_err(MultisigError::from)
            .map_err(WalletError::from)
    }

    #[cfg(not(feature = "wallet_multisig_hooks"))]
    pub fn multisig_scope(&self) -> Result<Option<crate::multisig::MultisigScope>, WalletError> {
        Err(WalletError::MultisigDisabled)
    }

    #[cfg(feature = "wallet_multisig_hooks")]
    pub fn set_multisig_scope(
        &self,
        scope: Option<MultisigScope>,
    ) -> Result<Option<MultisigScope>, WalletError> {
        let mut batch = self.store.batch().map_err(store_error)?;
        let previous = self.multisig_scope()?;
        match scope {
            Some(scope) => {
                store_scope(&mut batch, &scope)
                    .map_err(MultisigError::from)
                    .map_err(WalletError::from)?;
            }
            None => clear_scope(&mut batch),
        }
        batch.commit().map_err(store_error)?;
        Ok(previous)
    }

    #[cfg(not(feature = "wallet_multisig_hooks"))]
    pub fn set_multisig_scope(
        &self,
        _scope: Option<crate::multisig::MultisigScope>,
    ) -> Result<Option<crate::multisig::MultisigScope>, WalletError> {
        Err(WalletError::MultisigDisabled)
    }

    #[cfg(feature = "wallet_multisig_hooks")]
    pub fn cosigner_registry(&self) -> Result<Option<CosignerRegistry>, WalletError> {
        load_cosigner_registry(&self.store)
            .map_err(MultisigError::from)
            .map_err(WalletError::from)
    }

    #[cfg(not(feature = "wallet_multisig_hooks"))]
    pub fn cosigner_registry(
        &self,
    ) -> Result<Option<crate::multisig::CosignerRegistry>, WalletError> {
        Err(WalletError::MultisigDisabled)
    }

    #[cfg(feature = "wallet_multisig_hooks")]
    pub fn set_cosigner_registry(
        &self,
        registry: Option<CosignerRegistry>,
    ) -> Result<Option<CosignerRegistry>, WalletError> {
        let mut batch = self.store.batch().map_err(store_error)?;
        let previous = self.cosigner_registry()?;
        match registry {
            Some(registry) => {
                store_cosigner_registry(&mut batch, &registry)
                    .map_err(MultisigError::from)
                    .map_err(WalletError::from)?;
            }
            None => clear_cosigner_registry(&mut batch),
        }
        batch.commit().map_err(store_error)?;
        Ok(previous)
    }

    #[cfg(not(feature = "wallet_multisig_hooks"))]
    pub fn set_cosigner_registry(
        &self,
        _registry: Option<crate::multisig::CosignerRegistry>,
    ) -> Result<Option<crate::multisig::CosignerRegistry>, WalletError> {
        Err(WalletError::MultisigDisabled)
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

    pub fn sign_and_prove(
        &self,
        draft: &DraftTransaction,
    ) -> Result<(ProveResult, ProverMeta), WalletError> {
        self.ensure_signing_allowed()?;
        let inputs: Vec<_> = draft
            .inputs
            .iter()
            .map(|input| input.outpoint.clone())
            .collect();
        let ctx = DraftProverContext::new(draft);
        let result = (|| {
            let plan = self.prover.prepare_witness(&ctx)?;
            let prove_result = self.prover.prove(&ctx, plan)?;
            let meta = self.prover.attest_metadata(&ctx, &prove_result)?;
            Ok((prove_result, meta))
        })();

        match result {
            Ok((output, meta)) => {
                let proof_generated = output.proof().is_some();
                if self.prover_config.require_proof && !proof_generated {
                    self.engine.release_locks_for_inputs(inputs.iter())?;
                    return Err(WalletError::ProofMissing);
                }
                let txid = lock_fingerprint(draft);
                let proof_bytes = meta.proof_bytes.map(|bytes| bytes as u64);
                let proof_hash = meta.proof_hash.map(hex::encode);
                let metadata = PendingLockMetadata::new(
                    meta.backend.to_string(),
                    meta.witness_bytes as u64,
                    meta.duration_ms,
                    self.prover_config.require_proof,
                    proof_generated,
                    proof_bytes,
                    proof_hash,
                );
                self.engine
                    .attach_locks_to_txid(inputs.iter(), txid, Some(metadata))?;
                Ok((output, meta))
            }
            Err(err) => {
                self.engine.release_locks_for_inputs(inputs.iter())?;
                Err(err.into())
            }
        }
    }

    pub fn broadcast(&self, draft: &DraftTransaction) -> Result<(), WalletError> {
        self.ensure_broadcast_allowed()?;
        let txid = lock_fingerprint(draft);
        let submission = crate::node_client::submission_from_draft(draft);
        match self.node_client.submit_tx(&submission) {
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
        self.telemetry.snapshot()
    }

    pub fn telemetry_handle(&self) -> Arc<WalletActionTelemetry> {
        Arc::clone(&self.telemetry)
    }

    pub fn prover_config(&self) -> &WalletProverConfig {
        &self.prover_config
    }

    pub fn prover_identity(&self) -> ProverIdentity {
        self.prover.identity()
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

    #[cfg(feature = "wallet_hw")]
    pub fn configure_hardware_signer(
        &self,
        signer: Option<Arc<dyn HardwareSigner>>,
    ) -> Result<(), WalletError> {
        if signer.is_some() {
            self.ensure_hardware_enabled()?;
        }
        self.engine
            .set_hardware_signer(signer)
            .map_err(|_| WalletError::HardwareStatePoisoned)
    }

    #[cfg(feature = "wallet_hw")]
    fn hardware_backend(&self) -> Result<Arc<dyn HardwareSigner>, WalletError> {
        self.ensure_hardware_enabled()?;
        match self
            .engine
            .hardware_signer()
            .map_err(|_| WalletError::HardwareStatePoisoned)?
        {
            Some(signer) => Ok(signer),
            None => Err(WalletError::HardwareUnavailable),
        }
    }

    #[cfg(feature = "wallet_hw")]
    pub fn hardware_devices(&self) -> Result<Vec<HardwareDevice>, WalletError> {
        let backend = self.hardware_backend()?;
        backend.enumerate().map_err(WalletError::from)
    }

    #[cfg(feature = "wallet_hw")]
    pub fn hardware_public_key(
        &self,
        fingerprint: &str,
        path: &DerivationPath,
    ) -> Result<HardwarePublicKey, WalletError> {
        let backend = self.hardware_backend()?;
        backend
            .get_public_key(fingerprint, path)
            .map_err(WalletError::from)
    }

    #[cfg(feature = "wallet_hw")]
    pub fn hardware_sign(
        &self,
        request: HardwareSignRequest,
    ) -> Result<HardwareSignature, WalletError> {
        self.ensure_signing_allowed()?;
        let backend = self.hardware_backend()?;
        backend.sign(&request).map_err(WalletError::from)
    }

    #[cfg(feature = "wallet_zsi")]
    fn zsi_backend(&self) -> Result<Arc<dyn ProofBackend>, WalletError> {
        self.zsi.backend().map_err(WalletError::from)
    }

    #[cfg(not(feature = "wallet_zsi"))]
    fn zsi_backend(&self) -> Result<Arc<dyn ProofBackend>, WalletError> {
        let _ = &self.zsi;
        Err(ZsiError::Disabled.into())
    }

    #[cfg(feature = "wallet_zsi")]
    fn ensure_zsi_enabled(&self) -> Result<(), WalletError> {
        if self.zsi.enabled() {
            Ok(())
        } else {
            Err(ZsiError::Disabled.into())
        }
    }

    #[cfg(not(feature = "wallet_zsi"))]
    fn ensure_zsi_enabled(&self) -> Result<(), WalletError> {
        let _ = &self.zsi;
        Err(ZsiError::Disabled.into())
    }

    #[cfg(feature = "wallet_zsi")]
    pub fn zsi_bind_account(&self, request: ZsiProofRequest) -> Result<ZsiBinding, WalletError> {
        self.ensure_signing_allowed()?;
        self.ensure_zsi_enabled()?;
        let backend = self.zsi_backend()?;
        let (_binder, witness, inputs) =
            zsi_prepare_binding(&backend, request.operation, &request.record)?;
        Ok(ZsiBinding {
            operation: request.operation,
            record: request.record,
            witness: witness.into_inner(),
            inputs,
        })
    }

    #[cfg(not(feature = "wallet_zsi"))]
    pub fn zsi_bind_account(&self, _request: ZsiProofRequest) -> Result<ZsiBinding, WalletError> {
        self.ensure_signing_allowed()?;
        Err(ZsiError::Disabled.into())
    }

    #[cfg(feature = "wallet_zsi")]
    pub fn zsi_prove(&self, request: ZsiProofRequest) -> Result<LifecycleProof, WalletError> {
        self.ensure_signing_allowed()?;
        self.ensure_zsi_enabled()?;
        let backend = self.zsi_backend()?;
        let (binder, witness, inputs) =
            zsi_prepare_binding(&backend, request.operation, &request.record)?;

        let proof = match zsi::prove::generate(backend.as_ref(), &binder, witness, inputs.clone()) {
            Ok(Some(proof)) => proof,
            Ok(None) => return Err(ZsiError::Unsupported.into()),
            Err(err) => return Err(map_zsi_error(err)),
        };

        let artifact = StoredZsiArtifact::new(
            current_timestamp_ms(),
            request.record.identity.clone(),
            proof.proof_commitment.clone(),
            proof.backend.clone(),
            Cow::Owned(proof.raw_proof.clone()),
        );
        let mut batch = self.store.batch().map_err(store_error)?;
        batch.put_zsi_artifact(&artifact).map_err(store_error)?;
        batch.commit().map_err(store_error)?;

        Ok(proof)
    }

    #[cfg(not(feature = "wallet_zsi"))]
    pub fn zsi_prove(&self, _request: ZsiProofRequest) -> Result<LifecycleProof, WalletError> {
        self.ensure_signing_allowed()?;
        Err(ZsiError::Disabled.into())
    }

    #[cfg(feature = "wallet_zsi")]
    pub fn zsi_verify(&self, request: ZsiVerifyRequest) -> Result<(), WalletError> {
        self.ensure_signing_allowed()?;
        self.ensure_zsi_enabled()?;
        let backend = self.zsi_backend()?;
        let inputs = zsi_identity_inputs(&request.record);
        let proof = ProofBytes(request.proof);
        zsi::verify::identity(backend.as_ref(), &proof, &inputs).map_err(map_zsi_error)
    }

    #[cfg(not(feature = "wallet_zsi"))]
    pub fn zsi_verify(&self, _request: ZsiVerifyRequest) -> Result<(), WalletError> {
        self.ensure_signing_allowed()?;
        Err(ZsiError::Disabled.into())
    }

    #[cfg(feature = "wallet_zsi")]
    pub fn zsi_list(&self) -> Result<Vec<StoredZsiArtifact<'static>>, WalletError> {
        self.ensure_signing_allowed()?;
        self.ensure_zsi_enabled()?;
        self.store.iter_zsi_artifacts().map_err(store_error)
    }

    #[cfg(not(feature = "wallet_zsi"))]
    pub fn zsi_list(&self) -> Result<Vec<StoredZsiArtifact<'static>>, WalletError> {
        self.ensure_signing_allowed()?;
        Err(ZsiError::Disabled.into())
    }

    #[cfg(feature = "wallet_zsi")]
    pub fn zsi_delete(&self, identity: &str, commitment_digest: &str) -> Result<(), WalletError> {
        self.ensure_signing_allowed()?;
        self.ensure_zsi_enabled()?;
        let mut batch = self.store.batch().map_err(store_error)?;
        batch.delete_zsi_artifact(identity, commitment_digest);
        batch.commit().map_err(store_error)
    }

    #[cfg(not(feature = "wallet_zsi"))]
    pub fn zsi_delete(&self, _identity: &str, _commitment_digest: &str) -> Result<(), WalletError> {
        self.ensure_signing_allowed()?;
        Err(ZsiError::Disabled.into())
    }

    pub fn start_sync_coordinator(
        &self,
        indexer_client: Arc<dyn IndexerClient>,
    ) -> Result<WalletSyncCoordinator, WalletError> {
        WalletSyncCoordinator::start(self.engine_handle(), indexer_client).map_err(Into::into)
    }
}

#[derive(Clone)]
struct WalletZsiState {
    enabled: bool,
    backend: Option<Arc<dyn ProofBackend>>,
    configured_label: Option<String>,
}

impl WalletZsiState {
    #[cfg(feature = "wallet_zsi")]
    fn new(
        config: WalletZsiConfig,
        backend: Option<Arc<dyn ProofBackend>>,
    ) -> Result<Self, WalletError> {
        let backend = if config.enabled { backend } else { None };
        Ok(Self {
            enabled: config.enabled,
            backend,
            configured_label: config.backend,
        })
    }

    #[cfg(not(feature = "wallet_zsi"))]
    fn new(
        config: WalletZsiConfig,
        _backend: Option<Arc<dyn ProofBackend>>,
    ) -> Result<Self, WalletError> {
        if config.enabled {
            return Err(ZsiError::Disabled.into());
        }
        Ok(Self {
            enabled: false,
            backend: None,
            configured_label: config.backend,
        })
    }

    #[cfg(feature = "wallet_zsi")]
    fn backend(&self) -> Result<Arc<dyn ProofBackend>, ZsiError> {
        if !self.enabled {
            return Err(ZsiError::Disabled);
        }
        self.backend
            .as_ref()
            .cloned()
            .ok_or(ZsiError::BackendUnavailable)
    }

    #[cfg(not(feature = "wallet_zsi"))]
    fn backend(&self) -> Result<Arc<dyn ProofBackend>, ZsiError> {
        let _ = &self.backend;
        Err(ZsiError::Disabled)
    }

    fn enabled(&self) -> bool {
        self.enabled
    }
}

#[derive(Default)]
struct DisabledWatchOnlyProver;

impl WalletProver for DisabledWatchOnlyProver {
    fn identity(&self) -> ProverIdentity {
        ProverIdentity::new("watch-only", true)
    }

    fn prepare_witness(
        &self,
        _ctx: &DraftProverContext<'_>,
    ) -> Result<WitnessPlan, EngineProverError> {
        Err(EngineProverError::Unsupported(
            "watch-only mode does not support proving",
        ))
    }

    fn prove(
        &self,
        _ctx: &DraftProverContext<'_>,
        _plan: WitnessPlan,
    ) -> Result<ProveResult, EngineProverError> {
        Err(EngineProverError::Unsupported(
            "watch-only mode does not support proving",
        ))
    }

    fn attest_metadata(
        &self,
        _ctx: &DraftProverContext<'_>,
        _result: &ProveResult,
    ) -> Result<ProverMeta, EngineProverError> {
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

#[cfg(feature = "wallet_zsi")]
fn zsi_prepare_binding(
    backend: &Arc<dyn ProofBackend>,
    operation: ZsiOperation,
    record: &ZsiRecord,
) -> Result<(ZsiBinder, WitnessBytes, IdentityPublicInputs), WalletError> {
    let binder = ZsiBinder::new(backend.as_ref(), operation);
    let witness = binder.encode_witness(record).map_err(map_zsi_error)?;
    let inputs = zsi_identity_inputs(record);
    Ok((binder, witness, inputs))
}

#[cfg(feature = "wallet_zsi")]
fn zsi_identity_inputs(record: &ZsiRecord) -> IdentityPublicInputs {
    let approvals = serde_json::to_vec(&record.approvals).unwrap_or_default();
    IdentityPublicInputs {
        wallet_address: zsi::prove::hash_bytes(record.identity.as_bytes()),
        vrf_tag: record.attestation_digest.as_bytes().to_vec(),
        identity_root: zsi::prove::hash_bytes(record.genesis_id.as_bytes()),
        state_root: zsi::prove::hash_bytes(&approvals),
    }
}

#[cfg(feature = "wallet_zsi")]
fn map_zsi_error(error: ZsiBackendError) -> WalletError {
    match error {
        ZsiBackendError::Unsupported(_) => ZsiError::Unsupported.into(),
        other => ZsiError::Backend(other).into(),
    }
}

impl WalletService for Wallet {
    fn address(&self) -> String {
        self.address().to_string()
    }

    fn attach_node_client(&self, _client: Arc<dyn NodeClient>) -> WalletServiceResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use tempfile::tempdir;

    use crate::config::wallet::{
        WalletFeeConfig, WalletHwConfig, WalletPolicyConfig, WalletProverConfig,
    };
    use crate::db::{UtxoOutpoint, UtxoRecord};
    use crate::engine::signing::ProverError;
    use crate::engine::{DerivationPath, WalletEngine};
    #[cfg(feature = "wallet_hw")]
    use crate::hw::{HardwareDevice, HardwareSignRequest, HardwareSignature, MockHardwareSigner};
    use crate::modes::watch_only::WatchOnlyRecord;
    #[cfg(feature = "wallet_multisig_hooks")]
    use crate::multisig::{
        store_cosigner_registry, store_scope, Cosigner, CosignerRegistry, MultisigError,
        MultisigScope,
    };
    use crate::node_client::{NodeClient, StubNodeClient};
    use crate::proof_backend::BackendError as TestBackendError;
    use crate::telemetry::WalletActionTelemetry;
    use crate::wallet::WatchOnlyError;
    use tokio::runtime::Handle;
    use tokio::task;

    struct SleepyWalletProver {
        jobs: ProverJobManager,
        sleep: Duration,
    }

    impl SleepyWalletProver {
        fn new(timeout_secs: u64, sleep: Duration) -> Self {
            let mut config = WalletProverConfig::default();
            config.timeout_secs = timeout_secs;
            config.max_concurrency = 1;
            Self {
                jobs: ProverJobManager::new(&config),
                sleep,
            }
        }
    }

    impl WalletProver for SleepyWalletProver {
        fn identity(&self) -> ProverIdentity {
            ProverIdentity::new("sleepy", true)
        }

        fn prepare_witness(
            &self,
            _ctx: &DraftProverContext<'_>,
        ) -> Result<WitnessPlan, ProverError> {
            Ok(WitnessPlan::empty())
        }

        fn prove(
            &self,
            _ctx: &DraftProverContext<'_>,
            plan: WitnessPlan,
        ) -> Result<ProveResult, ProverError> {
            let permit = self.jobs.acquire()?;
            let handle = Handle::try_current().map_err(|err| {
                ProverError::Runtime(format!("tokio runtime handle not available: {err}"))
            })?;
            let sleep = self.sleep;
            let witness_bytes = plan.witness_bytes();
            handle.block_on(async move {
                let token = permit.cancellation_token();
                let job = task::spawn_blocking(move || {
                    if token.is_cancelled() {
                        return Err(ProverError::Cancelled);
                    }
                    std::thread::sleep(sleep);
                    Ok(())
                });
                let started_at = Instant::now();
                permit
                    .wait(async move {
                        job.await.map_err(|err| {
                            if err.is_cancelled() {
                                ProverError::Cancelled
                            } else if err.is_panic() {
                                ProverError::Runtime("prover task panicked".into())
                            } else {
                                ProverError::Runtime(format!("prover task failed: {err}"))
                            }
                        })?
                    })
                    .await?;
                let finished_at = Instant::now();
                Ok(ProveResult::new(
                    None,
                    witness_bytes,
                    started_at,
                    finished_at,
                ))
            })
        }

        fn attest_metadata(
            &self,
            _ctx: &DraftProverContext<'_>,
            result: &ProveResult,
        ) -> Result<ProverMeta, ProverError> {
            Ok(ProverMeta {
                backend: self.identity().backend,
                witness_bytes: result.witness_bytes(),
                proof_bytes: None,
                proof_hash: None,
                duration_ms: result.duration().as_millis() as u64,
            })
        }
    }

    #[test]
    fn prover_timeout_maps_to_wallet_error() {
        let err: WalletError = ProverError::Timeout(2).into();
        assert!(matches!(
            err,
            WalletError::ProverTimeout { timeout_secs } if timeout_secs == 2
        ));
    }

    #[test]
    fn prover_backend_disabled_maps_to_specific_variant() {
        let err: WalletError = ProverError::Backend(TestBackendError::Unsupported(
            "wallet prover backend disabled",
        ))
        .into();
        assert!(matches!(err, WalletError::ProverBackendDisabled));
    }

    #[test]
    fn prover_backend_failure_is_reported_as_internal() {
        let err: WalletError =
            ProverError::Backend(TestBackendError::Failure("boom".into())).into();
        match err {
            WalletError::ProverInternal { reason } => {
                assert!(reason.contains("boom"));
            }
            other => panic!("expected ProverInternal, got {other:?}"),
        }
    }

    #[test]
    fn prover_witness_limit_maps_to_wallet_error() {
        let err: WalletError = ProverError::WitnessTooLarge { size: 5, limit: 3 }.into();
        assert!(matches!(
            err,
            WalletError::ProverWitnessTooLarge { size, limit }
                if size == 5 && limit == 3
        ));
    }

    #[derive(Default)]
    struct InstantWalletProver;

    impl WalletProver for InstantWalletProver {
        fn identity(&self) -> ProverIdentity {
            ProverIdentity::new("instant", true)
        }

        fn prepare_witness(
            &self,
            _ctx: &DraftProverContext<'_>,
        ) -> Result<WitnessPlan, ProverError> {
            Ok(WitnessPlan::empty())
        }

        fn prove(
            &self,
            _ctx: &DraftProverContext<'_>,
            plan: WitnessPlan,
        ) -> Result<ProveResult, ProverError> {
            let now = Instant::now();
            Ok(ProveResult::new(None, plan.witness_bytes(), now, now))
        }

        fn attest_metadata(
            &self,
            _ctx: &DraftProverContext<'_>,
            result: &ProveResult,
        ) -> Result<ProverMeta, ProverError> {
            Ok(ProverMeta {
                backend: self.identity().backend,
                witness_bytes: result.witness_bytes(),
                proof_bytes: None,
                proof_hash: None,
                duration_ms: result.duration().as_millis() as u64,
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

    #[cfg(feature = "wallet_hw")]
    fn hardware_wallet() -> (Wallet, MockHardwareSigner, tempfile::TempDir) {
        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        let mut batch = store.batch().expect("batch");
        let outpoint = UtxoOutpoint::new([1u8; 32], 0);
        let record = UtxoRecord::new(outpoint.clone(), 42_000, "owner".to_string(), None);
        batch.put_utxo(&outpoint, &record).expect("seed utxo");
        batch.commit().expect("commit utxo");
        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let keystore = tempdir.path().join("keystore.toml");
        let backup = tempdir.path().join("backups");
        let mut hw_config = WalletHwConfig::default();
        hw_config.enabled = true;
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [42u8; 32],
            },
            policy,
            fees,
            WalletProverConfig::default(),
            hw_config,
            WalletZsiConfig::default(),
            None,
            node_client,
            WalletPaths::new(keystore, backup),
            Arc::new(WalletActionTelemetry::new(false)),
        )
        .expect("wallet");
        let signer = MockHardwareSigner::new(vec![
            HardwareDevice::new("a1b2", "TestSigner").with_label("Primary"),
            HardwareDevice::new("c3d4", "TestSigner"),
        ]);
        wallet
            .configure_hardware_signer(Some(Arc::new(signer.clone())))
            .expect("configure signer");
        (wallet, signer, tempdir)
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
            keystore_path: PathBuf::new(),
            backup_path: PathBuf::new(),
            watch_only: Arc::new(RwLock::new(None)),
            telemetry: Arc::new(WalletActionTelemetry::new(false)),
            zsi: WalletZsiState::new(WalletZsiConfig::default(), None).expect("zsi state"),
            hw_config: WalletHwConfig::default(),
        }
    }

    fn make_draft(wallet: &Wallet, amount: u128) -> DraftTransaction {
        wallet
            .create_draft("wallet.recipient".into(), amount, None)
            .expect("draft")
            .draft
    }

    fn fingerprint(byte: u8) -> String {
        let chunk = format!("{:02x}", byte);
        std::iter::repeat(chunk)
            .take(32)
            .collect::<Vec<_>>()
            .join("")
    }

    fn runtime_guard() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("runtime")
    }

    #[cfg(not(feature = "wallet_zsi"))]
    #[test]
    fn wallet_new_fails_when_zsi_feature_disabled() {
        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let mut zsi_config = WalletZsiConfig::default();
        zsi_config.enabled = true;
        let keystore = tempdir.path().join("keystore.toml");
        let backup = tempdir.path().join("backups");

        let result = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [1u8; 32],
            },
            policy,
            fees,
            WalletProverConfig::default(),
            WalletHwConfig::default(),
            zsi_config,
            None,
            node_client,
            WalletPaths::new(keystore, backup),
            Arc::new(WalletActionTelemetry::new(false)),
        );

        assert!(matches!(result, Err(WalletError::Zsi(ZsiError::Disabled))));
    }

    #[cfg(not(feature = "wallet_hw"))]
    #[test]
    fn wallet_new_rejects_hw_config_without_feature() {
        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let mut hw_config = WalletHwConfig::default();
        hw_config.enabled = true;
        let result = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [2u8; 32],
            },
            policy,
            fees,
            WalletProverConfig::default(),
            hw_config,
            WalletZsiConfig::default(),
            None,
            node_client,
            WalletPaths::new(
                tempdir.path().join("keystore.toml"),
                tempdir.path().join("backups"),
            ),
            Arc::new(WalletActionTelemetry::new(false)),
        );

        assert!(matches!(result, Err(WalletError::HardwareFeatureDisabled)));
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
            WalletHwConfig::default(),
            WalletZsiConfig::default(),
            None,
            Arc::clone(&node_client),
            WalletPaths::new(keystore, backup),
            Arc::new(WalletActionTelemetry::new(false)),
        )
        .expect("wallet");

        let draft = make_draft(&wallet, 10_000);
        let locks_before = wallet.pending_locks().expect("locks");
        assert!(!locks_before.is_empty());

        let (prove_result, meta) = wallet.sign_and_prove(&draft).expect("mock prove");
        assert_eq!(wallet.prover_identity().backend, "mock");
        assert!(prove_result.proof().is_some());

        let locks = wallet.pending_locks().expect("locks after prove");
        assert_eq!(locks.len(), locks_before.len());
        let proof_bytes = meta.proof_bytes.map(|bytes| bytes as u64);
        let proof_hash = meta.proof_hash.as_ref().map(hex::encode);
        let proof_required = wallet.prover_config().require_proof;
        let proof_present = prove_result.proof().is_some();
        assert!(locks.iter().all(|lock| {
            lock.spending_txid.is_some()
                && lock.metadata.backend == meta.backend
                && lock.metadata.witness_bytes == meta.witness_bytes as u64
                && lock.metadata.prove_duration_ms == meta.duration_ms
                && lock.metadata.proof_required == proof_required
                && lock.metadata.proof_present == proof_present
                && lock.metadata.proof_bytes == proof_bytes
                && lock.metadata.proof_hash == proof_hash
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
        config.backend = WalletProverBackend::Stwo;
        config.require_proof = true;
        config.timeout_secs = 30;
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
            WalletHwConfig::default(),
            WalletZsiConfig::default(),
            None,
            Arc::clone(&node_client),
            WalletPaths::new(keystore, backup),
            Arc::new(WalletActionTelemetry::new(false)),
        )
        .expect("wallet");

        let draft = make_draft(&wallet, 15_000);
        let locks_before = wallet.pending_locks().expect("locks");
        assert!(!locks_before.is_empty());

        let (prove_result, meta) = wallet.sign_and_prove(&draft).expect("stwo prove");
        assert_eq!(wallet.prover_identity().backend, "stwo");
        assert!(prove_result.proof().is_some());

        let locks = wallet.pending_locks().expect("locks after prove");
        assert_eq!(locks.len(), locks_before.len());
        let proof_bytes = meta.proof_bytes.map(|bytes| bytes as u64);
        let proof_hash = meta.proof_hash.as_ref().map(hex::encode);
        let proof_required = wallet.prover_config().require_proof;
        let proof_present = prove_result.proof().is_some();
        assert!(locks.iter().all(|lock| {
            lock.spending_txid.is_some()
                && lock.metadata.backend == meta.backend
                && lock.metadata.witness_bytes == meta.witness_bytes as u64
                && lock.metadata.prove_duration_ms == meta.duration_ms
                && lock.metadata.proof_required == proof_required
                && lock.metadata.proof_present == proof_present
                && lock.metadata.proof_bytes == proof_bytes
                && lock.metadata.proof_hash == proof_hash
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
            WalletError::ProverTimeout { timeout_secs } if timeout_secs == 1
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
            WalletHwConfig::default(),
            WalletZsiConfig::default(),
            None,
            Arc::clone(&node_client),
            WalletPaths::new(keystore, backup),
            Arc::new(WalletActionTelemetry::new(false)),
        )
        .expect("wallet");

        let draft = make_draft(&wallet, 12_000);
        assert!(!wallet.pending_locks().expect("locks before").is_empty());

        let err = wallet
            .sign_and_prove(&draft)
            .expect_err("witness too large");
        assert!(matches!(
            err,
            WalletError::ProverWitnessTooLarge { limit, .. } if limit == 1
        ));
        assert!(wallet.pending_locks().expect("locks after").is_empty());
        drop(tempdir);
    }

    #[test]
    #[cfg(feature = "wallet_multisig_hooks")]
    fn create_draft_includes_multisig_metadata() {
        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        seed_store_with_utxo(&store, 80_000);
        {
            let mut batch = store.batch().expect("batch");
            let scope = MultisigScope::new(2, 3).expect("scope");
            store_scope(&mut batch, &scope).expect("store scope");
            let registry = CosignerRegistry::new(vec![
                Cosigner::new(fingerprint(0x11), Some("https://a")).expect("cosigner"),
                Cosigner::new(fingerprint(0x22), None).expect("cosigner"),
            ])
            .expect("registry");
            store_cosigner_registry(&mut batch, &registry).expect("store registry");
            batch.commit().expect("commit");
        }

        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let wallet = build_wallet_with_prover(
            Arc::clone(&store),
            policy,
            fees,
            Arc::new(InstantWalletProver::default()),
            Arc::clone(&node_client),
        );

        let bundle = wallet
            .create_draft("wallet.recipient".into(), 30_000, None)
            .expect("bundle");
        let metadata = bundle.metadata.multisig.expect("multisig metadata");
        assert_eq!(metadata.scope.threshold(), 2);
        assert_eq!(metadata.scope.participants(), 3);
        assert_eq!(metadata.cosigners.len(), 2);
    }

    #[test]
    #[cfg(feature = "wallet_multisig_hooks")]
    fn create_draft_requires_cosigners_for_multisig() {
        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        seed_store_with_utxo(&store, 70_000);
        {
            let mut batch = store.batch().expect("batch");
            let scope = MultisigScope::new(2, 3).expect("scope");
            store_scope(&mut batch, &scope).expect("store scope");
            batch.commit().expect("commit");
        }

        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let wallet = build_wallet_with_prover(
            Arc::clone(&store),
            policy,
            fees,
            Arc::new(InstantWalletProver::default()),
            Arc::clone(&node_client),
        );

        let err = wallet
            .create_draft("wallet.recipient".into(), 25_000, None)
            .expect_err("missing cosigners");
        assert!(matches!(
            err,
            WalletError::Multisig(MultisigError::MissingCosigners)
        ));
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
            WalletHwConfig::default(),
            WalletZsiConfig::default(),
            None,
            Arc::clone(&node_client),
            WalletPaths::new(keystore, backup),
            Arc::new(WalletActionTelemetry::new(false)),
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

    #[test]
    fn enabling_watch_only_on_full_wallet_blocks_signing() {
        let runtime = runtime_guard();
        let _guard = runtime.enter();

        let tempdir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        seed_store_with_utxo(&store, 45_000);

        let (policy, fees) = sample_wallet_configs();
        let node_client: Arc<dyn NodeClient> = Arc::new(StubNodeClient::default());
        let keystore = tempdir.path().join("keystore.toml");
        let backup = tempdir.path().join("backups");
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [21u8; 32],
            },
            policy,
            fees,
            WalletProverConfig::default(),
            WalletHwConfig::default(),
            WalletZsiConfig::default(),
            None,
            Arc::clone(&node_client),
            WalletPaths::new(keystore, backup),
            Arc::new(WalletActionTelemetry::new(false)),
        )
        .expect("wallet");

        assert!(!wallet.is_watch_only());
        let draft = make_draft(&wallet, 12_000);

        let record = WatchOnlyRecord::new("wpkh(full)")
            .with_birthday_height(Some(88))
            .with_account_xpub("xpub-full");
        wallet.enable_watch_only(record).expect("enable watch-only");

        let sign_err = wallet
            .sign_and_prove(&draft)
            .expect_err("signing blocked by watch-only");
        assert!(matches!(
            sign_err,
            WalletError::WatchOnly(WatchOnlyError::SigningDisabled)
        ));

        wallet.disable_watch_only().expect("disable watch-only");
        wallet
            .sign_and_prove(&draft)
            .expect("signing resumes after disabling watch-only");
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
        config.backend = WalletProverBackend::Stwo;
        config.require_proof = true;
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
            WalletHwConfig::default(),
            WalletZsiConfig::default(),
            None,
            Arc::clone(&node_client),
            WalletPaths::new(keystore, backup),
            Arc::new(WalletActionTelemetry::new(false)),
        )
        .expect("wallet");

        let draft = make_draft(&wallet, 18_000);
        assert!(!wallet.pending_locks().expect("locks before").is_empty());

        let err = wallet
            .sign_and_prove(&draft)
            .expect_err("witness too large");
        assert!(matches!(
            err,
            WalletError::ProverWitnessTooLarge { limit, .. } if limit == 1
        ));
        assert!(wallet.pending_locks().expect("locks after").is_empty());
        drop(tempdir);
    }

    #[cfg(feature = "wallet_hw")]
    #[test]
    fn hardware_enumeration_returns_devices() {
        let (wallet, signer, _dir) = hardware_wallet();
        let devices = wallet.hardware_devices().expect("devices");
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].fingerprint, "a1b2");
        assert_eq!(devices[0].label.as_deref(), Some("Primary"));
        assert_eq!(devices[1].fingerprint, "c3d4");
        assert!(signer
            .enumerate()
            .expect("mock enumerate")
            .iter()
            .any(|device| device.fingerprint == "a1b2"));
    }

    #[cfg(feature = "wallet_hw")]
    #[test]
    fn hardware_signing_forwards_requests() {
        let (wallet, signer, _dir) = hardware_wallet();
        let path = DerivationPath::new(0, false, 7);
        signer.push_sign_response(Ok(HardwareSignature::new(
            "a1b2",
            path.clone(),
            [9u8; 64],
            [8u8; 33],
        )));
        let request = HardwareSignRequest::new("a1b2", path.clone(), [1u8; 32]);
        let signature = wallet.hardware_sign(request.clone()).expect("signature");
        assert_eq!(signature.signature, vec![9u8; 64]);
        assert_eq!(signature.public_key, vec![8u8; 33]);
        let recorded = signer.last_sign_request().expect("recorded request");
        assert_eq!(recorded.fingerprint, request.fingerprint);
        assert_eq!(recorded.path, request.path);
        assert_eq!(recorded.payload, request.payload);
    }

    #[cfg(feature = "wallet_hw")]
    #[test]
    fn hardware_signing_propagates_rejection() {
        let (wallet, signer, _dir) = hardware_wallet();
        let path = DerivationPath::new(0, false, 0);
        signer.push_sign_response(Err(HardwareSignerError::rejected("user cancelled")));
        let request = HardwareSignRequest::new("a1b2", path, [2u8; 16]);
        let err = wallet.hardware_sign(request).expect_err("rejection");
        assert!(matches!(
            err,
            WalletError::Hardware(HardwareSignerError::Rejected { .. })
        ));
    }
}
