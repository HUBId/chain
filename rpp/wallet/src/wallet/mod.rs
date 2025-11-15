use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::wallet::{
    PolicyTierHooks, WalletFeeConfig, WalletPolicyConfig, WalletProverConfig, WalletZsiConfig,
};
use crate::db::{
    PendingLock, PendingLockMetadata, PolicySnapshot, StoredZsiArtifact, TxCacheEntry, UtxoRecord,
    WalletStore, WalletStoreError,
};
use crate::engine::signing::{
    build_wallet_prover, ProverError as EngineProverError, ProverOutput, WalletProver,
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
use crate::multisig::{
    clear_cosigner_registry, clear_scope, load_cosigner_registry, load_scope,
    store_cosigner_registry, store_scope, CosignerRegistry, MultisigError, MultisigScope,
};
use crate::node_client::{BlockFeeSummary, ChainHead, MempoolInfo, NodeClient, NodeClientError};
use crate::proof_backend::{
    Blake2sHasher, IdentityPublicInputs, ProofBackend, ProofBytes, WitnessBytes,
};
use crate::runtime::node::MempoolStatus;
use crate::telemetry::{TelemetryCounters, WalletActionTelemetry};
#[cfg(feature = "wallet_zsi")]
use crate::zsi::ZsiBinder;
use crate::zsi::{self, LifecycleProof, ZsiOperation, ZsiRecord};
use prover_backend_interface::BackendError as ZsiBackendError;
use serde::{Deserialize, Serialize};

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
    #[error("multisig error: {0}")]
    Multisig(#[from] MultisigError),
    #[error("zsi error: {0}")]
    Zsi(#[from] ZsiError),
    #[cfg(feature = "wallet_hw")]
    #[error("hardware signer error: {0}")]
    Hardware(#[from] HardwareSignerError),
    #[cfg(feature = "wallet_hw")]
    #[error("hardware signer not configured")]
    HardwareUnavailable,
    #[cfg(feature = "wallet_hw")]
    #[error("hardware signer state unavailable")]
    HardwareStatePoisoned,
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
    identifier: String,
    keystore_path: PathBuf,
    backup_path: PathBuf,
    watch_only: Arc<RwLock<Option<WatchOnlyRecord>>>,
    telemetry: Arc<WalletActionTelemetry>,
    zsi: WalletZsiState,
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
        zsi_config: WalletZsiConfig,
        zsi_backend: Option<Arc<dyn ProofBackend>>,
        node_client: Arc<dyn NodeClient>,
        paths: WalletPaths,
        telemetry: Arc<WalletActionTelemetry>,
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
        let zsi = WalletZsiState::new(zsi_config, zsi_backend)?;
        Ok(Self {
            store,
            engine,
            node_client,
            prover,
            identifier,
            keystore_path: keystore,
            backup_path: backup,
            watch_only: Arc::new(RwLock::new(watch_only_record)),
            telemetry,
            zsi,
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
    ) -> Result<DraftBundle, WalletError> {
        Ok(self
            .engine
            .create_draft(to, amount, fee_rate, Some(self.node_client.as_ref()))?)
    }

    pub fn multisig_scope(&self) -> Result<Option<MultisigScope>, WalletError> {
        load_scope(&self.store)
            .map_err(MultisigError::from)
            .map_err(WalletError::from)
    }

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

    pub fn cosigner_registry(&self) -> Result<Option<CosignerRegistry>, WalletError> {
        load_cosigner_registry(&self.store)
            .map_err(MultisigError::from)
            .map_err(WalletError::from)
    }

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
        self.telemetry.snapshot()
    }

    pub fn telemetry_handle(&self) -> Arc<WalletActionTelemetry> {
        Arc::clone(&self.telemetry)
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
        self.engine
            .set_hardware_signer(signer)
            .map_err(|_| WalletError::HardwareStatePoisoned)
    }

    #[cfg(feature = "wallet_hw")]
    fn hardware_backend(&self) -> Result<Arc<dyn HardwareSigner>, WalletError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::sync::Arc;
    use std::time::Duration;

    use tempfile::tempdir;

    use crate::config::wallet::{WalletFeeConfig, WalletPolicyConfig, WalletProverConfig};
    use crate::db::{UtxoOutpoint, UtxoRecord};
    use crate::engine::signing::ProverError;
    use crate::engine::{DerivationPath, WalletEngine};
    #[cfg(feature = "wallet_hw")]
    use crate::hw::{HardwareDevice, HardwareSignRequest, HardwareSignature, MockHardwareSigner};
    use crate::modes::watch_only::WatchOnlyRecord;
    use crate::multisig::{
        store_cosigner_registry, store_scope, Cosigner, CosignerRegistry, MultisigError,
        MultisigScope,
    };
    use crate::node_client::{NodeClient, StubNodeClient};
    use crate::telemetry::WalletActionTelemetry;
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

    #[derive(Default)]
    struct InstantWalletProver;

    impl WalletProver for InstantWalletProver {
        fn backend(&self) -> &'static str {
            "instant"
        }

        fn prove(&self, _draft: &DraftTransaction) -> Result<ProverOutput, ProverError> {
            Ok(ProverOutput {
                backend: "instant".into(),
                proof: None,
                witness_bytes: 0,
                duration_ms: 0,
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
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [42u8; 32],
            },
            policy,
            fees,
            WalletProverConfig::default(),
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
            zsi_config,
            None,
            node_client,
            WalletPaths::new(keystore, backup),
            Arc::new(WalletActionTelemetry::new(false)),
        );

        assert!(matches!(result, Err(WalletError::Zsi(ZsiError::Disabled))));
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
            WalletError::Prover(ProverError::WitnessTooLarge { limit, .. }) if limit == 1
        ));
        assert!(wallet.pending_locks().expect("locks after").is_empty());
        drop(tempdir);
    }

    #[test]
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
            WalletError::Prover(ProverError::WitnessTooLarge { limit, .. }) if limit == 1
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
