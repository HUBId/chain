use std::fmt;
use std::sync::Arc;
#[cfg(feature = "wallet_hw")]
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::wallet::{PolicyTierHooks, WalletFeeConfig, WalletPolicyConfig};
use crate::db::{
    PendingLock, PendingLockMetadata, TxCacheEntry, UtxoOutpoint, UtxoRecord, WalletStore,
    WalletStoreError,
};
#[cfg(feature = "wallet_hw")]
use crate::hw::HardwareSigner;
use crate::multisig::{load_cosigner_registry, load_scope, MultisigDraftMetadata, MultisigError};
use crate::node_client::NodeClient;

pub mod addresses;
pub mod builder;
pub mod fees;
pub mod policies;
pub mod signing;
pub mod utxo_sel;

#[cfg(test)]
pub mod tests;

pub use addresses::{AddressError, AddressManager, DerivedAddress};
pub use builder::{BuildMetadata, BuildPlan, BuilderError, BuiltTransaction, TransactionBuilder};
pub use fees::{FeeCongestionLevel, FeeError, FeeEstimateSource, FeeEstimator, FeeQuote};
pub use policies::{PolicyEngine, PolicyViolation};
pub use signing::{ProverError, ProverOutput, WalletProver};
pub use utxo_sel::{
    CandidateUtxo, SelectionError, SelectionMetadata, SelectionRequest, SelectionResult,
    SelectionStrategy,
};

/// Derivation path following a minimal BIP32-inspired structure.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DerivationPath {
    pub account: u32,
    pub change: bool,
    pub index: u32,
}

impl DerivationPath {
    pub fn new(account: u32, change: bool, index: u32) -> Self {
        Self {
            account,
            change,
            index,
        }
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let branch = if self.change { 1 } else { 0 };
        write!(
            f,
            "m/{account}/{branch}/{index}",
            account = self.account,
            index = self.index
        )
    }
}

/// Model describing how much value should be spent in a draft transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpendModel {
    Exact { amount: u128 },
    Sweep,
    Account { debit: u128 },
}

impl SpendModel {
    pub fn amount(&self) -> Option<u128> {
        match self {
            SpendModel::Exact { amount } => Some(*amount),
            SpendModel::Sweep => None,
            SpendModel::Account { debit } => Some(*debit),
        }
    }
}

/// Draft input referencing a wallet-controlled outpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftInput {
    pub outpoint: UtxoOutpoint,
    pub value: u128,
    pub confirmations: u32,
}

/// Draft output emitted by the transaction builder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftOutput {
    pub address: String,
    pub value: u128,
    pub change: bool,
}

impl DraftOutput {
    pub fn new(address: impl Into<String>, value: u128, change: bool) -> Self {
        Self {
            address: address.into(),
            value,
            change,
        }
    }
}

/// Transaction draft surfaced by the wallet engine prior to signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftTransaction {
    pub inputs: Vec<DraftInput>,
    pub outputs: Vec<DraftOutput>,
    pub fee_rate: u64,
    pub fee: u128,
    pub spend_model: SpendModel,
}

impl DraftTransaction {
    pub fn total_input_value(&self) -> u128 {
        self.inputs.iter().map(|input| input.value).sum()
    }

    pub fn total_output_value(&self) -> u128 {
        self.outputs.iter().map(|output| output.value).sum()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DraftBundle {
    pub draft: DraftTransaction,
    pub metadata: BuildMetadata,
}

/// Aggregated wallet balance numbers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalletBalance {
    pub confirmed: u128,
    pub pending: u128,
}

impl WalletBalance {
    pub fn total(&self) -> u128 {
        self.confirmed + self.pending
    }
}

/// Unified error type surfaced by the wallet engine.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("store error: {0}")]
    Store(#[from] WalletStoreError),
    #[error("address error: {0}")]
    Address(#[from] AddressError),
    #[error("fee error: {0}")]
    Fee(#[from] FeeError),
    #[error("coin selection error: {0}")]
    Selection(#[from] SelectionError),
    #[error("builder error: {0}")]
    Builder(#[from] BuilderError),
    #[error("policy violations: {0:?}")]
    Policy(Vec<PolicyViolation>),
    #[error("multisig error: {0}")]
    Multisig(#[from] MultisigError),
}

/// High-level coordinator gluing the wallet engine modules together.
pub struct WalletEngine {
    store: Arc<WalletStore>,
    address_manager: AddressManager,
    fee_estimator: FeeEstimator,
    policy_engine: PolicyEngine,
    tx_builder: TransactionBuilder,
    min_confirmations: u32,
    pending_lock_timeout: u64,
    tier_hooks: PolicyTierHooks,
    #[cfg(feature = "wallet_hw")]
    hardware_signer: Mutex<Option<Arc<dyn HardwareSigner>>>,
}

impl WalletEngine {
    pub fn new(
        store: Arc<WalletStore>,
        root_seed: [u8; 32],
        policy: WalletPolicyConfig,
        fees: WalletFeeConfig,
    ) -> Result<Self, EngineError> {
        let address_manager = AddressManager::new(
            Arc::clone(&store),
            root_seed,
            policy.external_gap_limit,
            policy.internal_gap_limit,
        )?;
        let fee_estimator = FeeEstimator::new(fees);
        let policy_engine = PolicyEngine::from_config(&policy);
        let dust_limit = policy_engine.dust_limit();
        let max_change_outputs = policy_engine.max_change_outputs();
        let tx_builder = TransactionBuilder::new(dust_limit, max_change_outputs);
        Ok(Self {
            store,
            address_manager,
            fee_estimator,
            policy_engine,
            tx_builder,
            min_confirmations: policy.min_confirmations,
            pending_lock_timeout: policy.pending_lock_timeout,
            tier_hooks: policy.tier.clone(),
            #[cfg(feature = "wallet_hw")]
            hardware_signer: Mutex::new(None),
        })
    }

    pub fn identifier(&self) -> String {
        self.address_manager.fingerprint()
    }

    pub fn store(&self) -> &Arc<WalletStore> {
        &self.store
    }

    pub fn address_manager(&self) -> &AddressManager {
        &self.address_manager
    }

    pub fn fee_estimator(&self) -> &FeeEstimator {
        &self.fee_estimator
    }

    pub fn policy_engine(&self) -> &PolicyEngine {
        &self.policy_engine
    }

    pub fn tx_builder(&self) -> &TransactionBuilder {
        &self.tx_builder
    }

    pub fn pending_lock_timeout(&self) -> u64 {
        self.pending_lock_timeout
    }

    pub fn tier_hooks(&self) -> &PolicyTierHooks {
        &self.tier_hooks
    }

    #[cfg(feature = "wallet_hw")]
    pub fn set_hardware_signer(&self, signer: Option<Arc<dyn HardwareSigner>>) -> Result<(), ()> {
        let mut slot = self.hardware_signer.lock().map_err(|_| ())?;
        *slot = signer;
        Ok(())
    }

    #[cfg(feature = "wallet_hw")]
    pub fn hardware_signer(&self) -> Result<Option<Arc<dyn HardwareSigner>>, ()> {
        let slot = self.hardware_signer.lock().map_err(|_| ())?;
        Ok(slot.as_ref().map(Arc::clone))
    }

    pub fn pending_locks(&self) -> Result<Vec<PendingLock>, EngineError> {
        self.release_stale_locks()?;
        self.address_manager
            .pending_locks()
            .map_err(EngineError::from)
    }

    pub fn release_stale_locks(&self) -> Result<Vec<PendingLock>, EngineError> {
        let now = current_timestamp_ms();
        self.address_manager
            .release_expired_locks(now, self.pending_lock_timeout)
            .map_err(EngineError::from)
    }

    pub fn release_pending_locks(&self) -> Result<Vec<PendingLock>, EngineError> {
        let _ = self.release_stale_locks()?;
        let locks = self.address_manager.pending_locks()?;
        if locks.is_empty() {
            return Ok(locks);
        }
        let outpoints: Vec<_> = locks.iter().map(|lock| lock.outpoint.clone()).collect();
        self.address_manager
            .release_inputs(outpoints.iter())
            .map_err(EngineError::from)
    }

    pub fn release_locks_for_inputs<'a, I>(
        &self,
        inputs: I,
    ) -> Result<Vec<PendingLock>, EngineError>
    where
        I: IntoIterator<Item = &'a UtxoOutpoint>,
    {
        self.address_manager
            .release_inputs(inputs)
            .map_err(EngineError::from)
    }

    pub fn release_locks_by_txid(&self, txid: &[u8; 32]) -> Result<Vec<PendingLock>, EngineError> {
        self.address_manager
            .release_by_txid(txid)
            .map_err(EngineError::from)
    }

    pub fn attach_locks_to_txid<'a, I>(
        &self,
        inputs: I,
        txid: [u8; 32],
        metadata: Option<PendingLockMetadata>,
    ) -> Result<Vec<PendingLock>, EngineError>
    where
        I: IntoIterator<Item = &'a UtxoOutpoint>,
    {
        self.address_manager
            .attach_lock_txid(inputs, txid, metadata)
            .map_err(EngineError::from)
    }

    pub fn balance(&self) -> Result<WalletBalance, EngineError> {
        let utxos = self.store.iter_utxos()?;
        let confirmed = utxos.iter().map(|utxo| utxo.value).sum();
        Ok(WalletBalance {
            confirmed,
            pending: 0,
        })
    }

    pub fn list_utxos(&self) -> Result<Vec<UtxoRecord<'static>>, EngineError> {
        self.store.iter_utxos().map_err(EngineError::from)
    }

    pub fn list_transactions(&self) -> Result<Vec<([u8; 32], TxCacheEntry<'static>)>, EngineError> {
        self.store
            .iter_tx_cache_entries()
            .map_err(EngineError::from)
    }

    pub fn next_external_address(&self) -> Result<DerivedAddress, EngineError> {
        Ok(self.address_manager.next_external_address()?)
    }

    pub fn next_internal_address(&self) -> Result<DerivedAddress, EngineError> {
        Ok(self.address_manager.next_internal_address()?)
    }

    pub fn create_draft(
        &self,
        to: String,
        amount: u128,
        fee_rate_override: Option<u64>,
        node_client: Option<&dyn NodeClient>,
    ) -> Result<DraftBundle, EngineError> {
        let fee_quote = self.fee_estimator.resolve(node_client, fee_rate_override)?;
        let fee_rate = fee_quote.rate();
        let now = current_timestamp_ms();
        self.address_manager
            .release_expired_locks(now, self.pending_lock_timeout)?;
        let utxos = self.store.iter_utxos()?;
        let candidates: Vec<CandidateUtxo> = utxos
            .into_iter()
            .map(|record| {
                let confirmations = record.timelock.unwrap_or_default() as u32;
                let pending = self.address_manager.is_outpoint_pending(&record.outpoint);
                CandidateUtxo::new(record, confirmations, pending)
            })
            .collect();
        let selection = utxo_sel::select_coins(SelectionRequest {
            candidates: &candidates,
            amount,
            min_confirmations: self.min_confirmations,
            strategy: SelectionStrategy::PreferConfirmed,
        })?;
        let mut preflight = self.policy_engine.evaluate_selection(&selection.inputs);
        if let Some(violation) = self.policy_engine.evaluate_daily_limit(amount) {
            preflight.push(violation);
        }
        if !preflight.is_empty() {
            return Err(EngineError::Policy(preflight));
        }
        let spend_model = SpendModel::Exact { amount };
        let mut outputs = vec![DraftOutput::new(&to, amount, false)];
        let plan = self
            .tx_builder
            .plan(Some(&selection), &outputs, fee_rate, &spend_model)?;
        let BuildPlan {
            fee,
            change_values,
            metadata,
        } = plan;
        for change_value in &change_values {
            let change = self.address_manager.next_internal_address()?;
            outputs.push(DraftOutput::new(change.address, *change_value, true));
        }
        let postflight = self.policy_engine.evaluate_outputs(&outputs);
        if !postflight.is_empty() {
            return Err(EngineError::Policy(postflight));
        }
        let mut built = self.tx_builder.finalize(
            Some(selection),
            outputs,
            fee_rate,
            fee,
            spend_model,
            metadata,
        )?;
        let scope = load_scope(&self.store).map_err(MultisigError::from)?;
        if let Some(scope) = scope {
            let registry = load_cosigner_registry(&self.store).map_err(MultisigError::from)?;
            let cosigners = registry
                .map(|registry| registry.to_vec())
                .unwrap_or_default();
            if scope.requires_collaboration() && cosigners.is_empty() {
                return Err(EngineError::Multisig(MultisigError::MissingCosigners));
            }
            built.metadata.multisig = Some(MultisigDraftMetadata { scope, cosigners });
        }
        let mut draft = built.transaction;
        self.address_manager.lock_inputs(
            draft.inputs.iter().map(|input| &input.outpoint),
            None,
            now,
            None,
        )?;
        Ok(DraftBundle {
            draft,
            metadata: built.metadata,
        })
    }
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}
