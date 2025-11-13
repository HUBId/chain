use std::fmt;
use std::sync::Arc;

use crate::config::wallet::{WalletFeeConfig, WalletPolicyConfig};
use crate::db::{WalletStore, WalletStoreError};
use crate::db::{TxCacheEntry, UtxoOutpoint, UtxoRecord};

pub mod addresses;
pub mod builder;
pub mod fees;
pub mod policies;
pub mod signing;
pub mod utxo_sel;

#[cfg(test)]
pub mod tests;

pub use addresses::{AddressError, AddressManager, DerivedAddress};
pub use builder::{BuilderError, TransactionBuilder};
pub use fees::{FeeEstimator, FeeError};
pub use policies::{PolicyEngine, PolicyViolation};
pub use signing::{ProverError, ProverOutput, WalletProver};
pub use utxo_sel::{CandidateUtxo, SelectionError};

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
        write!(f, "m/{account}/{branch}/{index}", account = self.account, index = self.index)
    }
}

/// Model describing how much value should be spent in a draft transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpendModel {
    Exact { amount: u128 },
    Sweep,
}

impl SpendModel {
    pub fn amount(&self) -> Option<u128> {
        match self {
            SpendModel::Exact { amount } => Some(*amount),
            SpendModel::Sweep => None,
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
}

/// High-level coordinator gluing the wallet engine modules together.
pub struct WalletEngine {
    store: Arc<WalletStore>,
    address_manager: AddressManager,
    fee_estimator: FeeEstimator,
    policy_engine: PolicyEngine,
    tx_builder: TransactionBuilder,
    min_confirmations: u32,
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
        let policy_engine = PolicyEngine::new(policy.min_confirmations, None);
        let dust_limit = policy_engine.dust_limit();
        let tx_builder = TransactionBuilder::new(dust_limit);
        Ok(Self {
            store,
            address_manager,
            fee_estimator,
            policy_engine,
            tx_builder,
            min_confirmations: policy.min_confirmations,
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

    pub fn list_transactions(
        &self,
    ) -> Result<Vec<([u8; 32], TxCacheEntry<'static>)>, EngineError> {
        self.store.iter_tx_cache_entries().map_err(EngineError::from)
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
    ) -> Result<DraftTransaction, EngineError> {
        let fee_rate = self.fee_estimator.resolve(fee_rate_override)?;
        let utxos = self.store.iter_utxos()?;
        let candidates: Vec<CandidateUtxo> = utxos
            .into_iter()
            .map(|record| {
                let confirmations = record.timelock.unwrap_or_default() as u32;
                let pending = self.address_manager.is_outpoint_pending(&record.outpoint);
                CandidateUtxo::new(record, confirmations, pending)
            })
            .collect();
        let mut selection = utxo_sel::select_coins(&candidates, amount, self.min_confirmations)?;
        let mut violations = Vec::new();
        violations.extend(self.policy_engine.evaluate_selection(&selection));
        let mut outputs = vec![DraftOutput::new(&to, amount, false)];
        violations.extend(self.policy_engine.evaluate_outputs(&outputs));
        if let Some(violation) = self.policy_engine.evaluate_daily_limit(amount) {
            violations.push(violation);
        }
        if !violations.is_empty() {
            return Err(EngineError::Policy(violations));
        }
        let total_in: u128 = selection.iter().map(|utxo| utxo.record.value).sum();
        let mut fee = self.tx_builder.estimate_fee(selection.len(), outputs.len(), fee_rate);
        if total_in < amount + fee {
            return Err(BuilderError::InsufficientFunds { required: amount + fee, available: total_in }.into());
        }
        let mut change_output = None;
        let mut remainder = total_in
            .checked_sub(amount)
            .and_then(|value| value.checked_sub(fee))
            .ok_or_else(|| BuilderError::InsufficientFunds {
                required: amount + fee,
                available: total_in,
            })?;
        if remainder >= self.tx_builder.dust_limit() {
            fee = self
                .tx_builder
                .estimate_fee(selection.len(), outputs.len() + 1, fee_rate);
            remainder = total_in
                .checked_sub(amount)
                .and_then(|value| value.checked_sub(fee))
                .ok_or_else(|| BuilderError::InsufficientFunds {
                    required: amount + fee,
                    available: total_in,
                })?;
            if remainder >= self.tx_builder.dust_limit() {
                let change = self.address_manager.next_internal_address()?;
                change_output = Some(DraftOutput::new(change.address, remainder, true));
            } else {
                fee = fee.checked_add(remainder).ok_or(BuilderError::FeeOverflow)?;
                remainder = 0;
            }
        } else {
            fee = fee.checked_add(remainder).ok_or(BuilderError::FeeOverflow)?;
            remainder = 0;
        }
        if let Some(change) = change_output {
            outputs.push(change);
        }
        let spend_model = SpendModel::Exact { amount };
        let draft = self
            .tx_builder
            .assemble(selection, outputs, fee_rate, fee, spend_model);
        self.address_manager
            .mark_inputs_pending(draft.inputs.iter().map(|input| &input.outpoint))?;
        Ok(draft)
    }
}

