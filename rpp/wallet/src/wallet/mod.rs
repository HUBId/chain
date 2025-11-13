use std::sync::Arc;

use anyhow::Result as AnyResult;

use crate::config::wallet::{WalletFeeConfig, WalletPolicyConfig, WalletProverConfig};
use crate::db::{TxCacheEntry, UtxoRecord, WalletStore};
use crate::engine::signing::{build_wallet_prover, ProverError as EngineProverError, ProverOutput, WalletProver};
use crate::engine::{DraftTransaction, EngineError, WalletBalance, WalletEngine};

#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("engine error: {0}")]
    Engine(#[from] EngineError),
    #[error("prover error: {0}")]
    Prover(#[from] EngineProverError),
    #[error("node error: {0}")]
    Node(#[from] anyhow::Error),
}

pub trait NodeClient: Send + Sync {
    fn broadcast(&self, draft: &DraftTransaction) -> AnyResult<()>;
    fn rescan(&self) -> AnyResult<()>;
}

pub struct Wallet {
    store: Arc<WalletStore>,
    engine: WalletEngine,
    node_client: Arc<dyn NodeClient>,
    prover: Arc<dyn WalletProver>,
    identifier: String,
}

impl Wallet {
    pub fn new(
        store: Arc<WalletStore>,
        root_seed: [u8; 32],
        policy: WalletPolicyConfig,
        fees: WalletFeeConfig,
        prover_config: WalletProverConfig,
        node_client: Arc<dyn NodeClient>,
    ) -> Result<Self, WalletError> {
        let engine = WalletEngine::new(Arc::clone(&store), root_seed, policy, fees)?;
        let prover = build_wallet_prover(&prover_config)?;
        let identifier = engine.identifier();
        Ok(Self {
            store,
            engine,
            node_client,
            prover,
            identifier,
        })
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
        Ok(self.engine.create_draft(to, amount, fee_rate)?)
    }

    pub fn sign_and_prove(&self, draft: &DraftTransaction) -> Result<ProverOutput, WalletError> {
        Ok(self.prover.prove(draft)?)
    }

    pub fn broadcast(&self, draft: &DraftTransaction) -> Result<(), WalletError> {
        self.node_client.broadcast(draft)?;
        Ok(())
    }

    pub fn rescan(&self) -> Result<(), WalletError> {
        self.node_client.rescan()?;
        Ok(())
    }

    pub fn store(&self) -> Arc<WalletStore> {
        Arc::clone(&self.store)
    }

    pub fn engine(&self) -> &WalletEngine {
        &self.engine
    }
}

