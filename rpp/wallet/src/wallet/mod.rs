use std::sync::Arc;

use crate::config::wallet::{WalletFeeConfig, WalletPolicyConfig, WalletProverConfig};
use crate::db::{TxCacheEntry, UtxoRecord, WalletStore};
use crate::engine::signing::{
    build_wallet_prover, ProverError as EngineProverError, ProverOutput, WalletProver,
};
use crate::engine::{DraftTransaction, EngineError, WalletBalance, WalletEngine};
use crate::indexer::IndexerClient;
use crate::node_client::{ChainHead, NodeClient, NodeClientError};
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
}

pub struct Wallet {
    store: Arc<WalletStore>,
    engine: Arc<WalletEngine>,
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
        let engine = Arc::new(WalletEngine::new(
            Arc::clone(&store),
            root_seed,
            policy,
            fees,
        )?);
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
        self.node_client.submit_tx(draft)?;
        Ok(())
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

    pub fn store(&self) -> Arc<WalletStore> {
        Arc::clone(&self.store)
    }

    pub fn engine(&self) -> &WalletEngine {
        self.engine.as_ref()
    }

    pub fn engine_handle(&self) -> Arc<WalletEngine> {
        Arc::clone(&self.engine)
    }

    pub fn start_sync_coordinator(
        &self,
        indexer_client: Arc<dyn IndexerClient>,
    ) -> Result<WalletSyncCoordinator, WalletError> {
        WalletSyncCoordinator::start(self.engine_handle(), indexer_client).map_err(Into::into)
    }
}
