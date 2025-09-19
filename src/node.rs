use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::Keypair;
use parking_lot::RwLock;
use tokio::time;
use tracing::{info, warn};

use crate::config::{GenesisAccount, NodeConfig};
use crate::consensus::{aggregate_total_stake, select_proposer};
use crate::crypto::{address_from_public_key, load_or_generate_keypair, sign_message};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::{Ledger, compute_merkle_root};
use crate::storage::Storage;
use crate::types::{
    Account, Address, Block, BlockHeader, PruningProof, RecursiveProof, SignedTransaction,
};

const BASE_BLOCK_REWARD: u64 = 5;

#[derive(Clone, Copy)]
struct ChainTip {
    height: u64,
    last_hash: [u8; 32],
}

pub struct Node {
    inner: Arc<NodeInner>,
}

struct NodeInner {
    config: NodeConfig,
    keypair: Keypair,
    address: Address,
    storage: Storage,
    ledger: Ledger,
    mempool: RwLock<VecDeque<SignedTransaction>>,
    chain_tip: RwLock<ChainTip>,
    block_interval: Duration,
}

#[derive(Clone)]
pub struct NodeHandle {
    inner: Arc<NodeInner>,
}

impl Node {
    pub fn new(config: NodeConfig) -> ChainResult<Self> {
        config.ensure_directories()?;
        let keypair = load_or_generate_keypair(&config.key_path)?;
        let address = address_from_public_key(&keypair.public);
        let db_path = config.data_dir.join("db");
        let storage = Storage::open(&db_path)?;
        let mut accounts = storage.load_accounts()?;
        if storage.tip()?.is_none() {
            let genesis_accounts = if config.genesis.accounts.is_empty() {
                vec![GenesisAccount {
                    address: address.clone(),
                    balance: 1_000_000_000,
                    stake: "1000".to_string(),
                }]
            } else {
                config.genesis.accounts.clone()
            };
            accounts = build_genesis_accounts(genesis_accounts)?;
            for account in &accounts {
                storage.persist_account(account)?;
            }
            let ledger = Ledger::load(accounts.clone());
            let mut tx_hashes: Vec<[u8; 32]> = Vec::new();
            let tx_root = compute_merkle_root(&mut tx_hashes);
            let state_root = ledger.state_root();
            let state_root_hex = hex::encode(state_root);
            let stakes = ledger.stake_snapshot();
            let total_stake = aggregate_total_stake(&stakes);
            let header = BlockHeader::new(
                0,
                hex::encode([0u8; 32]),
                hex::encode(tx_root),
                state_root_hex.clone(),
                total_stake.to_string(),
                "0".to_string(),
                address.clone(),
            );
            let pruning_proof = PruningProof::genesis(&state_root_hex);
            let recursive_proof = RecursiveProof::genesis(&header, &pruning_proof);
            let signature = sign_message(&keypair, &header.canonical_bytes());
            let genesis_block = Block::new(
                header,
                Vec::new(),
                pruning_proof,
                recursive_proof,
                signature,
            );
            genesis_block.verify(None)?;
            storage.store_block(&genesis_block)?;
        }

        if accounts.is_empty() {
            accounts = storage.load_accounts()?;
        }

        let ledger = Ledger::load(accounts);

        let inner = Arc::new(NodeInner {
            block_interval: Duration::from_millis(config.block_time_ms),
            config,
            keypair,
            address,
            storage,
            ledger,
            mempool: RwLock::new(VecDeque::new()),
            chain_tip: RwLock::new(ChainTip {
                height: 0,
                last_hash: [0u8; 32],
            }),
        });
        inner.bootstrap()?;
        Ok(Self { inner })
    }

    pub fn handle(&self) -> NodeHandle {
        NodeHandle {
            inner: self.inner.clone(),
        }
    }

    pub async fn start(self) -> ChainResult<()> {
        self.inner.clone().run().await
    }
}

impl NodeHandle {
    pub fn submit_transaction(&self, tx: SignedTransaction) -> ChainResult<String> {
        self.inner.submit_transaction(tx)
    }

    pub fn get_block(&self, height: u64) -> ChainResult<Option<Block>> {
        self.inner.get_block(height)
    }

    pub fn latest_block(&self) -> ChainResult<Option<Block>> {
        self.inner.latest_block()
    }

    pub fn get_account(&self, address: &str) -> ChainResult<Option<Account>> {
        self.inner.get_account(address)
    }

    pub fn address(&self) -> &str {
        &self.inner.address
    }
}

impl NodeInner {
    async fn run(self: Arc<Self>) -> ChainResult<()> {
        info!(address = %self.address, "starting node");
        let mut ticker = time::interval(self.block_interval);
        loop {
            ticker.tick().await;
            if let Err(err) = self.produce_block() {
                warn!(?err, "block production failed");
            }
        }
    }

    fn submit_transaction(&self, tx: SignedTransaction) -> ChainResult<String> {
        tx.verify()?;
        let mut mempool = self.mempool.write();
        if mempool.len() >= self.config.mempool_limit {
            return Err(ChainError::Transaction("mempool full".into()));
        }
        let tx_hash = hex::encode(tx.hash());
        if mempool.iter().any(|existing| existing.id == tx.id) {
            return Err(ChainError::Transaction("transaction already queued".into()));
        }
        mempool.push_back(tx);
        Ok(tx_hash)
    }

    fn get_block(&self, height: u64) -> ChainResult<Option<Block>> {
        self.storage.read_block(height)
    }

    fn latest_block(&self) -> ChainResult<Option<Block>> {
        let tip_height = self.chain_tip.read().height;
        self.storage.read_block(tip_height)
    }

    fn get_account(&self, address: &str) -> ChainResult<Option<Account>> {
        Ok(self.ledger.get_account(address))
    }

    fn produce_block(&self) -> ChainResult<()> {
        let mut pending = Vec::new();
        {
            let mut mempool = self.mempool.write();
            while pending.len() < self.config.max_block_transactions {
                if let Some(tx) = mempool.pop_front() {
                    pending.push(tx);
                } else {
                    break;
                }
            }
        }
        if pending.is_empty() {
            return Ok(());
        }
        let tip_snapshot = *self.chain_tip.read();
        let stakes = self.ledger.stake_snapshot();
        let selection =
            match select_proposer(&stakes, &tip_snapshot.last_hash, tip_snapshot.height + 1) {
                Some(selection) => selection,
                None => {
                    warn!("no proposer could be selected");
                    return Ok(());
                }
            };
        if selection.proposer != self.address {
            info!(proposer = %selection.proposer, "not elected proposer for this round");
            return Ok(());
        }

        let mut accepted = Vec::new();
        let mut total_fees: u64 = 0;
        for tx in pending {
            match self.ledger.apply_transaction(&tx) {
                Ok(fee) => {
                    total_fees = total_fees.saturating_add(fee);
                    accepted.push(tx);
                }
                Err(err) => warn!(?err, "dropping invalid transaction"),
            }
        }

        if accepted.is_empty() {
            return Ok(());
        }

        let block_reward = BASE_BLOCK_REWARD.saturating_add(total_fees);
        self.ledger.reward_proposer(&self.address, block_reward);

        let mut tx_hashes = accepted.iter().map(|tx| tx.hash()).collect::<Vec<_>>();
        let tx_root = compute_merkle_root(&mut tx_hashes);
        let state_root = self.ledger.state_root();
        let height = tip_snapshot.height + 1;
        let header = BlockHeader::new(
            height,
            hex::encode(tip_snapshot.last_hash),
            hex::encode(tx_root),
            hex::encode(state_root),
            selection.total_stake.to_string(),
            selection.randomness.to_string(),
            self.address.clone(),
        );
        let previous_block = self.storage.read_block(tip_snapshot.height)?;
        let pruning_proof = PruningProof::from_previous(previous_block.as_ref(), &header);
        let recursive_proof = match previous_block.as_ref() {
            Some(block) => RecursiveProof::extend(&block.recursive_proof, &header, &pruning_proof),
            None => RecursiveProof::genesis(&header, &pruning_proof),
        };
        let signature = sign_message(&self.keypair, &header.canonical_bytes());
        let block = Block::new(header, accepted, pruning_proof, recursive_proof, signature);
        block.verify(previous_block.as_ref())?;
        self.storage.store_block(&block)?;
        self.persist_accounts()?;
        let mut tip = self.chain_tip.write();
        tip.height = block.header.height;
        tip.last_hash = block.block_hash();
        info!(height = tip.height, "sealed block");
        Ok(())
    }

    fn persist_accounts(&self) -> ChainResult<()> {
        let accounts = self.ledger.accounts_snapshot();
        for account in accounts {
            self.storage.persist_account(&account)?;
        }
        Ok(())
    }

    fn bootstrap(&self) -> ChainResult<()> {
        if let Some(metadata) = self.storage.tip()? {
            let block = self
                .storage
                .read_block(metadata.height)?
                .ok_or_else(|| ChainError::Config("tip metadata missing block".into()))?;
            block.verify(None)?;
            let mut tip = self.chain_tip.write();
            tip.height = block.header.height;
            tip.last_hash = block.block_hash();
        } else {
            let mut tip = self.chain_tip.write();
            tip.height = 0;
            tip.last_hash = [0u8; 32];
        }
        Ok(())
    }
}

fn build_genesis_accounts(entries: Vec<GenesisAccount>) -> ChainResult<Vec<Account>> {
    entries
        .into_iter()
        .map(|entry| {
            let stake = entry.stake_value()?;
            Ok(Account::new(entry.address, entry.balance, stake))
        })
        .collect()
}
