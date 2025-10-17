use std::sync::{mpsc, Arc, Mutex};

use anyhow::Result;

use crate::vendor::electrs::chain::{Chain, NewHeader};
use crate::vendor::electrs::rpp_ledger::bitcoin::blockdata::{
    block::Header as BlockHeader,
    constants,
};
use crate::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, Network, Txid};
use crate::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction;
use crate::vendor::electrs::types::{
    bsl_txid, serialize_block, serialize_transaction, SerBlock,
};

/// Lightweight daemon harness that mimics a Bitcoin Core RPC backend.
///
/// The real electrs daemon talks to bitcoind over RPC and P2P. Within the
/// repository we only need a deterministic, in-memory source of blocks so that
/// higher level components (indexer, status tracker) can be exercised in tests.
/// This harness stores headers and transactions and exposes a subset of the
/// upstream electrs interface.
pub struct Daemon {
    network: Network,
    blocks: Vec<(BlockHeader, Vec<Transaction>)>,
    subscribers: Arc<Mutex<Vec<mpsc::Sender<()>>>>,
}

impl Daemon {
    /// Create a new daemon pre-populated with the network genesis block.
    pub fn new(network: Network) -> Self {
        let genesis = constants::genesis_block(network).header;
        Self {
            network,
            blocks: vec![(genesis, Vec::new())],
            subscribers: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Return the configured ledger network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Current best block hash tracked by the daemon.
    pub fn tip(&self) -> BlockHash {
        self.blocks
            .last()
            .map(|(header, _)| header.block_hash())
            .unwrap_or_default()
    }

    /// Height of the best block known to the daemon.
    pub fn height(&self) -> usize {
        self.blocks.len().saturating_sub(1)
    }

    /// Append a new block to the in-memory chain.
    pub fn push_block(&mut self, header: BlockHeader, transactions: Vec<Transaction>) -> BlockHash {
        let hash = header.block_hash();
        self.blocks.push((header, transactions));
        self.notify_new_block();
        hash
    }

    fn notify_new_block(&self) {
        let mut subscribers = self.subscribers.lock().expect("poisoned notifier");
        subscribers.retain(|sender| sender.send(()).is_ok());
    }

    /// List headers that extend the provided chain tip.
    pub(crate) fn get_new_headers(&self, chain: &Chain) -> Result<Vec<NewHeader>> {
        let start_height = chain.height() + 1;
        Ok(self
            .blocks
            .iter()
            .enumerate()
            .skip(start_height)
            .map(|(height, (header, _))| NewHeader::from((header.clone(), height)))
            .collect())
    }

    /// Snapshot all blocks that appear above the provided height.
    pub fn blocks_since(&self, height: usize) -> Vec<(BlockHeader, Vec<Transaction>)> {
        self.blocks
            .iter()
            .enumerate()
            .skip(height + 1)
            .map(|(_, (header, txs))| (header.clone(), txs.clone()))
            .collect()
    }

    /// Iterate over blocks matching the supplied hashes and invoke `func` with
    /// their serialized representation.
    pub(crate) fn for_blocks<B, F>(&self, blockhashes: B, mut func: F) -> Result<()>
    where
        B: IntoIterator<Item = BlockHash>,
        F: FnMut(BlockHash, SerBlock),
    {
        for blockhash in blockhashes {
            if let Some((header, txs)) = self
                .blocks
                .iter()
                .find(|(header, _)| header.block_hash() == blockhash)
            {
                let serialized = serialize_block(txs);
                func(header.block_hash(), serialized);
            }
        }
        Ok(())
    }

    /// Subscribe to new block notifications. Each call returns a dedicated
    /// receiver that is triggered when [`push_block`] appends a new entry.
    pub(crate) fn new_block_notification(&self) -> mpsc::Receiver<()> {
        let (sender, receiver) = mpsc::channel();
        self
            .subscribers
            .lock()
            .expect("poisoned notifier")
            .push(sender);
        receiver
    }

    /// Find the serialized representation of `txid`, if the daemon knows about it.
    pub fn find_transaction(&self, txid: Txid) -> Option<(BlockHash, Box<[u8]>)> {
        for (header, transactions) in &self.blocks {
            for tx in transactions {
                if bsl_txid(tx) == txid {
                    let bytes = serialize_transaction(tx).into_boxed_slice();
                    return Some((header.block_hash(), bytes));
                }
            }
        }
        None
    }
}
