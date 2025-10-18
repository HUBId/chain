use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rpp::runtime::node::MempoolStatus;
use rpp::runtime::types::Block as RuntimeBlock;
use serde_json;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast::{self, error::TryRecvError};

use crate::vendor::electrs::chain::Chain;
use crate::vendor::electrs::daemon::Daemon;
use crate::vendor::electrs::index::Index;
use crate::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, Script, Txid};
use crate::vendor::electrs::status::{Balance, ScriptHashStatus, UnspentEntry};
use crate::vendor::electrs::types::{
    bsl_txid, serialize_block, serialize_transaction, HashPrefixRow, TxidRow, HASH_PREFIX_ROW_SIZE,
};

#[derive(Clone, Debug)]
pub enum TransactionLookup {
    Block {
        block_hash: BlockHash,
        block_height: u64,
        block: Box<[u8]>,
        transaction: Box<[u8]>,
    },
    Mempool {
        status: MempoolStatus,
    },
}

/// High-level coordinator that keeps the index in sync with the daemon and
/// exposes convenience helpers for status tracking.
pub struct Tracker {
    index: Index,
    mempool: Option<MempoolStatus>,
    mempool_fingerprint: Option<[u8; 32]>,
    block_notifications: Option<broadcast::Receiver<Vec<u8>>>,
}

impl Tracker {
    /// Create a tracker around an already-initialised index.
    pub fn new(index: Index) -> Self {
        Self {
            index,
            mempool: None,
            mempool_fingerprint: None,
            block_notifications: None,
        }
    }

    /// Immutable access to the underlying index.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Mutable access to the underlying index.
    pub fn index_mut(&mut self) -> &mut Index {
        &mut self.index
    }

    /// Access the tracked chain state.
    pub fn chain(&self) -> &Chain {
        self.index.chain()
    }

    /// Consume queued blocks from the daemon and extend the local index.
    pub fn sync(&mut self, daemon: &Daemon) -> Result<bool> {
        self.ensure_block_subscription(daemon)?;

        let mut updated = self.drain_block_notifications();

        let current_height = self.index.chain().height();
        let new_headers = daemon.get_new_headers(self.chain())?;
        if !new_headers.is_empty() {
            for (header, transactions) in daemon.blocks_since(current_height)? {
                self.index
                    .index_block(header, &transactions, None)?;
            }
            updated = true;
        }

        if self.refresh_mempool(daemon)? {
            updated = true;
        }

        Ok(updated)
    }

    /// Convenience wrapper to recompute a script hash status snapshot.
    pub fn update_scripthash_status(
        &self,
        status: &mut ScriptHashStatus,
        script: &Script,
    ) -> Result<bool> {
        let previous = status.statushash();
        status.sync(script, self.index(), self.chain(), self.mempool.as_ref())?;
        Ok(previous != status.statushash())
    }

    /// Return the deterministic balance used by the placeholder backend.
    pub fn get_balance(&self, status: &ScriptHashStatus) -> Balance {
        status.get_balance(self.chain())
    }

    /// Return tracked unspent outputs for the script hash.
    pub fn get_unspent(&self, status: &ScriptHashStatus) -> Vec<UnspentEntry> {
        status.get_unspent(self.chain())
    }

    /// Snapshot of the latest runtime mempool state observed during sync.
    pub fn mempool_status(&self) -> Option<&MempoolStatus> {
        self.mempool.as_ref()
    }

    /// Locate a transaction using the daemon's in-memory data set.
    pub fn lookup_transaction(
        &self,
        daemon: &Daemon,
        txid: Txid,
    ) -> Result<Option<TransactionLookup>> {
        if let Some(result) = self.locate_transaction_in_chain(daemon, txid)? {
            return Ok(Some(result));
        }

        if let Some(status) = self.mempool.as_ref() {
            return Ok(Some(TransactionLookup::Mempool {
                status: status.clone(),
            }));
        }

        Ok(None)
    }

    /// The simplified tracker is always considered ready.
    pub fn status(&self) -> Result<()> {
        Ok(())
    }

    fn locate_transaction_in_chain(
        &self,
        daemon: &Daemon,
        txid: Txid,
    ) -> Result<Option<TransactionLookup>> {
        const TXID_PREFIX: u8 = b't';
        let mut key_prefix = Vec::with_capacity(1 + HASH_PREFIX_ROW_SIZE);
        key_prefix.push(TXID_PREFIX);
        key_prefix.extend_from_slice(&TxidRow::scan_prefix(txid));

        let mut heights = Vec::new();
        for (key, value) in daemon.firewood().scan_prefix(&key_prefix) {
            if key.len() != 1 + HASH_PREFIX_ROW_SIZE {
                continue;
            }
            if value.len() != 32 || value.as_slice() != txid.as_bytes() {
                continue;
            }
            let mut row_bytes = [0u8; HASH_PREFIX_ROW_SIZE];
            row_bytes.copy_from_slice(&key[1..]);
            let row = HashPrefixRow::from_db_row(row_bytes);
            heights.push(row.height() as u64);
        }

        if heights.is_empty() {
            return Ok(None);
        }

        heights.sort_unstable();
        heights.dedup();

        let mut index = 0usize;
        while index < heights.len() {
            let mut start = heights[index];
            let mut end = start;
            while index + 1 < heights.len() && heights[index + 1] == end + 1 {
                index += 1;
                end = heights[index];
            }

            let blocks = reconstruct_verified_range(daemon, start, end)?;
            for block in blocks {
                let (header, transactions) = Daemon::convert_block(&block);
                for tx in &transactions {
                    if bsl_txid(tx) == txid {
                        let block_hash = header.block_hash();
                        let block_bytes = serialize_block(&transactions).into_boxed_slice();
                        let tx_bytes = serialize_transaction(tx).into_boxed_slice();
                        return Ok(Some(TransactionLookup::Block {
                            block_hash,
                            block_height: block.header.height,
                            block: block_bytes,
                            transaction: tx_bytes,
                        }));
                    }
                }
            }

            index += 1;
        }

        Ok(None)
    }

    fn ensure_block_subscription(&mut self, daemon: &Daemon) -> Result<()> {
        if self.block_notifications.is_none() {
            self.block_notifications = Some(daemon.new_block_notification()?);
        }
        Ok(())
    }

    fn drain_block_notifications(&mut self) -> bool {
        let mut updated = false;
        let mut closed = false;
        if let Some(receiver) = self.block_notifications.as_mut() {
            loop {
                match receiver.try_recv() {
                    Ok(_) => {
                        updated = true;
                    }
                    Err(TryRecvError::Lagged(_)) => {
                        updated = true;
                        continue;
                    }
                    Err(TryRecvError::Closed) => {
                        closed = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }
        }
        if closed {
            self.block_notifications = None;
        }
        updated
    }

    fn refresh_mempool(&mut self, daemon: &Daemon) -> Result<bool> {
        let snapshot = daemon.mempool_snapshot()?;
        let fingerprint = mempool_fingerprint(&snapshot)?;
        if self.mempool_fingerprint != Some(fingerprint) {
            self.mempool_fingerprint = Some(fingerprint);
            self.mempool = Some(snapshot);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

fn mempool_fingerprint(status: &MempoolStatus) -> Result<[u8; 32]> {
    let encoded = serde_json::to_vec(status)?;
    let digest: [u8; 32] = Sha256::digest(&encoded).into();
    Ok(digest)
}

fn reconstruct_verified_range(
    daemon: &Daemon,
    start: u64,
    end: u64,
) -> Result<Vec<RuntimeBlock>> {
    let runtime = daemon.runtime();
    let provider = Arc::clone(runtime.payload_provider());
    let blocks = runtime
        .node()
        .reconstruct_range(start, end, provider.as_ref())
        .map_err(|err| anyhow!("reconstruct blocks {start}..={end}: {err}"))?;
    let verifier = Arc::clone(runtime.proof_verifier());
    for block in &blocks {
        let proof_bytes = serde_json::to_vec(&block.recursive_proof.proof)
            .context("encode recursive proof payload")?;
        verifier
            .verify_recursive(
                &proof_bytes,
                &block.recursive_proof.commitment,
                block.recursive_proof.previous_commitment.as_deref(),
            )
            .map_err(|err| {
                anyhow!(
                    "verify recursive proof for block {}: {err}",
                    block.header.height
                )
            })?;
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use tempfile::TempDir;

    use crate::vendor::electrs::daemon::test_helpers::setup;
    use crate::vendor::electrs::index::Index;
    use crate::vendor::electrs::rpp_ledger::bitcoin::{Network, Txid};

    #[test]
    fn sync_indexes_blocks_from_runtime() {
        let temp_dir = TempDir::new().expect("tempdir");
        let index_path = temp_dir.path().join("index");
        fs::create_dir_all(&index_path).expect("index dir");
        let index = Index::open(&index_path, Network::Regtest).expect("open index");
        let mut tracker = Tracker::new(index);

        let context = setup();
        let updated = tracker.sync(&context.daemon).expect("sync tracker");
        assert!(updated, "initial sync should report updates");

        let daemon_tip = context.daemon.tip().expect("daemon tip");
        assert_eq!(tracker.chain().tip(), daemon_tip);

        let second = tracker.sync(&context.daemon).expect("second sync");
        assert!(!second, "subsequent sync without changes should be idle");
    }

    #[test]
    fn lookup_transaction_reconstructs_verified_payload() {
        let temp_dir = TempDir::new().expect("tempdir");
        let index_path = temp_dir.path().join("index");
        fs::create_dir_all(&index_path).expect("index dir");
        let index = Index::open(&index_path, Network::Regtest).expect("open index");
        let mut tracker = Tracker::new(index);

        let context = setup();
        tracker.sync(&context.daemon).expect("sync tracker");

        let lookup = tracker
            .lookup_transaction(&context.daemon, context.transaction_id)
            .expect("lookup transaction")
            .expect("transaction should be located");

        match lookup {
            TransactionLookup::Block {
                block_hash,
                block_height,
                block,
                transaction,
            } => {
                assert_eq!(block_hash, context.block_one_hash);
                assert_eq!(block_height, 1);
                assert_eq!(block.as_ref(), context.expected_block_bytes.as_slice());
                assert_eq!(
                    transaction.as_ref(),
                    context.expected_transaction_bytes.as_ref()
                );
            }
            TransactionLookup::Mempool { .. } => {
                panic!("expected block data, received mempool context");
            }
        }
    }

    #[test]
    fn lookup_transaction_surfaces_mempool_context_when_missing() {
        let temp_dir = TempDir::new().expect("tempdir");
        let index_path = temp_dir.path().join("index");
        fs::create_dir_all(&index_path).expect("index dir");
        let index = Index::open(&index_path, Network::Regtest).expect("open index");
        let mut tracker = Tracker::new(index);

        let context = setup();
        tracker.sync(&context.daemon).expect("sync tracker");

        let missing = Txid::from_bytes([0u8; 32]);
        let lookup = tracker
            .lookup_transaction(&context.daemon, missing)
            .expect("lookup transaction")
            .expect("mempool context should be available");

        match lookup {
            TransactionLookup::Mempool { status } => {
                assert!(status.transactions.is_empty());
            }
            TransactionLookup::Block { .. } => {
                panic!("expected mempool context for missing transaction");
            }
        }
    }
}

