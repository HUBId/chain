use anyhow::Result;
use rpp::runtime::node::MempoolStatus;
use serde_json;
use sha2::{Digest, Sha256};
use tokio::sync::broadcast::{self, error::TryRecvError};

use crate::vendor::electrs::chain::Chain;
use crate::vendor::electrs::daemon::Daemon;
use crate::vendor::electrs::index::Index;
use crate::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, Script, Txid};
use crate::vendor::electrs::status::{Balance, ScriptHashStatus, UnspentEntry};

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
                self.index.index_block(header, &transactions)?;
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
        status.sync(script, self.index(), self.chain())?;
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
    ) -> Result<Option<(BlockHash, Box<[u8]>)>> {
        Ok(daemon.find_transaction(txid))
    }

    /// The simplified tracker is always considered ready.
    pub fn status(&self) -> Result<()> {
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use tempfile::TempDir;

    use crate::vendor::electrs::daemon::test_helpers::setup;
    use crate::vendor::electrs::index::Index;
    use crate::vendor::electrs::rpp_ledger::bitcoin::Network;

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
}

