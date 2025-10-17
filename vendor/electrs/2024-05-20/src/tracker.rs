use anyhow::Result;

use crate::vendor::electrs::chain::Chain;
use crate::vendor::electrs::daemon::Daemon;
use crate::vendor::electrs::index::Index;
use crate::vendor::electrs::rpp_ledger::bitcoin::{BlockHash, Script, Txid};
use crate::vendor::electrs::status::{Balance, ScriptHashStatus, UnspentEntry};

/// High-level coordinator that keeps the index in sync with the daemon and
/// exposes convenience helpers for status tracking.
pub struct Tracker {
    index: Index,
}

impl Tracker {
    /// Create a tracker around an already-initialised index.
    pub fn new(index: Index) -> Self {
        Self { index }
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
        let current_height = self.index.chain().height();
        let mut updated = false;
        for (header, transactions) in daemon.blocks_since(current_height) {
            self.index.index_block(header, &transactions)?;
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
}
