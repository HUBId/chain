use std::path::Path;

use anyhow::{Context, Result};
use storage_firewood::kv::{FirewoodKv, Hash, KvError};

/// Thin wrapper around the Firewood key-value engine that exposes a simplified
/// API tailored to the Electrs integration.
#[derive(Debug)]
pub struct FirewoodAdapter {
    inner: FirewoodKv,
}

impl FirewoodAdapter {
    /// Open (or create) a Firewood instance rooted at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let inner = FirewoodKv::open(path).context("open firewood store")?;
        Ok(Self { inner })
    }

    /// Stage a put mutation.
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.inner.put(key, value);
    }

    /// Stage a delete mutation.
    pub fn delete(&mut self, key: &[u8]) {
        self.inner.delete(key);
    }

    /// Fetch a value without mutating the staged batch.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

    /// Iterate over the state using a prefix filter.
    pub fn scan_prefix(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.inner.scan_prefix(prefix).collect()
    }

    /// Commit all staged mutations and persist them to disk.
    pub fn commit(&mut self) -> Result<Hash> {
        self.inner.commit().map_err(|err| match err {
            KvError::EmptyCommit => anyhow::anyhow!("firewood commit without mutations"),
            other => anyhow::Error::new(other).context("commit firewood state"),
        })
    }
}
