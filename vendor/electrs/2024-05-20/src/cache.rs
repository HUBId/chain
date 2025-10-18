use std::collections::HashMap;
use std::convert::TryInto;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use parking_lot::RwLock;

use crate::vendor::electrs::firewood_adapter::FirewoodAdapter;
use crate::vendor::electrs::rpp_ledger::bitcoin::Txid;
use crate::vendor::electrs::rpp_ledger::bitcoin_slices::bsl::Transaction;
use crate::vendor::electrs::types;

const TXID_LEN: usize = 32;

/// In-memory cache for serialized transactions backed by optional telemetry.
pub struct Cache {
    txs: Arc<RwLock<HashMap<Txid, Vec<u8>>>>,
    telemetry: CacheTelemetry,
}

impl Cache {
    /// Creates a new cache with the supplied telemetry handle.
    pub fn new(telemetry: CacheTelemetry) -> Self {
        Self {
            txs: Arc::new(RwLock::new(HashMap::new())),
            telemetry,
        }
    }

    /// Creates a cache instance without telemetry recording.
    pub fn without_telemetry() -> Self {
        Self::new(CacheTelemetry::disabled())
    }

    /// Returns the number of cached transactions.
    pub fn len(&self) -> usize {
        self.txs.read().len()
    }

    /// Returns the telemetry handle associated with the cache.
    pub fn telemetry(&self) -> CacheTelemetry {
        self.telemetry.clone()
    }

    /// Insert a transaction into the cache.
    ///
    /// Returns `true` when the transaction was newly inserted and `false` when
    /// it was already present.
    pub fn add_transaction(&self, txid: Txid, tx: &Transaction) -> bool {
        let serialized = types::serialize_transaction(tx);
        let len = serialized.len();
        let mut guard = self.txs.write();
        let is_new = guard.insert(txid, serialized).is_none();
        drop(guard);
        if is_new {
            self.telemetry.record_insert(len);
        }
        is_new
    }

    /// Fetch a cached transaction by running `f` on the serialized bytes.
    pub fn get_transaction<F, T>(&self, txid: &Txid, f: F) -> Option<T>
    where
        F: FnOnce(&[u8]) -> T,
    {
        let guard = self.txs.read();
        let result = guard.get(txid).map(|bytes| f(bytes));
        drop(guard);
        if result.is_some() {
            self.telemetry.record_hit();
        } else {
            self.telemetry.record_miss();
        }
        result
    }

    /// Persist the current cache contents under the provided Firewood prefix.
    ///
    /// Returns the number of serialized transactions that were written to the
    /// Firewood store.
    pub fn persist_warmup(
        &self,
        store: &mut FirewoodAdapter,
        prefix: &[u8],
    ) -> Result<usize> {
        let guard = self.txs.read();
        let mut count = 0usize;
        let mut total_bytes = 0usize;
        for (txid, bytes) in guard.iter() {
            let mut key = Vec::with_capacity(prefix.len() + TXID_LEN);
            key.extend_from_slice(prefix);
            key.extend_from_slice(txid.as_bytes());
            store.put(key, bytes.clone());
            count += 1;
            total_bytes += bytes.len();
        }
        drop(guard);

        if count > 0 {
            store.commit()?;
        }

        self.telemetry
            .record_warmup_persisted(count, total_bytes);
        Ok(count)
    }

    /// Populate the cache using previously persisted warmup data.
    ///
    /// The method loads serialized transactions that were written under
    /// `prefix` and inserts them into the cache. The return value matches the
    /// amount of unique transactions that were inserted.
    pub fn warm_from_firewood(
        &self,
        store: &FirewoodAdapter,
        prefix: &[u8],
    ) -> Result<usize> {
        let entries = store.scan_prefix(prefix);
        let mut added = 0usize;
        let mut total_bytes = 0usize;
        let mut guard = self.txs.write();
        for (key, bytes) in entries {
            if key.len() != prefix.len() + TXID_LEN {
                return Err(anyhow!(
                    "invalid warmup key length: expected {} got {}",
                    prefix.len() + TXID_LEN,
                    key.len()
                ));
            }
            let txid_slice = &key[prefix.len()..];
            let txid_bytes: [u8; TXID_LEN] = txid_slice
                .try_into()
                .map_err(|_| anyhow!("warmup key without txid suffix"))?;
            let txid = Txid::from_bytes(txid_bytes);
            let len = bytes.len();
            if guard.insert(txid, bytes).is_none() {
                added += 1;
                total_bytes += len;
                self.telemetry.record_insert(len);
            }
        }
        drop(guard);

        self.telemetry
            .record_warmup_loaded(added, total_bytes);
        Ok(added)
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::without_telemetry()
    }
}

/// Telemetry handle capturing cache statistics.
#[derive(Clone, Default)]
pub struct CacheTelemetry {
    inner: Arc<CacheTelemetryInner>,
}

#[derive(Default)]
struct CacheTelemetryInner {
    enabled: AtomicBool,
    hits: AtomicU64,
    misses: AtomicU64,
    entries: AtomicU64,
    stored_bytes: AtomicU64,
    largest_entry: AtomicU64,
    warmup_loaded: AtomicU64,
    warmup_loaded_bytes: AtomicU64,
    warmup_persisted: AtomicU64,
    warmup_persisted_bytes: AtomicU64,
}

impl CacheTelemetry {
    /// Construct a telemetry handle that records metrics when `enabled` is true.
    pub fn new(enabled: bool) -> Self {
        let telemetry = CacheTelemetryInner {
            enabled: AtomicBool::new(enabled),
            ..CacheTelemetryInner::default()
        };
        Self {
            inner: Arc::new(telemetry),
        }
    }

    /// Construct a telemetry handle that records metrics.
    pub fn enabled() -> Self {
        Self::new(true)
    }

    /// Construct a telemetry handle that ignores metric updates.
    pub fn disabled() -> Self {
        Self::new(false)
    }

    fn record_hit(&self) {
        if self.inner.enabled.load(Ordering::Relaxed) {
            self.inner.hits.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_miss(&self) {
        if self.inner.enabled.load(Ordering::Relaxed) {
            self.inner.misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn record_insert(&self, len: usize) {
        if !self.inner.enabled.load(Ordering::Relaxed) {
            return;
        }
        self.inner.entries.fetch_add(1, Ordering::Relaxed);
        self.inner
            .stored_bytes
            .fetch_add(len as u64, Ordering::Relaxed);
        self.update_largest(len as u64);
    }

    fn record_warmup_loaded(&self, count: usize, bytes: usize) {
        if !self.inner.enabled.load(Ordering::Relaxed) {
            return;
        }
        self.inner
            .warmup_loaded
            .fetch_add(count as u64, Ordering::Relaxed);
        self.inner
            .warmup_loaded_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn record_warmup_persisted(&self, count: usize, bytes: usize) {
        if !self.inner.enabled.load(Ordering::Relaxed) {
            return;
        }
        self.inner
            .warmup_persisted
            .fetch_add(count as u64, Ordering::Relaxed);
        self.inner
            .warmup_persisted_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    fn update_largest(&self, len: u64) {
        let mut current = self.inner.largest_entry.load(Ordering::Relaxed);
        while len > current {
            match self.inner.largest_entry.compare_exchange(
                current,
                len,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    /// Returns a snapshot of all currently recorded metrics.
    pub fn snapshot(&self) -> CacheMetricsSnapshot {
        if !self.inner.enabled.load(Ordering::Relaxed) {
            return CacheMetricsSnapshot::default();
        }
        CacheMetricsSnapshot {
            hits: self.inner.hits.load(Ordering::Relaxed),
            misses: self.inner.misses.load(Ordering::Relaxed),
            entries: self.inner.entries.load(Ordering::Relaxed),
            stored_bytes: self.inner.stored_bytes.load(Ordering::Relaxed),
            largest_entry_bytes: self.inner.largest_entry.load(Ordering::Relaxed),
            warmup_loaded: self.inner.warmup_loaded.load(Ordering::Relaxed),
            warmup_loaded_bytes: self
                .inner
                .warmup_loaded_bytes
                .load(Ordering::Relaxed),
            warmup_persisted: self.inner.warmup_persisted.load(Ordering::Relaxed),
            warmup_persisted_bytes: self
                .inner
                .warmup_persisted_bytes
                .load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of cache metrics.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CacheMetricsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
    pub stored_bytes: u64,
    pub largest_entry_bytes: u64,
    pub warmup_loaded: u64,
    pub warmup_loaded_bytes: u64,
    pub warmup_persisted: u64,
    pub warmup_persisted_bytes: u64,
}
