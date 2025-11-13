use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use hex::FromHexError;
use thiserror::Error;

use crate::db::{
    checkpoints::{
        birthday_height, persist_birthday_height, persist_last_scan_ts, persist_resume_height,
        resume_height,
    },
    AddressKind, TxCacheEntry, UtxoOutpoint, UtxoRecord, WalletStore, WalletStoreBatch,
    WalletStoreError,
};
use crate::engine::{AddressError, WalletEngine};

use super::client::{
    GetHeadersRequest, GetHeadersResponse, GetScripthashStatusRequest, IndexedUtxo, IndexerClient,
    IndexerClientError, ListScripthashUtxosRequest, TransactionPayload,
};

const DEFAULT_DISCOVERY_BATCH: usize = 16;

/// High-level wallet scanner that keeps the local store in sync with an indexer backend.
pub struct WalletScanner {
    engine: Arc<WalletEngine>,
    client: Arc<dyn IndexerClient>,
    discovery_batch: usize,
    start_height: u64,
}

/// Aggregated synchronisation status returned by scanning operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncStatus {
    /// Latest chain height reported by the indexer backend.
    pub latest_height: u64,
    /// Number of script hashes (addresses) visited during the scan.
    pub scanned_scripthashes: usize,
    /// Optional pending height range that still requires backfilling.
    pub pending_range: Option<(u64, u64)>,
}

#[derive(Clone, Copy, Debug)]
enum ScanMode {
    Full,
    Resume,
    Rescan { from_height: u64 },
}

/// Errors emitted during wallet scanning operations.
#[derive(Debug, Error)]
pub enum ScannerError {
    #[error("store error: {0}")]
    Store(#[from] WalletStoreError),
    #[error("address manager error: {0}")]
    Address(#[from] AddressError),
    #[error("indexer error: {0}")]
    Indexer(#[from] IndexerClientError),
    #[error("invalid wallet address encoding: {0}")]
    InvalidAddress(#[from] FromHexError),
}

impl WalletScanner {
    /// Construct a new wallet scanner backed by the provided engine and indexer client.
    pub fn new(
        engine: Arc<WalletEngine>,
        client: Arc<dyn IndexerClient>,
    ) -> Result<Self, ScannerError> {
        let start_height = birthday_height(engine.store())?.unwrap_or(0);
        Ok(Self {
            engine,
            client,
            discovery_batch: DEFAULT_DISCOVERY_BATCH,
            start_height,
        })
    }

    /// Execute a full synchronisation starting from the configured birthday height.
    pub fn sync_full(&self) -> Result<SyncStatus, ScannerError> {
        self.scan(ScanMode::Full)
    }

    /// Resume synchronisation from the last stored checkpoint.
    pub fn sync_resume(&self) -> Result<SyncStatus, ScannerError> {
        self.scan(ScanMode::Resume)
    }

    /// Trigger an explicit rescan starting from `from_height`.
    pub fn rescan_from(&self, from_height: u64) -> Result<SyncStatus, ScannerError> {
        self.scan(ScanMode::Rescan { from_height })
    }

    fn scan(&self, mode: ScanMode) -> Result<SyncStatus, ScannerError> {
        let store = self.engine.store();
        let base_height = match mode {
            ScanMode::Full => self.start_height,
            ScanMode::Resume => resume_height(store)?.unwrap_or(self.start_height),
            ScanMode::Rescan { from_height } => from_height,
        };

        let headers = self
            .client
            .get_headers(&GetHeadersRequest::new(base_height, 1))?;
        let latest_height = headers.latest_height;

        let mut scanned_scripthashes = 0usize;
        for kind in [AddressKind::External, AddressKind::Internal] {
            scanned_scripthashes += self.scan_address_space(kind, base_height, latest_height)?;
        }

        let existing_birthday = birthday_height(store)?;
        let mut batch = store.batch()?;
        self.persist_checkpoints(
            &mut batch,
            mode,
            base_height,
            latest_height,
            existing_birthday,
        )?;
        batch.commit()?;

        Ok(SyncStatus {
            latest_height,
            scanned_scripthashes,
            pending_range: (base_height < latest_height).then_some((base_height, latest_height)),
        })
    }

    fn scan_address_space(
        &self,
        kind: AddressKind,
        base_height: u64,
        latest_height: u64,
    ) -> Result<usize, ScannerError> {
        let store = self.engine.store();
        let mut scanned = 0usize;
        let mut queue: VecDeque<TrackedAddress> = self.load_known_addresses(kind)?.into();

        loop {
            if queue.is_empty() {
                let derived = self.derive_batch(kind)?;
                if derived.is_empty() {
                    break;
                }
                queue.extend(derived);
            }

            let Some(address) = queue.pop_front() else {
                break;
            };
            scanned += 1;
            if self.scan_single_address(store, &address, latest_height)? {
                self.engine
                    .address_manager()
                    .mark_address_used(kind, address.index)?;
            }
        }

        Ok(scanned)
    }

    fn scan_single_address(
        &self,
        store: &Arc<WalletStore>,
        address: &TrackedAddress,
        latest_height: u64,
    ) -> Result<bool, ScannerError> {
        let scripthash = decode_address_scripthash(&address.address)?;

        let _status = self
            .client
            .get_scripthash_status(&GetScripthashStatusRequest::new(scripthash))?;
        let utxo_response = self
            .client
            .list_scripthash_utxos(&ListScripthashUtxosRequest::new(scripthash))?;

        let mut new_utxos = Vec::new();
        let mut tx_requests = HashSet::new();
        for utxo in utxo_response.utxos {
            let outpoint = UtxoOutpoint::new(utxo.outpoint.txid, utxo.outpoint.vout);
            if store.get_utxo(&outpoint)?.is_some() {
                continue;
            }

            new_utxos.push(UtxoRecord::new(
                outpoint,
                address.address.clone(),
                u128::from(utxo.value),
                Cow::Owned(utxo.script.clone()),
                utxo.height,
            ));
            tx_requests.insert(utxo.outpoint.txid);
        }

        let mut new_txs = Vec::new();
        for txid in tx_requests {
            if store.get_tx_cache_entry(&txid)?.is_some() {
                continue;
            }
            let response = self
                .client
                .get_transaction(&super::client::GetTransactionRequest::new(txid))?;
            if let Some(tx) = response.transaction {
                new_txs.push((txid, normalise_transaction(tx, latest_height)));
            }
        }

        if new_utxos.is_empty() && new_txs.is_empty() {
            return Ok(false);
        }

        let mut batch = store.batch()?;
        for utxo in &new_utxos {
            batch.put_utxo(utxo)?;
        }
        for (txid, entry) in &new_txs {
            batch.put_tx_cache_entry(txid, entry)?;
        }
        batch.commit()?;

        // If we imported new data, advance checkpoints immediately to avoid reprocessing on
        // subsequent resume scans.
        let mut checkpoint_batch = store.batch()?;
        persist_resume_height(&mut checkpoint_batch, Some(latest_height))?;
        let ts = current_timestamp_ms();
        persist_last_scan_ts(&mut checkpoint_batch, Some(ts))?;
        checkpoint_batch.commit()?;

        Ok(true)
    }

    fn load_known_addresses(&self, kind: AddressKind) -> Result<Vec<TrackedAddress>, ScannerError> {
        let mut entries = self.engine.store().iter_addresses(kind)?;
        entries.sort_by_key(|(index, _)| *index);
        Ok(entries
            .into_iter()
            .map(|(index, address)| TrackedAddress {
                kind,
                index,
                address,
            })
            .collect())
    }

    fn derive_batch(&self, kind: AddressKind) -> Result<Vec<TrackedAddress>, ScannerError> {
        let manager = self.engine.address_manager();
        let mut derived = Vec::new();
        for _ in 0..self.discovery_batch {
            let derived_address = match kind {
                AddressKind::External => manager.next_external_address(),
                AddressKind::Internal => manager.next_internal_address(),
            };
            match derived_address {
                Ok(address) => derived.push(TrackedAddress {
                    kind,
                    index: address.path.index,
                    address: address.address,
                }),
                Err(AddressError::GapLimit { .. }) => break,
                Err(err) => return Err(ScannerError::Address(err)),
            }
        }
        Ok(derived)
    }

    fn persist_checkpoints(
        &self,
        batch: &mut WalletStoreBatch<'_>,
        mode: ScanMode,
        base_height: u64,
        latest_height: u64,
        existing_birthday: Option<u64>,
    ) -> Result<(), ScannerError> {
        let desired_birthday = match (mode, existing_birthday) {
            (ScanMode::Full, None) => Some(base_height),
            (ScanMode::Full, Some(current)) => Some(current.min(base_height)),
            (ScanMode::Resume, Some(current)) => Some(current),
            (ScanMode::Resume, None) => Some(base_height),
            (ScanMode::Rescan { from_height }, Some(current)) => Some(current.min(from_height)),
            (ScanMode::Rescan { from_height }, None) => Some(from_height),
        };
        persist_birthday_height(batch, desired_birthday)?;
        persist_resume_height(batch, Some(latest_height))?;
        let ts = current_timestamp_ms();
        persist_last_scan_ts(batch, Some(ts))?;
        Ok(())
    }
}

fn decode_address_scripthash(address: &str) -> Result<[u8; 32], FromHexError> {
    let bytes = hex::decode(address)?;
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[..32]);
    Ok(hash)
}

fn normalise_transaction(
    payload: TransactionPayload,
    fallback_height: u64,
) -> TxCacheEntry<'static> {
    let height = payload.height.unwrap_or(fallback_height);
    let timestamp_ms = current_timestamp_ms();
    let raw = payload.raw.into_owned();
    TxCacheEntry::new(height, timestamp_ms, Cow::Owned(raw))
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone, Debug)]
struct TrackedAddress {
    kind: AddressKind,
    index: u32,
    address: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::wallet::{WalletFeeConfig, WalletPolicyConfig};
    use crate::db::checkpoints;
    use crate::db::WalletStore;
    use crate::engine::AddressManager;
    use crate::indexer::client::{GetTransactionRequest, IndexedHeader, TxOutpoint};
    use std::sync::Mutex;
    use tempfile::tempdir;

    #[test]
    fn scanner_discovers_utxos_past_gap() {
        let seed = [1u8; 32];
        let addresses = derive_external_addresses(seed, 3);

        let latest_height = 120;
        let mut mock = MockIndexer::new(latest_height);
        mock.add_status(&addresses[1]);
        mock.add_utxo(
            &addresses[1],
            IndexedUtxo::new(
                TxOutpoint::new([2u8; 32], 0),
                50_000,
                hex::decode(&addresses[1]).unwrap(),
                Some(latest_height - 10),
            ),
        );
        mock.add_transaction(
            [2u8; 32],
            TransactionPayload::new(
                [2u8; 32],
                Some(latest_height - 10),
                Cow::Owned(vec![1, 2, 3]),
            ),
        );

        let (engine, scanner) = test_engine_and_scanner(seed, mock);
        let status = scanner.sync_full().expect("sync full");

        assert_eq!(status.latest_height, latest_height);
        let utxos = engine.store().iter_utxos().expect("utxos");
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].owner, addresses[1]);
        let cached = engine.store().iter_tx_cache_entries().expect("tx cache");
        assert_eq!(cached.len(), 1);
    }

    #[test]
    fn scanner_avoids_duplicate_entries() {
        let seed = [9u8; 32];
        let addresses = derive_external_addresses(seed, 2);
        let latest_height = 64;
        let mut mock = MockIndexer::new(latest_height);
        mock.add_status(&addresses[0]);
        mock.add_utxo(
            &addresses[0],
            IndexedUtxo::new(
                TxOutpoint::new([7u8; 32], 0),
                75_000,
                hex::decode(&addresses[0]).unwrap(),
                Some(latest_height - 5),
            ),
        );
        mock.add_transaction(
            [7u8; 32],
            TransactionPayload::new(
                [7u8; 32],
                Some(latest_height - 5),
                Cow::Owned(vec![9, 9, 9]),
            ),
        );

        let (engine, scanner) = test_engine_and_scanner(seed, mock);
        scanner.sync_full().expect("first sync");
        scanner.sync_resume().expect("resume sync");

        let utxos = engine.store().iter_utxos().expect("utxos");
        assert_eq!(utxos.len(), 1);
        let cached = engine.store().iter_tx_cache_entries().expect("tx cache");
        assert_eq!(cached.len(), 1);
    }

    #[test]
    fn scanner_updates_checkpoints() {
        let seed = [3u8; 32];
        let addresses = derive_external_addresses(seed, 1);
        let latest_height = 22;
        let mut mock = MockIndexer::new(latest_height);
        mock.add_status(&addresses[0]);

        let (engine, scanner) = test_engine_and_scanner(seed, mock);
        let status = scanner.sync_full().expect("sync full");
        assert_eq!(status.latest_height, latest_height);

        let store = engine.store();
        let resume = checkpoints::resume_height(store).expect("resume");
        assert_eq!(resume, Some(latest_height));
        let birthday = checkpoints::birthday_height(store).expect("birthday");
        assert_eq!(birthday, Some(0));
        let timestamp = checkpoints::last_scan_ts(store).expect("ts");
        assert!(timestamp.unwrap_or(0) > 0);
    }

    fn test_engine_and_scanner(
        seed: [u8; 32],
        mock: MockIndexer,
    ) -> (Arc<WalletEngine>, WalletScanner) {
        let dir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(dir.path()).expect("store"));
        let policy = WalletPolicyConfig {
            external_gap_limit: 4,
            internal_gap_limit: 4,
            min_confirmations: 1,
        };
        let engine = Arc::new(
            WalletEngine::new(Arc::clone(&store), seed, policy, WalletFeeConfig::default())
                .expect("engine"),
        );
        let scanner = WalletScanner::new(Arc::clone(&engine), Arc::new(mock)).expect("scanner");
        (engine, scanner)
    }

    fn derive_external_addresses(seed: [u8; 32], count: usize) -> Vec<String> {
        let dir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(dir.path()).expect("store"));
        let manager = AddressManager::new(Arc::clone(&store), seed, 16, 16).expect("manager");
        (0..count)
            .map(|_| manager.next_external_address().expect("address").address)
            .collect()
    }

    #[derive(Clone)]
    struct MockIndexer {
        latest_height: u64,
        statuses: Arc<Mutex<HashSet<[u8; 32]>>>,
        utxos: Arc<Mutex<HashMap<[u8; 32], Vec<IndexedUtxo>>>>,
        transactions: Arc<Mutex<HashMap<[u8; 32], TransactionPayload>>>,
    }

    impl MockIndexer {
        fn new(latest_height: u64) -> Self {
            Self {
                latest_height,
                statuses: Arc::new(Mutex::new(HashSet::new())),
                utxos: Arc::new(Mutex::new(HashMap::new())),
                transactions: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn add_status(&mut self, address: &str) {
            let hash = decode_address_scripthash(address).expect("decode");
            self.statuses.lock().unwrap().insert(hash);
        }

        fn add_utxo(&mut self, address: &str, utxo: IndexedUtxo) {
            let hash = decode_address_scripthash(address).expect("decode");
            self.utxos
                .lock()
                .unwrap()
                .entry(hash)
                .or_default()
                .push(utxo);
        }

        fn add_transaction(&mut self, txid: [u8; 32], payload: TransactionPayload) {
            self.transactions.lock().unwrap().insert(txid, payload);
        }
    }

    impl IndexerClient for MockIndexer {
        fn get_headers(
            &self,
            request: &GetHeadersRequest,
        ) -> Result<GetHeadersResponse, IndexerClientError> {
            let header = IndexedHeader::new(request.start_height, [0u8; 32], [0u8; 32], vec![]);
            Ok(GetHeadersResponse::new(self.latest_height, vec![header]))
        }

        fn get_scripthash_status(
            &self,
            request: &GetScripthashStatusRequest,
        ) -> Result<super::client::GetScripthashStatusResponse, IndexerClientError> {
            let status = self
                .statuses
                .lock()
                .unwrap()
                .contains(&request.scripthash)
                .then(|| hex::encode(request.scripthash));
            Ok(super::client::GetScripthashStatusResponse::new(status))
        }

        fn list_scripthash_utxos(
            &self,
            request: &ListScripthashUtxosRequest,
        ) -> Result<super::client::ListScripthashUtxosResponse, IndexerClientError> {
            let utxos = self
                .utxos
                .lock()
                .unwrap()
                .get(&request.scripthash)
                .cloned()
                .unwrap_or_default();
            Ok(super::client::ListScripthashUtxosResponse::new(utxos))
        }

        fn get_transaction(
            &self,
            request: &GetTransactionRequest,
        ) -> Result<super::client::GetTransactionResponse, IndexerClientError> {
            let tx = self
                .transactions
                .lock()
                .unwrap()
                .get(&request.txid)
                .cloned();
            Ok(super::client::GetTransactionResponse::new(tx))
        }
    }
}
