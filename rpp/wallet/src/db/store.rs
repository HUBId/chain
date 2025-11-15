use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use storage_firewood::{
    column_family::ColumnFamily,
    kv::{FirewoodKv, Hash, KvError},
};

use crate::db::{
    codec::{
        self, Address, CodecError, PendingLock, PolicySnapshot, StoredZsiArtifact, TxCacheEntry,
        UtxoOutpoint, UtxoRecord, WatchOnlyRecord,
    },
    migrations, schema,
};

/// High-level wallet facade around the Firewood key-value engine.
pub struct WalletStore {
    kv: Mutex<FirewoodKv>,
    pending_locks_cf: ColumnFamily,
    prover_meta_cf: ColumnFamily,
    checkpoints_cf: ColumnFamily,
}

impl WalletStore {
    /// Open or initialise a wallet store rooted at `data_dir`.
    pub fn open(data_dir: &Path) -> Result<Self, WalletStoreError> {
        let mut kv = FirewoodKv::open(data_dir)?;
        initialise_schema(&mut kv)?;
        let pending_locks_cf = open_extension(&kv, schema::EXTENSION_PENDING_LOCKS)?;
        let prover_meta_cf = open_extension(&kv, schema::EXTENSION_PROVER_META)?;
        let checkpoints_cf = open_extension(&kv, schema::EXTENSION_CHECKPOINTS)?;
        Ok(Self {
            kv: Mutex::new(kv),
            pending_locks_cf,
            prover_meta_cf,
            checkpoints_cf,
        })
    }

    /// Start a new batched write session.
    pub fn batch(&self) -> Result<WalletStoreBatch<'_>, WalletStoreError> {
        let guard = self.lock()?;
        Ok(WalletStoreBatch { guard })
    }

    /// Return the currently stored schema version.
    pub fn schema_version(&self) -> Result<u32, WalletStoreError> {
        let mut guard = self.lock()?;
        let Some(bytes) = guard.get(schema::SCHEMA_VERSION_KEY) else {
            return Ok(schema::SCHEMA_VERSION_LATEST);
        };
        drop(guard);
        Ok(codec::decode_schema_version(&bytes)?)
    }

    /// Column family storing pending lock extension state.
    pub fn pending_locks_extension(&self) -> ColumnFamily {
        self.pending_locks_cf.clone()
    }

    /// Column family storing prover metadata artifacts.
    pub fn prover_meta_extension(&self) -> ColumnFamily {
        self.prover_meta_cf.clone()
    }

    /// Column family holding checkpoint exports.
    pub fn checkpoints_extension(&self) -> ColumnFamily {
        self.checkpoints_cf.clone()
    }

    /// Fetch the recorded timestamp for the last rescan request.
    pub fn last_rescan_timestamp(&self) -> Result<Option<u64>, WalletStoreError> {
        self.get_meta_timestamp(schema::META_LAST_RESCAN_TS_KEY)
    }

    /// Fetch the timestamp when the fee cache was last refreshed.
    pub fn fee_cache_fetched_at(&self) -> Result<Option<u64>, WalletStoreError> {
        self.get_meta_timestamp(schema::META_FEE_CACHE_FETCHED_TS_KEY)
    }

    /// Fetch the timestamp indicating when the fee cache expires.
    pub fn fee_cache_expires_at(&self) -> Result<Option<u64>, WalletStoreError> {
        self.get_meta_timestamp(schema::META_FEE_CACHE_EXPIRES_TS_KEY)
    }

    /// Fetch a raw metadata value stored under the wallet namespace.
    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, WalletStoreError> {
        let mut guard = self.lock()?;
        let key = meta_key(key);
        Ok(guard.get(&key))
    }

    /// Enumerate all metadata entries stored under the wallet namespace.
    pub fn iter_meta(&self) -> Result<Vec<(String, Vec<u8>)>, WalletStoreError> {
        let mut guard = self.lock()?;
        let prefix = schema::META_NAMESPACE;
        let entries = guard
            .scan_prefix(prefix)
            .map(|(key, value)| {
                let label = std::str::from_utf8(&key[prefix.len()..])
                    .map_err(|err| WalletStoreError::CorruptKey(err.to_string()))?
                    .to_string();
                Ok((label, value))
            })
            .collect::<Result<Vec<_>, WalletStoreError>>()?;
        drop(guard);
        Ok(entries)
    }

    /// Fetch a raw backup metadata value stored under the backup namespace.
    pub fn get_backup_meta(&self, key: &str) -> Result<Option<Vec<u8>>, WalletStoreError> {
        self.get_raw(backup_meta_key(key))
    }

    /// Enumerate backup metadata entries stored under the backup namespace.
    pub fn iter_backup_meta(&self) -> Result<Vec<(String, Vec<u8>)>, WalletStoreError> {
        self.collect_namespace(schema::BACKUP_META_NAMESPACE)
    }

    /// Fetch a serialized multisig scope artefact.
    pub fn get_multisig_scope_entry(&self, key: &str) -> Result<Option<Vec<u8>>, WalletStoreError> {
        self.get_raw(multisig_scope_key(key))
    }

    /// Enumerate all serialized multisig scope artefacts.
    pub fn iter_multisig_scope(&self) -> Result<Vec<(String, Vec<u8>)>, WalletStoreError> {
        self.collect_namespace(schema::MULTISIG_SCOPE_NAMESPACE)
    }

    /// Fetch a wallet security RBAC record.
    pub fn get_security_rbac_entry(&self, key: &str) -> Result<Option<Vec<u8>>, WalletStoreError> {
        self.get_raw(security_rbac_key(key))
    }

    /// Enumerate wallet security RBAC records.
    pub fn iter_security_rbac(&self) -> Result<Vec<(String, Vec<u8>)>, WalletStoreError> {
        self.collect_namespace(schema::SECURITY_RBAC_NAMESPACE)
    }

    /// Fetch a wallet security mTLS record.
    pub fn get_security_mtls_entry(&self, key: &str) -> Result<Option<Vec<u8>>, WalletStoreError> {
        self.get_raw(security_mtls_key(key))
    }

    /// Enumerate wallet security mTLS records.
    pub fn iter_security_mtls(&self) -> Result<Vec<(String, Vec<u8>)>, WalletStoreError> {
        self.collect_namespace(schema::SECURITY_MTLS_NAMESPACE)
    }

    /// Fetch a hardware signer registry entry.
    pub fn get_hw_registry_entry(&self, key: &str) -> Result<Option<Vec<u8>>, WalletStoreError> {
        self.get_raw(hw_registry_key(key))
    }

    /// Enumerate hardware signer registry entries.
    pub fn iter_hw_registry(&self) -> Result<Vec<(String, Vec<u8>)>, WalletStoreError> {
        self.collect_namespace(schema::HW_REGISTRY_NAMESPACE)
    }

    /// Retrieve persisted key material.
    pub fn get_key_material(&self, label: &str) -> Result<Option<Vec<u8>>, WalletStoreError> {
        let mut guard = self.lock()?;
        let key = key_material_key(label);
        let Some(bytes) = guard.get(&key) else {
            return Ok(None);
        };
        drop(guard);
        Ok(Some(codec::decode_key_material(&bytes)?))
    }

    /// Load the persisted watch-only configuration record, when present.
    pub fn watch_only_record(&self) -> Result<Option<WatchOnlyRecord>, WalletStoreError> {
        let mut guard = self.lock()?;
        let key = watch_only_key(schema::WATCH_ONLY_STATE_KEY);
        let Some(bytes) = guard.get(&key) else {
            return Ok(None);
        };
        drop(guard);
        Ok(Some(codec::decode_watch_only(&bytes)?))
    }

    /// Load an address entry.
    pub fn get_address(
        &self,
        kind: AddressKind,
        index: u32,
    ) -> Result<Option<Address>, WalletStoreError> {
        let mut guard = self.lock()?;
        let key = address_key(kind, index);
        let Some(bytes) = guard.get(&key) else {
            return Ok(None);
        };
        drop(guard);
        Ok(Some(codec::decode_address(&bytes)?))
    }

    /// Enumerate all known addresses inside a namespace.
    pub fn iter_addresses(
        &self,
        kind: AddressKind,
    ) -> Result<Vec<(u32, Address)>, WalletStoreError> {
        let mut guard = self.lock()?;
        let prefix = kind.namespace();
        let entries = guard
            .scan_prefix(prefix)
            .map(|(key, value)| {
                let index = parse_u32_suffix(&key[prefix.len()..])?;
                let address = codec::decode_address(&value)?;
                Ok((index, address))
            })
            .collect::<Result<Vec<_>, WalletStoreError>>();
        drop(guard);
        entries
    }

    /// Fetch a single UTXO record.
    pub fn get_utxo(
        &self,
        outpoint: &UtxoOutpoint,
    ) -> Result<Option<UtxoRecord<'static>>, WalletStoreError> {
        let mut guard = self.lock()?;
        let key = utxo_key(outpoint);
        let Some(bytes) = guard.get(&key) else {
            return Ok(None);
        };
        drop(guard);
        Ok(Some(codec::decode_utxo(&bytes)?.into_owned()))
    }

    /// Iterate over all stored UTXO records.
    pub fn iter_utxos(&self) -> Result<Vec<UtxoRecord<'static>>, WalletStoreError> {
        let mut guard = self.lock()?;
        let prefix = schema::UTXOS_NAMESPACE;
        let utxos = guard
            .scan_prefix(prefix)
            .map(|(_, value)| codec::decode_utxo(&value).map(UtxoRecord::into_owned))
            .collect::<Result<Vec<_>, _>>()?;
        drop(guard);
        Ok(utxos)
    }

    /// Fetch a pending lock entry for a given outpoint.
    pub fn get_pending_lock(
        &self,
        outpoint: &UtxoOutpoint,
    ) -> Result<Option<PendingLock>, WalletStoreError> {
        let mut guard = self.lock()?;
        let key = pending_lock_key(outpoint);
        let Some(bytes) = guard.get(&key) else {
            return Ok(None);
        };
        drop(guard);
        Ok(Some(codec::decode_pending_lock(&bytes)?))
    }

    /// Iterate over all pending lock entries currently stored.
    pub fn iter_pending_locks(&self) -> Result<Vec<PendingLock>, WalletStoreError> {
        let mut guard = self.lock()?;
        let prefix = schema::PENDING_LOCKS_NAMESPACE;
        let locks = guard
            .scan_prefix(prefix)
            .map(|(_, value)| codec::decode_pending_lock(&value))
            .collect::<Result<Vec<_>, _>>()?;
        drop(guard);
        Ok(locks)
    }

    /// Fetch a cached ZSI lifecycle proof artefact.
    pub fn get_zsi_artifact(
        &self,
        identity: &str,
        commitment_digest: &str,
    ) -> Result<Option<StoredZsiArtifact<'static>>, WalletStoreError> {
        let mut guard = self.lock()?;
        let key = zsi_key(identity, commitment_digest);
        let Some(bytes) = guard.get(&key) else {
            return Ok(None);
        };
        drop(guard);
        Ok(Some(codec::decode_zsi_artifact(&bytes)?.into_owned()))
    }

    /// Enumerate all cached ZSI lifecycle proof artefacts.
    pub fn iter_zsi_artifacts(&self) -> Result<Vec<StoredZsiArtifact<'static>>, WalletStoreError> {
        let mut guard = self.lock()?;
        let prefix = schema::ZSI_NAMESPACE;
        let artifacts = guard
            .scan_prefix(prefix)
            .map(|(_, value)| codec::decode_zsi_artifact(&value).map(StoredZsiArtifact::into_owned))
            .collect::<Result<Vec<_>, _>>()?;
        drop(guard);
        Ok(artifacts)
    }

    /// Fetch a cached transaction entry by txid.
    pub fn get_tx_cache_entry(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<TxCacheEntry<'static>>, WalletStoreError> {
        let mut guard = self.lock()?;
        let key = tx_cache_key(txid);
        let Some(bytes) = guard.get(&key) else {
            return Ok(None);
        };
        drop(guard);
        Ok(Some(codec::decode_tx_cache_entry(&bytes)?.into_owned()))
    }

    /// Iterate over cached transactions.
    pub fn iter_tx_cache_entries(
        &self,
    ) -> Result<Vec<([u8; 32], TxCacheEntry<'static>)>, WalletStoreError> {
        let mut guard = self.lock()?;
        let prefix = schema::TX_CACHE_NAMESPACE;
        let entries = guard
            .scan_prefix(prefix)
            .map(|(key, value)| {
                let txid = parse_txid(&key[prefix.len()..])?;
                let entry = codec::decode_tx_cache_entry(&value)?.into_owned();
                Ok((txid, entry))
            })
            .collect::<Result<Vec<_>, WalletStoreError>>();
        drop(guard);
        entries
    }

    /// Fetch a persisted policy snapshot.
    pub fn get_policy_snapshot(
        &self,
        label: &str,
    ) -> Result<Option<PolicySnapshot>, WalletStoreError> {
        let mut guard = self.lock()?;
        let key = policy_key(label);
        let Some(bytes) = guard.get(&key) else {
            return Ok(None);
        };
        drop(guard);
        Ok(Some(codec::decode_policy_snapshot(&bytes)?))
    }

    /// Iterate over all stored policy snapshots.
    pub fn iter_policy_snapshots(&self) -> Result<Vec<(String, PolicySnapshot)>, WalletStoreError> {
        let mut guard = self.lock()?;
        let prefix = schema::POLICIES_NAMESPACE;
        let entries = guard
            .scan_prefix(prefix)
            .map(|(key, value)| {
                let label = std::str::from_utf8(&key[prefix.len()..])
                    .map_err(|err| WalletStoreError::CorruptKey(err.to_string()))?
                    .to_string();
                let snapshot = codec::decode_policy_snapshot(&value)?;
                Ok((label, snapshot))
            })
            .collect::<Result<Vec<_>, WalletStoreError>>();
        drop(guard);
        entries
    }

    /// Fetch a checkpoint (e.g. last synced height).
    pub fn get_checkpoint(&self, label: &str) -> Result<Option<u64>, WalletStoreError> {
        let mut guard = self.lock()?;
        let key = checkpoint_key(label);
        let Some(bytes) = guard.get(&key) else {
            return Ok(None);
        };
        drop(guard);
        Ok(Some(codec::decode_checkpoint(&bytes)?))
    }

    /// Iterate over stored checkpoints.
    pub fn iter_checkpoints(&self) -> Result<Vec<(String, u64)>, WalletStoreError> {
        let mut guard = self.lock()?;
        let prefix = schema::CHECKPOINTS_NAMESPACE;
        let entries = guard
            .scan_prefix(prefix)
            .map(|(key, value)| {
                let label = std::str::from_utf8(&key[prefix.len()..])
                    .map_err(|err| WalletStoreError::CorruptKey(err.to_string()))?
                    .to_string();
                let height = codec::decode_checkpoint(&value)?;
                Ok((label, height))
            })
            .collect::<Result<Vec<_>, WalletStoreError>>();
        drop(guard);
        entries
    }

    fn get_raw(&self, key: Vec<u8>) -> Result<Option<Vec<u8>>, WalletStoreError> {
        let mut guard = self.lock()?;
        let value = guard.get(&key);
        drop(guard);
        Ok(value)
    }

    fn collect_namespace(&self, prefix: &[u8]) -> Result<Vec<(String, Vec<u8>)>, WalletStoreError> {
        let mut guard = self.lock()?;
        let entries = guard
            .scan_prefix(prefix)
            .map(|(key, value)| {
                let label = std::str::from_utf8(&key[prefix.len()..])
                    .map_err(|err| WalletStoreError::CorruptKey(err.to_string()))?
                    .to_string();
                Ok((label, value))
            })
            .collect::<Result<Vec<_>, WalletStoreError>>()?;
        drop(guard);
        Ok(entries)
    }

    fn lock(&self) -> Result<MutexGuard<'_, FirewoodKv>, WalletStoreError> {
        self.kv.lock().map_err(|_| WalletStoreError::Poisoned)
    }

    fn get_meta_timestamp(&self, key: &str) -> Result<Option<u64>, WalletStoreError> {
        let mut guard = self.lock()?;
        let key = meta_key(key);
        let Some(bytes) = guard.get(&key) else {
            return Ok(None);
        };
        drop(guard);
        Ok(Some(codec::decode_checkpoint(&bytes)?))
    }
}

/// Address storage namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    External,
    Internal,
}

impl AddressKind {
    fn namespace(self) -> &'static [u8] {
        match self {
            AddressKind::External => schema::ADDR_EXTERNAL_NAMESPACE,
            AddressKind::Internal => schema::ADDR_INTERNAL_NAMESPACE,
        }
    }
}

/// Wrapper around a Firewood write batch.
pub struct WalletStoreBatch<'a> {
    guard: MutexGuard<'a, FirewoodKv>,
}

impl<'a> WalletStoreBatch<'a> {
    pub fn put_meta(&mut self, key: &str, value: &[u8]) {
        self.guard.put(meta_key(key), value.to_vec());
    }

    pub fn delete_meta(&mut self, key: &str) {
        self.guard.delete(&meta_key(key));
    }

    pub fn put_backup_meta(&mut self, key: &str, value: &[u8]) {
        self.guard.put(backup_meta_key(key), value.to_vec());
    }

    pub fn delete_backup_meta(&mut self, key: &str) {
        self.guard.delete(&backup_meta_key(key));
    }

    pub fn put_multisig_scope_entry(&mut self, key: &str, value: &[u8]) {
        self.guard.put(multisig_scope_key(key), value.to_vec());
    }

    pub fn delete_multisig_scope_entry(&mut self, key: &str) {
        self.guard.delete(&multisig_scope_key(key));
    }

    pub fn put_security_rbac_entry(&mut self, key: &str, value: &[u8]) {
        self.guard.put(security_rbac_key(key), value.to_vec());
    }

    pub fn delete_security_rbac_entry(&mut self, key: &str) {
        self.guard.delete(&security_rbac_key(key));
    }

    pub fn put_security_mtls_entry(&mut self, key: &str, value: &[u8]) {
        self.guard.put(security_mtls_key(key), value.to_vec());
    }

    pub fn delete_security_mtls_entry(&mut self, key: &str) {
        self.guard.delete(&security_mtls_key(key));
    }

    pub fn put_hw_registry_entry(&mut self, key: &str, value: &[u8]) {
        self.guard.put(hw_registry_key(key), value.to_vec());
    }

    pub fn delete_hw_registry_entry(&mut self, key: &str) {
        self.guard.delete(&hw_registry_key(key));
    }

    pub fn set_last_rescan_timestamp(
        &mut self,
        timestamp: Option<u64>,
    ) -> Result<(), WalletStoreError> {
        self.write_meta_timestamp(schema::META_LAST_RESCAN_TS_KEY, timestamp)
    }

    pub fn set_fee_cache_fetched_at(
        &mut self,
        timestamp: Option<u64>,
    ) -> Result<(), WalletStoreError> {
        self.write_meta_timestamp(schema::META_FEE_CACHE_FETCHED_TS_KEY, timestamp)
    }

    pub fn set_fee_cache_expires_at(
        &mut self,
        timestamp: Option<u64>,
    ) -> Result<(), WalletStoreError> {
        self.write_meta_timestamp(schema::META_FEE_CACHE_EXPIRES_TS_KEY, timestamp)
    }

    pub fn put_key_material(
        &mut self,
        label: &str,
        material: &[u8],
    ) -> Result<(), WalletStoreError> {
        let value = codec::encode_key_material(material)?;
        self.guard.put(key_material_key(label), value);
        Ok(())
    }

    pub fn put_address(
        &mut self,
        kind: AddressKind,
        index: u32,
        address: &Address,
    ) -> Result<(), WalletStoreError> {
        let value = codec::encode_address(address)?;
        self.guard.put(address_key(kind, index), value);
        Ok(())
    }

    pub fn put_utxo(&mut self, record: &UtxoRecord<'_>) -> Result<(), WalletStoreError> {
        let value = codec::encode_utxo(record)?;
        self.guard.put(utxo_key(&record.outpoint), value);
        Ok(())
    }

    pub fn delete_utxo(&mut self, outpoint: &UtxoOutpoint) {
        self.guard.delete(&utxo_key(outpoint));
    }

    pub fn put_tx_cache_entry(
        &mut self,
        txid: &[u8; 32],
        entry: &TxCacheEntry<'_>,
    ) -> Result<(), WalletStoreError> {
        let value = codec::encode_tx_cache_entry(entry)?;
        self.guard.put(tx_cache_key(txid), value);
        Ok(())
    }

    pub fn delete_tx_cache_entry(&mut self, txid: &[u8; 32]) {
        self.guard.delete(&tx_cache_key(txid));
    }

    pub fn put_policy_snapshot(
        &mut self,
        label: &str,
        snapshot: &PolicySnapshot,
    ) -> Result<(), WalletStoreError> {
        let value = codec::encode_policy_snapshot(snapshot)?;
        self.guard.put(policy_key(label), value);
        Ok(())
    }

    pub fn delete_policy_snapshot(&mut self, label: &str) {
        self.guard.delete(&policy_key(label));
    }

    pub fn put_checkpoint(&mut self, label: &str, height: u64) -> Result<(), WalletStoreError> {
        let value = codec::encode_checkpoint(height)?;
        self.guard.put(checkpoint_key(label), value);
        Ok(())
    }

    pub fn delete_checkpoint(&mut self, label: &str) {
        self.guard.delete(&checkpoint_key(label));
    }

    pub fn put_pending_lock(&mut self, lock: &PendingLock) -> Result<(), WalletStoreError> {
        let value = codec::encode_pending_lock(lock)?;
        self.guard.put(pending_lock_key(&lock.outpoint), value);
        Ok(())
    }

    pub fn delete_pending_lock(&mut self, outpoint: &UtxoOutpoint) {
        self.guard.delete(&pending_lock_key(outpoint));
    }

    pub fn put_zsi_artifact(
        &mut self,
        artifact: &StoredZsiArtifact<'_>,
    ) -> Result<(), WalletStoreError> {
        let value = codec::encode_zsi_artifact(artifact)?;
        self.guard.put(
            zsi_key(&artifact.identity, &artifact.commitment_digest),
            value,
        );
        Ok(())
    }

    pub fn delete_zsi_artifact(&mut self, identity: &str, commitment_digest: &str) {
        self.guard.delete(&zsi_key(identity, commitment_digest));
    }

    pub fn put_watch_only(&mut self, record: &WatchOnlyRecord) -> Result<(), WalletStoreError> {
        let value = codec::encode_watch_only(record)?;
        self.guard
            .put(watch_only_key(schema::WATCH_ONLY_STATE_KEY), value);
        Ok(())
    }

    pub fn clear_watch_only(&mut self) {
        self.guard
            .delete(&watch_only_key(schema::WATCH_ONLY_STATE_KEY));
    }

    pub fn commit(self) -> Result<Hash, WalletStoreError> {
        Ok(self.guard.commit()?)
    }

    fn write_meta_timestamp(
        &mut self,
        key: &str,
        timestamp: Option<u64>,
    ) -> Result<(), WalletStoreError> {
        match timestamp {
            Some(value) => {
                let encoded = codec::encode_checkpoint(value)?;
                self.guard.put(meta_key(key), encoded);
            }
            None => self.delete_meta(key),
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WalletStoreError {
    #[error("storage error: {0}")]
    Storage(#[from] KvError),
    #[error("serialization error: {0}")]
    Codec(#[from] CodecError),
    #[error("synchronisation primitive poisoned")]
    Poisoned,
    #[error("stored schema version {stored} exceeds supported {supported}")]
    UnsupportedSchema { stored: u32, supported: u32 },
    #[error("corrupt key encoding: {0}")]
    CorruptKey(String),
}

fn initialise_schema(kv: &mut FirewoodKv) -> Result<(), WalletStoreError> {
    let stored = kv.get(schema::SCHEMA_VERSION_KEY);
    let supported = schema::SCHEMA_VERSION_LATEST;
    let mut version = match stored {
        Some(bytes) => codec::decode_schema_version(&bytes)?,
        None => 0,
    };

    if version > supported {
        return Err(WalletStoreError::UnsupportedSchema {
            stored: version,
            supported,
        });
    }

    let mut mutated = false;

    if version < schema::SCHEMA_VERSION_V2 {
        mutated |= migrations::v2::apply(kv)?;
        version = schema::SCHEMA_VERSION_V2;
    }

    if version < schema::SCHEMA_VERSION_V3 {
        mutated |= migrations::v3::apply(kv)?;
        version = schema::SCHEMA_VERSION_V3;
    }

    if stored.is_none() || version != supported {
        kv.put(
            schema::SCHEMA_VERSION_KEY.to_vec(),
            codec::encode_schema_version(supported)?,
        );
        mutated = true;
    }

    if mutated {
        let _ = kv.commit()?;
    }
    Ok(())
}

fn open_extension(kv: &FirewoodKv, name: &str) -> Result<ColumnFamily, WalletStoreError> {
    ColumnFamily::open(kv.base_dir(), name)
        .map_err(|err| WalletStoreError::Storage(KvError::Io(err)))
}

fn meta_key(key: &str) -> Vec<u8> {
    namespaced(schema::META_NAMESPACE, key.as_bytes())
}

fn key_material_key(label: &str) -> Vec<u8> {
    namespaced(schema::KEYS_NAMESPACE, label.as_bytes())
}

fn backup_meta_key(key: &str) -> Vec<u8> {
    namespaced(schema::BACKUP_META_NAMESPACE, key.as_bytes())
}

fn address_key(kind: AddressKind, index: u32) -> Vec<u8> {
    let mut key = kind.namespace().to_vec();
    key.extend_from_slice(&index.to_be_bytes());
    key
}

fn utxo_key(outpoint: &UtxoOutpoint) -> Vec<u8> {
    let mut key = schema::UTXOS_NAMESPACE.to_vec();
    key.extend_from_slice(&outpoint.txid);
    key.extend_from_slice(&outpoint.index.to_be_bytes());
    key
}

fn tx_cache_key(txid: &[u8; 32]) -> Vec<u8> {
    let mut key = schema::TX_CACHE_NAMESPACE.to_vec();
    key.extend_from_slice(txid);
    key
}

fn policy_key(label: &str) -> Vec<u8> {
    namespaced(schema::POLICIES_NAMESPACE, label.as_bytes())
}

fn checkpoint_key(label: &str) -> Vec<u8> {
    namespaced(schema::CHECKPOINTS_NAMESPACE, label.as_bytes())
}

fn pending_lock_key(outpoint: &UtxoOutpoint) -> Vec<u8> {
    let mut key = schema::PENDING_LOCKS_NAMESPACE.to_vec();
    key.extend_from_slice(&outpoint.txid);
    key.extend_from_slice(&outpoint.index.to_be_bytes());
    key
}

fn watch_only_key(label: &str) -> Vec<u8> {
    namespaced(schema::WATCH_ONLY_NAMESPACE, label.as_bytes())
}

fn multisig_scope_key(label: &str) -> Vec<u8> {
    namespaced(schema::MULTISIG_SCOPE_NAMESPACE, label.as_bytes())
}

fn security_rbac_key(label: &str) -> Vec<u8> {
    namespaced(schema::SECURITY_RBAC_NAMESPACE, label.as_bytes())
}

fn security_mtls_key(label: &str) -> Vec<u8> {
    namespaced(schema::SECURITY_MTLS_NAMESPACE, label.as_bytes())
}

fn hw_registry_key(label: &str) -> Vec<u8> {
    namespaced(schema::HW_REGISTRY_NAMESPACE, label.as_bytes())
}

fn namespaced(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(suffix);
    key
}

fn zsi_key(identity: &str, commitment_digest: &str) -> Vec<u8> {
    let mut key = schema::ZSI_NAMESPACE.to_vec();
    let identity_bytes = identity.as_bytes();
    let identity_len =
        u32::try_from(identity_bytes.len()).expect("identity label exceeds u32::MAX bytes");
    key.extend_from_slice(&identity_len.to_be_bytes());
    key.extend_from_slice(identity_bytes);
    key.extend_from_slice(commitment_digest.as_bytes());
    key
}

fn parse_u32_suffix(bytes: &[u8]) -> Result<u32, WalletStoreError> {
    if bytes.len() != 4 {
        return Err(WalletStoreError::CorruptKey(format!(
            "expected 4-byte index suffix, got {} bytes",
            bytes.len()
        )));
    }
    let mut array = [0u8; 4];
    array.copy_from_slice(bytes);
    Ok(u32::from_be_bytes(array))
}

fn parse_txid(bytes: &[u8]) -> Result<[u8; 32], WalletStoreError> {
    if bytes.len() != 32 {
        return Err(WalletStoreError::CorruptKey(format!(
            "expected 32-byte txid suffix, got {} bytes",
            bytes.len()
        )));
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(bytes);
    Ok(txid)
}
