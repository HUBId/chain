use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use std::convert::TryInto;

use crate::db::{
    AddressKind, AddressMetadata, PendingLock, PendingLockMetadata, UtxoOutpoint, WalletStore,
    WalletStoreError,
};
use crate::proof_backend::Blake2sHasher;

use super::DerivationPath;

const META_EXTERNAL_CURSOR: &str = "addr_external_cursor";
const META_INTERNAL_CURSOR: &str = "addr_internal_cursor";
const META_EXTERNAL_UNUSED: &str = "addr_external_unused";
const META_INTERNAL_UNUSED: &str = "addr_internal_unused";
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedAddress {
    pub address: String,
    pub path: DerivationPath,
}

#[derive(Debug, thiserror::Error)]
pub enum AddressError {
    #[error("store error: {0}")]
    Store(#[from] WalletStoreError),
    #[error("gap limit reached for {kind:?}")]
    GapLimit { kind: AddressKind, gap_limit: u32 },
    #[error("key derivation failed: {0}")]
    Key(String),
}

pub struct AddressManager {
    store: Arc<WalletStore>,
    root_seed: [u8; 32],
    external_gap_limit: u32,
    internal_gap_limit: u32,
}

impl AddressManager {
    pub fn new(
        store: Arc<WalletStore>,
        root_seed: [u8; 32],
        external_gap_limit: u32,
        internal_gap_limit: u32,
    ) -> Result<Self, AddressError> {
        Ok(Self {
            store,
            root_seed,
            external_gap_limit,
            internal_gap_limit,
        })
    }

    pub fn fingerprint(&self) -> String {
        let digest: [u8; 32] = Blake2sHasher::hash(&self.root_seed).into();
        hex::encode(digest)
    }

    pub fn next_external_address(&self) -> Result<DerivedAddress, AddressError> {
        self.next_address(AddressKind::External)
    }

    pub fn next_internal_address(&self) -> Result<DerivedAddress, AddressError> {
        self.next_address(AddressKind::Internal)
    }

    pub fn mark_address_used(
        &self,
        kind: AddressKind,
        index: u32,
        first_seen_height: Option<u64>,
    ) -> Result<(), AddressError> {
        let mut metadata = self
            .store
            .get_address_metadata(kind, index)?
            .unwrap_or_default();
        metadata.used = true;
        if let Some(height) = first_seen_height {
            metadata.first_seen_height = match metadata.first_seen_height {
                Some(current) => Some(current.min(height)),
                None => Some(height),
            };
        }

        let mut batch = self.store.batch()?;
        let key = match kind {
            AddressKind::External => META_EXTERNAL_UNUSED,
            AddressKind::Internal => META_INTERNAL_UNUSED,
        };
        let unused = self.load_counter(key)?;
        let updated = unused.saturating_sub(1);
        batch.put_meta(key, &updated.to_be_bytes());
        batch.put_address_metadata(kind, index, &metadata)?;
        batch.commit()?;
        Ok(())
    }

    pub fn is_outpoint_pending(&self, outpoint: &UtxoOutpoint) -> bool {
        self.store
            .get_pending_lock(outpoint)
            .map(|value| value.is_some())
            .unwrap_or(false)
    }

    pub fn pending_locks(&self) -> Result<Vec<PendingLock>, AddressError> {
        Ok(self.store.iter_pending_locks()?)
    }

    pub fn lock_inputs<'a, I>(
        &self,
        inputs: I,
        spending_txid: Option<[u8; 32]>,
        locked_at_ms: u64,
        metadata: Option<PendingLockMetadata>,
    ) -> Result<Vec<PendingLock>, AddressError>
    where
        I: IntoIterator<Item = &'a UtxoOutpoint>,
    {
        let inputs: Vec<UtxoOutpoint> = inputs.into_iter().cloned().collect();
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        let mut batch = self.store.batch()?;
        let mut locks = Vec::with_capacity(inputs.len());
        for outpoint in &inputs {
            let mut lock = PendingLock::new(outpoint.clone(), locked_at_ms, spending_txid);
            if let Some(metadata) = metadata.as_ref() {
                lock.metadata = metadata.clone();
            }
            batch.put_pending_lock(&lock)?;
            locks.push(lock);
        }
        batch.commit()?;
        Ok(locks)
    }

    pub fn attach_lock_txid<'a, I>(
        &self,
        inputs: I,
        spending_txid: [u8; 32],
        metadata: Option<PendingLockMetadata>,
    ) -> Result<Vec<PendingLock>, AddressError>
    where
        I: IntoIterator<Item = &'a UtxoOutpoint>,
    {
        let inputs: Vec<UtxoOutpoint> = inputs.into_iter().cloned().collect();
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        let mut updated = Vec::new();
        for outpoint in &inputs {
            if let Some(mut lock) = self.store.get_pending_lock(outpoint)? {
                lock.spending_txid = Some(spending_txid);
                if let Some(metadata) = metadata.as_ref() {
                    lock.metadata = metadata.clone();
                }
                updated.push(lock);
            }
        }
        if updated.is_empty() {
            return Ok(updated);
        }
        let mut batch = self.store.batch()?;
        for lock in &updated {
            batch.put_pending_lock(lock)?;
        }
        batch.commit()?;
        Ok(updated)
    }

    pub fn release_inputs<'a, I>(&self, inputs: I) -> Result<Vec<PendingLock>, AddressError>
    where
        I: IntoIterator<Item = &'a UtxoOutpoint>,
    {
        let inputs: Vec<UtxoOutpoint> = inputs.into_iter().cloned().collect();
        if inputs.is_empty() {
            return Ok(Vec::new());
        }
        let mut released = Vec::new();
        for outpoint in &inputs {
            if let Some(lock) = self.store.get_pending_lock(outpoint)? {
                released.push(lock);
            }
        }
        if released.is_empty() {
            return Ok(released);
        }
        self.delete_prover_meta(&released)?;
        let mut batch = self.store.batch()?;
        for lock in &released {
            batch.delete_pending_lock(&lock.outpoint);
        }
        batch.commit()?;
        Ok(released)
    }

    pub fn release_by_txid(
        &self,
        spending_txid: &[u8; 32],
    ) -> Result<Vec<PendingLock>, AddressError> {
        let locks = self.store.iter_pending_locks()?;
        let released: Vec<PendingLock> = locks
            .into_iter()
            .filter(|lock| lock.spending_txid.as_ref() == Some(spending_txid))
            .collect();
        if released.is_empty() {
            return Ok(released);
        }
        self.delete_prover_meta(&released)?;
        let mut batch = self.store.batch()?;
        for lock in &released {
            batch.delete_pending_lock(&lock.outpoint);
        }
        batch.commit()?;
        Ok(released)
    }

    pub fn release_expired_locks(
        &self,
        now_ms: u64,
        timeout_secs: u64,
    ) -> Result<Vec<PendingLock>, AddressError> {
        if timeout_secs == 0 {
            return Ok(Vec::new());
        }
        let locks = self.store.iter_pending_locks()?;
        let timeout_ms = timeout_secs.saturating_mul(1000);
        let expired: Vec<PendingLock> = locks
            .into_iter()
            .filter(|lock| now_ms.saturating_sub(lock.locked_at_ms) >= timeout_ms)
            .collect();
        if expired.is_empty() {
            return Ok(expired);
        }
        self.delete_prover_meta(&expired)?;
        let mut batch = self.store.batch()?;
        for lock in &expired {
            batch.delete_pending_lock(&lock.outpoint);
        }
        batch.commit()?;
        Ok(expired)
    }

    fn delete_prover_meta(&self, locks: &[PendingLock]) -> Result<(), AddressError> {
        let mut txids: Vec<[u8; 32]> = locks.iter().filter_map(|lock| lock.spending_txid).collect();
        txids.sort_unstable();
        txids.dedup();
        for txid in txids {
            self.store.delete_prover_meta(&txid)?;
        }
        Ok(())
    }

    fn next_address(&self, kind: AddressKind) -> Result<DerivedAddress, AddressError> {
        let (cursor_key, unused_key, gap_limit) = match kind {
            AddressKind::External => (
                META_EXTERNAL_CURSOR,
                META_EXTERNAL_UNUSED,
                self.external_gap_limit,
            ),
            AddressKind::Internal => (
                META_INTERNAL_CURSOR,
                META_INTERNAL_UNUSED,
                self.internal_gap_limit,
            ),
        };
        let cursor = self.load_counter(cursor_key)?;
        let unused = self.load_counter(unused_key)?;
        if gap_limit > 0 && unused >= gap_limit {
            return Err(AddressError::GapLimit { kind, gap_limit });
        }
        let path = DerivationPath::new(0, matches!(kind, AddressKind::Internal), cursor);
        let address = self.derive_address(&path)?;
        let mut batch = self.store.batch()?;
        batch.put_address(kind, cursor, &address)?;
        batch.put_address_metadata(kind, cursor, &AddressMetadata::default())?;
        batch.put_meta(cursor_key, &(cursor + 1).to_be_bytes());
        batch.put_meta(unused_key, &(unused + 1).to_be_bytes());
        batch.commit()?;
        Ok(DerivedAddress { address, path })
    }

    fn derive_address(&self, path: &DerivationPath) -> Result<String, AddressError> {
        let mut material = Vec::with_capacity(32 + 12);
        material.extend_from_slice(&self.root_seed);
        material.extend_from_slice(&path.account.to_be_bytes());
        material.extend_from_slice(&(path.change as u32).to_be_bytes());
        material.extend_from_slice(&path.index.to_be_bytes());
        let seed: [u8; 32] = Blake2sHasher::hash(&material).into();
        let signing_key =
            SigningKey::from_bytes(&seed).map_err(|err| AddressError::Key(err.to_string()))?;
        let verifying_key = VerifyingKey::from(&signing_key);
        let hash: [u8; 32] = Blake2sHasher::hash(verifying_key.as_bytes()).into();
        Ok(hex::encode(hash))
    }

    fn load_counter(&self, key: &str) -> Result<u32, AddressError> {
        let bytes = self.store.get_meta(key)?;
        if let Some(bytes) = bytes {
            let array: [u8; 4] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| AddressError::Key(format!("invalid counter encoding for {key}")))?;
            Ok(u32::from_be_bytes(array))
        } else {
            Ok(0)
        }
    }
}
