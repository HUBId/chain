use std::sync::Arc;

use std::convert::TryInto;
use ed25519_dalek::{PublicKey, SecretKey};

use crate::db::{AddressKind, UtxoOutpoint, WalletStore, WalletStoreError};
use crate::proof_backend::Blake2sHasher;

use super::DerivationPath;

const META_EXTERNAL_CURSOR: &str = "addr_external_cursor";
const META_INTERNAL_CURSOR: &str = "addr_internal_cursor";
const META_EXTERNAL_UNUSED: &str = "addr_external_unused";
const META_INTERNAL_UNUSED: &str = "addr_internal_unused";
const META_PENDING_PREFIX: &str = "pending_utxo/";

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

    pub fn mark_address_used(&self, kind: AddressKind, _index: u32) -> Result<(), AddressError> {
        let mut batch = self.store.batch()?;
        let key = match kind {
            AddressKind::External => META_EXTERNAL_UNUSED,
            AddressKind::Internal => META_INTERNAL_UNUSED,
        };
        let unused = self.load_counter(key)?;
        let updated = unused.saturating_sub(1);
        batch.put_meta(key, &updated.to_be_bytes());
        batch.commit()?;
        Ok(())
    }

    pub fn is_outpoint_pending(&self, outpoint: &UtxoOutpoint) -> bool {
        let key = pending_key(outpoint);
        self.store
            .get_meta(&key)
            .map(|value| value.is_some())
            .unwrap_or(false)
    }

    pub fn mark_inputs_pending<'a, I>(&self, inputs: I) -> Result<(), AddressError>
    where
        I: IntoIterator<Item = &'a UtxoOutpoint>,
    {
        let mut batch = self.store.batch()?;
        for outpoint in inputs {
            let key = pending_key(outpoint);
            batch.put_meta(&key, &[1]);
        }
        batch.commit()?;
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
            return Err(AddressError::GapLimit {
                kind,
                gap_limit,
            });
        }
        let path = DerivationPath::new(0, matches!(kind, AddressKind::Internal), cursor);
        let address = self.derive_address(&path)?;
        let mut batch = self.store.batch()?;
        batch.put_address(kind, cursor, &address)?;
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
        let secret = SecretKey::from_bytes(&seed)
            .map_err(|err| AddressError::Key(err.to_string()))?;
        let public = PublicKey::from(&secret);
        let hash: [u8; 32] = Blake2sHasher::hash(public.as_bytes()).into();
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

fn pending_key(outpoint: &UtxoOutpoint) -> String {
    format!(
        "{META_PENDING_PREFIX}{}:{}",
        hex::encode(outpoint.txid),
        outpoint.index
    )
}

