mod cosigner_registry;
mod scopes;

pub use cosigner_registry::{Cosigner, CosignerRegistry, CosignerRegistryError};
pub use scopes::{MultisigScope, MultisigScopeError};

use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

use crate::db::{codec::CodecError, WalletStore, WalletStoreBatch, WalletStoreError};

pub const MULTISIG_SCOPE_KEY: &str = "multisig_scope";
pub const COSIGNER_REGISTRY_KEY: &str = "multisig_cosigners";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigDraftMetadata {
    pub scope: MultisigScope,
    pub cosigners: Vec<Cosigner>,
}

impl MultisigDraftMetadata {
    pub fn requires_collaboration(&self) -> bool {
        self.scope.requires_collaboration()
    }
}

#[derive(Debug, Error)]
pub enum MultisigStorageError {
    #[error("wallet store error: {0}")]
    Store(#[from] WalletStoreError),
    #[error("serialization error: {0}")]
    Codec(#[from] CodecError),
}

#[derive(Debug, Error)]
pub enum MultisigError {
    #[error("storage error: {0}")]
    Storage(#[from] MultisigStorageError),
    #[error("invalid scope: {0}")]
    Scope(#[from] MultisigScopeError),
    #[error("invalid cosigner registry: {0}")]
    Registry(#[from] CosignerRegistryError),
    #[error("multisig scope requires at least one cosigner entry")]
    MissingCosigners,
}

pub fn load_scope(store: &WalletStore) -> Result<Option<MultisigScope>, MultisigStorageError> {
    load_entry(store, MULTISIG_SCOPE_KEY)
}

pub fn load_cosigner_registry(
    store: &WalletStore,
) -> Result<Option<CosignerRegistry>, MultisigStorageError> {
    load_entry(store, COSIGNER_REGISTRY_KEY)
}

pub fn store_scope(
    batch: &mut WalletStoreBatch<'_>,
    scope: &MultisigScope,
) -> Result<(), MultisigStorageError> {
    store_entry(batch, MULTISIG_SCOPE_KEY, scope)
}

pub fn clear_scope(batch: &mut WalletStoreBatch<'_>) {
    batch.delete_meta(MULTISIG_SCOPE_KEY);
}

pub fn store_cosigner_registry(
    batch: &mut WalletStoreBatch<'_>,
    registry: &CosignerRegistry,
) -> Result<(), MultisigStorageError> {
    store_entry(batch, COSIGNER_REGISTRY_KEY, registry)
}

pub fn clear_cosigner_registry(batch: &mut WalletStoreBatch<'_>) {
    batch.delete_meta(COSIGNER_REGISTRY_KEY);
}

fn store_entry<T: Serialize>(
    batch: &mut WalletStoreBatch<'_>,
    key: &str,
    value: &T,
) -> Result<(), MultisigStorageError> {
    let encoded = encode(value)?;
    batch.put_meta(key, &encoded);
    Ok(())
}

fn load_entry<T>(store: &WalletStore, key: &str) -> Result<Option<T>, MultisigStorageError>
where
    T: DeserializeOwned,
{
    let Some(bytes) = store.get_meta(key)? else {
        return Ok(None);
    };
    let value = decode::<T>(&bytes)?;
    Ok(Some(value))
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, MultisigStorageError> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .serialize(value)
        .map_err(|err| MultisigStorageError::Codec(CodecError::Serialization(err)))
}

fn decode<'a, T>(bytes: &'a [u8]) -> Result<T, MultisigStorageError>
where
    T: DeserializeOwned,
{
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .deserialize(bytes)
        .map_err(|err| MultisigStorageError::Codec(CodecError::Serialization(err)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn scope_roundtrip_serialization() {
        let dir = tempdir().expect("tempdir");
        let store = WalletStore::open(dir.path()).expect("open store");
        let mut batch = store.batch().expect("batch");
        let scope = MultisigScope::new(2, 3).expect("scope");
        store_scope(&mut batch, &scope).expect("store scope");
        batch.commit().expect("commit");

        let loaded = load_scope(&store).expect("load").expect("present");
        assert_eq!(loaded, scope);
    }

    #[test]
    fn registry_roundtrip_serialization() {
        let dir = tempdir().expect("tempdir");
        let store = WalletStore::open(dir.path()).expect("open store");
        let mut batch = store.batch().expect("batch");
        let registry = CosignerRegistry::new(vec![Cosigner::new(
            "aa11bb22cc33dd44ee55ff66aa77bb88",
            Some("https://a"),
        )
        .expect("cosigner")])
        .expect("registry");
        store_cosigner_registry(&mut batch, &registry).expect("store registry");
        batch.commit().expect("commit");

        let loaded = load_cosigner_registry(&store)
            .expect("load")
            .expect("present");
        assert_eq!(loaded, registry);
    }
}
