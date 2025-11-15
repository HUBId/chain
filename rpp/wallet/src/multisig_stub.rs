use crate::db::{WalletStore, WalletStoreBatch};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MultisigScope;

impl MultisigScope {
    pub fn requires_collaboration(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Cosigner {
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub endpoint: Option<String>,
}

impl Cosigner {
    pub fn new(
        _fingerprint: impl Into<String>,
        _endpoint: Option<impl Into<String>>,
    ) -> Result<Self, CosignerRegistryError> {
        Err(CosignerRegistryError::Disabled)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CosignerRegistry {
    #[serde(default)]
    entries: Vec<Cosigner>,
}

impl CosignerRegistry {
    pub fn new(_entries: Vec<Cosigner>) -> Result<Self, CosignerRegistryError> {
        Err(CosignerRegistryError::Disabled)
    }

    pub fn entries(&self) -> &[Cosigner] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn to_vec(&self) -> Vec<Cosigner> {
        self.entries.clone()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CosignerRegistryError {
    #[error("wallet multisig support disabled at build time")]
    Disabled,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct MultisigDraftMetadata {
    pub scope: MultisigScope,
    #[serde(default)]
    pub cosigners: Vec<Cosigner>,
}

impl MultisigDraftMetadata {
    pub fn requires_collaboration(&self) -> bool {
        false
    }
}

#[derive(Debug, Error)]
pub enum MultisigStorageError {
    #[error("wallet multisig support disabled at build time")]
    Disabled,
}

#[derive(Debug, Error)]
pub enum MultisigError {
    #[error("wallet multisig support disabled at build time")]
    Disabled,
}

pub fn load_scope(_store: &WalletStore) -> Result<Option<MultisigScope>, MultisigStorageError> {
    Err(MultisigStorageError::Disabled)
}

pub fn load_cosigner_registry(
    _store: &WalletStore,
) -> Result<Option<CosignerRegistry>, MultisigStorageError> {
    Err(MultisigStorageError::Disabled)
}

pub fn store_scope(
    _batch: &mut WalletStoreBatch<'_>,
    _scope: &MultisigScope,
) -> Result<(), MultisigStorageError> {
    Err(MultisigStorageError::Disabled)
}

pub fn clear_scope(_batch: &mut WalletStoreBatch<'_>) {}

pub fn store_cosigner_registry(
    _batch: &mut WalletStoreBatch<'_>,
    _registry: &CosignerRegistry,
) -> Result<(), MultisigStorageError> {
    Err(MultisigStorageError::Disabled)
}

pub fn clear_cosigner_registry(_batch: &mut WalletStoreBatch<'_>) {}
