use crate::db::{WalletStore, WalletStoreBatch, WalletStoreError};

use super::{
    clear_cosigner_registry, clear_scope, load_cosigner_registry, load_scope,
    store_cosigner_registry, store_scope, MultisigDraftMetadata, MultisigError, MultisigScope,
};

/// High-level helper that persists multisig policy, cosigners, and exports.
#[derive(Debug)]
pub struct MultisigCoordinator<'store> {
    store: &'store WalletStore,
}

impl<'store> MultisigCoordinator<'store> {
    pub fn new(store: &'store WalletStore) -> Self {
        Self { store }
    }

    /// Fetch the configured multisig scope, if any.
    pub fn scope(&self) -> Result<Option<MultisigScope>, MultisigError> {
        load_scope(self.store).map_err(MultisigError::from)
    }

    /// Persist or clear the multisig scope, returning the previous value.
    pub fn set_scope(
        &self,
        scope: Option<MultisigScope>,
    ) -> Result<Option<MultisigScope>, MultisigError> {
        let mut batch = self.batch()?;
        let previous = self.scope()?;
        match scope.as_ref() {
            Some(scope) => store_scope(&mut batch, scope)?,
            None => clear_scope(&mut batch),
        }
        batch.commit()?;
        Ok(previous)
    }

    /// Fetch the registered cosigners, if any.
    pub fn cosigners(&self) -> Result<Option<crate::multisig::CosignerRegistry>, MultisigError> {
        load_cosigner_registry(self.store).map_err(MultisigError::from)
    }

    /// Persist or clear the cosigner registry, returning the previous value.
    pub fn set_cosigners(
        &self,
        registry: Option<crate::multisig::CosignerRegistry>,
    ) -> Result<Option<crate::multisig::CosignerRegistry>, MultisigError> {
        let mut batch = self.batch()?;
        let previous = self.cosigners()?;
        match registry.as_ref() {
            Some(registry) => store_cosigner_registry(&mut batch, registry)?,
            None => clear_cosigner_registry(&mut batch),
        }
        batch.commit()?;
        Ok(previous)
    }

    /// Persist draft metadata for coordinator handoff, replacing any prior entry for the draft.
    pub fn export_metadata(
        &self,
        draft_id: &str,
        metadata: Option<MultisigDraftMetadata>,
    ) -> Result<MultisigMetadataExport, MultisigError> {
        let mut batch = self.batch()?;
        match metadata.as_ref() {
            Some(metadata) => store_export(&mut batch, draft_id, metadata)?,
            None => clear_export(&mut batch, draft_id),
        }
        batch.commit()?;
        Ok(MultisigMetadataExport {
            draft_id: draft_id.to_string(),
            metadata,
        })
    }

    /// Load the last export persisted for a draft, if any.
    pub fn load_export(
        &self,
        draft_id: &str,
    ) -> Result<Option<MultisigDraftMetadata>, MultisigError> {
        load_export(self.store, draft_id).map_err(MultisigError::from)
    }

    /// List persisted exports for auditability.
    pub fn list_exports(&self) -> Result<Vec<MultisigMetadataExport>, MultisigError> {
        list_exports(self.store)
            .map(|entries| {
                entries
                    .into_iter()
                    .map(|(draft_id, metadata)| MultisigMetadataExport { draft_id, metadata })
                    .collect()
            })
            .map_err(MultisigError::from)
    }

    fn batch(&self) -> Result<WalletStoreBatch<'_>, MultisigError> {
        self.store
            .batch()
            .map_err(WalletStoreError::from)
            .map_err(MultisigError::from)
    }
}

/// Export entry persisted for coordinator consumption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultisigMetadataExport {
    pub draft_id: String,
    pub metadata: Option<MultisigDraftMetadata>,
}

pub fn store_export(
    batch: &mut WalletStoreBatch<'_>,
    draft_id: &str,
    metadata: &MultisigDraftMetadata,
) -> Result<(), MultisigError> {
    let encoded = super::encode(metadata)?;
    batch.put_multisig_scope_entry(draft_id, &encoded);
    Ok(())
}

pub fn load_export(
    store: &WalletStore,
    draft_id: &str,
) -> Result<Option<MultisigDraftMetadata>, MultisigError> {
    let Some(bytes) = store.get_multisig_scope_entry(draft_id)? else {
        return Ok(None);
    };
    super::decode(&bytes).map(Some).map_err(MultisigError::from)
}

pub fn list_exports(
    store: &WalletStore,
) -> Result<Vec<(String, MultisigDraftMetadata)>, MultisigError> {
    store
        .iter_multisig_scope()?
        .into_iter()
        .map(|(label, bytes)| super::decode(&bytes).map(|metadata| (label, metadata)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(MultisigError::from)
}

pub fn clear_export(batch: &mut WalletStoreBatch<'_>, draft_id: &str) {
    batch.delete_multisig_scope_entry(draft_id);
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::multisig::Cosigner;

    fn coordinator() -> (MultisigCoordinator<'static>, tempfile::TempDir) {
        let dir = tempdir().expect("tempdir");
        let store = Box::leak(Box::new(WalletStore::open(dir.path()).expect("store")));
        (MultisigCoordinator::new(store), dir)
    }

    #[test]
    fn coordinator_sets_scope_and_registry() {
        let (coordinator, _dir) = coordinator();

        let scope = MultisigScope::new(2, 3).expect("scope");
        let cosigner = Cosigner::new("aa11bb22cc33dd44ee55ff66aa77bb88", None).expect("cosigner");
        let registry = crate::multisig::CosignerRegistry::new(vec![cosigner]).expect("registry");

        assert!(coordinator.scope().expect("scope read").is_none());
        assert!(coordinator.cosigners().expect("registry read").is_none());

        coordinator
            .set_scope(Some(scope.clone()))
            .expect("persist scope");
        coordinator
            .set_cosigners(Some(registry.clone()))
            .expect("persist registry");

        assert_eq!(coordinator.scope().expect("scope read"), Some(scope));
        assert_eq!(
            coordinator.cosigners().expect("registry read"),
            Some(registry)
        );
    }

    #[test]
    fn coordinator_exports_metadata() {
        let (coordinator, _dir) = coordinator();
        let scope = MultisigScope::new(1, 2).expect("scope");
        let cosigner = Cosigner::new("aa11bb22cc33dd44ee55ff66aa77bb88", None).expect("cosigner");
        let metadata = MultisigDraftMetadata {
            scope,
            cosigners: vec![cosigner],
        };

        let export = coordinator
            .export_metadata("draft-1", Some(metadata.clone()))
            .expect("export");
        assert_eq!(export.draft_id, "draft-1");
        assert_eq!(export.metadata, Some(metadata.clone()));

        let loaded = coordinator
            .load_export("draft-1")
            .expect("load export")
            .expect("present");
        assert_eq!(loaded, metadata);

        let entries = coordinator.list_exports().expect("list exports");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].draft_id, "draft-1");
        assert_eq!(entries[0].metadata, Some(metadata));
    }
}
