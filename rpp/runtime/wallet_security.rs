use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::{ChainError, ChainResult};
use rpp_wallet_interface::runtime_config::WalletIdentityError;
pub use rpp_wallet_interface::runtime_config::{
    WalletIdentity, WalletRole, WalletRoleSet, WalletSecurityBinding,
};

fn wallet_identity_error(err: WalletIdentityError) -> ChainError {
    ChainError::Config(err.to_string())
}

fn hex_digest(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// RBAC assignments persisted on disk.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct WalletRbacAssignments {
    entries: BTreeMap<WalletIdentity, WalletRoleSet>,
}

/// Persistent RBAC store backed by a JSON document.
#[derive(Debug)]
pub struct WalletRbacStore {
    path: PathBuf,
    assignments: RwLock<WalletRbacAssignments>,
}

impl WalletRbacStore {
    /// Construct an in-memory store with no assignments.
    pub fn empty() -> Self {
        Self {
            path: PathBuf::new(),
            assignments: RwLock::new(WalletRbacAssignments::default()),
        }
    }

    /// Load assignments from the provided path, creating parent directories if necessary.
    pub fn load(path: impl AsRef<Path>) -> ChainResult<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let assignments = if path.exists() {
            let data = fs::read(&path)?;
            if data.is_empty() {
                WalletRbacAssignments::default()
            } else {
                serde_json::from_slice::<WalletRbacAssignments>(&data).map_err(|err| {
                    ChainError::Config(format!(
                        "unable to parse wallet RBAC store {}: {err}",
                        path.display()
                    ))
                })?
            }
        } else {
            WalletRbacAssignments::default()
        };
        Ok(Self {
            path,
            assignments: RwLock::new(assignments),
        })
    }

    /// Persist the RBAC assignments to disk.
    pub fn save(&self) -> ChainResult<()> {
        let assignments = self.assignments.read();
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let encoded = serde_json::to_vec_pretty(&*assignments).map_err(|err| {
            ChainError::Config(format!(
                "unable to encode wallet RBAC store {}: {err}",
                self.path.display()
            ))
        })?;
        fs::write(&self.path, encoded)?;
        Ok(())
    }

    /// Snapshot the current assignments.
    pub fn snapshot(&self) -> BTreeMap<WalletIdentity, WalletRoleSet> {
        self.assignments.read().entries.clone()
    }

    /// Resolve the roles associated with an identity.
    pub fn roles_for(&self, identity: &WalletIdentity) -> WalletRoleSet {
        self.assignments
            .read()
            .entries
            .get(identity)
            .cloned()
            .unwrap_or_default()
    }

    /// Persist the provided bindings into the RBAC store, replacing any
    /// existing roles associated with the identity.
    pub fn apply_bindings(&self, bindings: &[WalletSecurityBinding]) {
        let mut assignments = self.assignments.write();
        for binding in bindings {
            if binding.roles.is_empty() {
                assignments.entries.remove(&binding.identity);
            } else {
                assignments
                    .entries
                    .insert(binding.identity.clone(), binding.roles.clone());
            }
        }
    }
}

/// Filesystem locations used by the wallet security subsystem.
#[derive(Clone, Debug)]
pub struct WalletSecurityPaths {
    root: PathBuf,
}

impl WalletSecurityPaths {
    /// Construct a new helper rooted at the provided directory.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Derive the standard security directory from the wallet data directory.
    pub fn from_data_dir(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("wallet").join("security"),
        }
    }

    /// Ensure the security directory exists on disk.
    pub fn ensure(&self) -> ChainResult<()> {
        fs::create_dir_all(&self.root)?;
        Ok(())
    }

    /// Root directory for security artefacts.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Path to the RBAC store file.
    pub fn rbac_store(&self) -> PathBuf {
        self.root.join("rbac")
    }
}

/// Runtime object used to resolve identities into roles.
#[derive(Debug)]
pub struct WalletSecurityContext {
    store: WalletRbacStore,
}

impl WalletSecurityContext {
    /// Construct an empty context with no assignments.
    pub fn empty() -> Self {
        Self {
            store: WalletRbacStore::empty(),
        }
    }

    /// Load the RBAC store from disk.
    pub fn load_from_store(path: impl AsRef<Path>) -> ChainResult<Self> {
        Ok(Self {
            store: WalletRbacStore::load(path)?,
        })
    }

    /// Construct a context from an already loaded store.
    pub fn from_store(store: WalletRbacStore) -> Self {
        Self { store }
    }

    /// Resolve roles for the provided identities.
    pub fn resolve_roles(&self, identities: &[WalletIdentity]) -> WalletRoleSet {
        let mut roles = WalletRoleSet::new();
        for identity in identities {
            roles.extend(self.store.roles_for(identity));
        }
        roles
    }

    /// Convenience helper for resolving roles from a bearer token.
    pub fn resolve_bearer_roles(&self, token: &str) -> WalletRoleSet {
        self.resolve_roles(&[WalletIdentity::from_bearer_token(token)])
    }

    /// Convenience helper for resolving roles from a certificate fingerprint.
    pub fn resolve_certificate_roles(&self, fingerprint: &str) -> ChainResult<WalletRoleSet> {
        let identity = WalletIdentity::from_certificate_fingerprint(fingerprint)
            .map_err(wallet_identity_error)?;
        Ok(self.resolve_roles(&[identity]))
    }

    /// Access the underlying RBAC store snapshot.
    pub fn snapshot(&self) -> BTreeMap<WalletIdentity, WalletRoleSet> {
        self.store.snapshot()
    }
}

/// Client certificate fingerprints extracted during TLS handshakes.
#[derive(Clone, Debug, Default)]
pub struct WalletClientCertificates {
    fingerprints: Vec<String>,
}

impl WalletClientCertificates {
    /// Construct an empty certificate collection.
    pub fn empty() -> Self {
        Self {
            fingerprints: Vec::new(),
        }
    }

    /// Build the collection from DER-encoded certificates.
    pub fn from_der<'a, I>(certs: I) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let fingerprints = certs.into_iter().map(hex_digest).collect();
        Self { fingerprints }
    }

    /// Returns true when no certificates were presented.
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// Access the underlying fingerprint set.
    pub fn fingerprints(&self) -> &[String] {
        &self.fingerprints
    }

    /// Convert all fingerprints into wallet identities.
    pub fn identities(&self) -> Vec<WalletIdentity> {
        self.fingerprints
            .iter()
            .cloned()
            .map(WalletIdentity::Certificate)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use tempfile::tempdir;

    #[test]
    fn rbac_store_loads_and_persists_assignments() {
        let temp = tempdir().expect("tempdir");
        let path = temp.path().join("rbac.json");

        let store = WalletRbacStore::load(&path).expect("load empty store");
        assert!(store.snapshot().is_empty(), "new store should start empty");

        let identity = WalletIdentity::from_bearer_token("secret-token");
        let mut roles = WalletRoleSet::new();
        roles.insert(WalletRole::Admin);
        roles.insert(WalletRole::Viewer);
        let binding = WalletSecurityBinding::new(identity.clone(), roles.clone());

        store.apply_bindings(&[binding]);
        store.save().expect("save store");

        let encoded = fs::read(&path).expect("store written to disk");
        assert!(!encoded.is_empty(), "store should not be empty after save");

        let loaded = WalletRbacStore::load(&path).expect("reload store");
        let snapshot = loaded.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot.get(&identity), Some(&roles));
    }

    #[test]
    fn client_certificate_fingerprints_are_recorded() {
        let cert_a = b"client-cert-a";
        let cert_b = b"client-cert-b";
        let collection = WalletClientCertificates::from_der([cert_a.as_slice(), cert_b.as_slice()]);

        assert!(!collection.is_empty());
        let fingerprints: Vec<_> = collection.fingerprints().to_vec();
        assert_eq!(fingerprints.len(), 2);

        let expected_a = hex::encode(Sha256::digest(cert_a));
        let expected_b = hex::encode(Sha256::digest(cert_b));
        assert!(fingerprints.contains(&expected_a));
        assert!(fingerprints.contains(&expected_b));

        let identities = collection.identities();
        assert_eq!(identities.len(), 2);
        assert!(identities
            .iter()
            .any(|identity| matches!(identity, WalletIdentity::Certificate(value) if value == &expected_a)));
        assert!(identities
            .iter()
            .any(|identity| matches!(identity, WalletIdentity::Certificate(value) if value == &expected_b)));
    }

    #[test]
    fn resolves_roles_for_multiple_identities() {
        let temp = tempdir().expect("tempdir");
        let store_path = temp.path().join("rbac.json");
        let store = WalletRbacStore::load(&store_path).expect("load store");

        let token_identity = WalletIdentity::from_bearer_token("operator");
        let certificate_identity = WalletIdentity::from_certificate_der(b"mtls-client");

        let mut operator_roles = WalletRoleSet::new();
        operator_roles.insert(WalletRole::Operator);
        let mut viewer_roles = WalletRoleSet::new();
        viewer_roles.insert(WalletRole::Viewer);

        store.apply_bindings(&[
            WalletSecurityBinding::new(token_identity.clone(), operator_roles.clone()),
            WalletSecurityBinding::new(certificate_identity.clone(), viewer_roles.clone()),
        ]);
        store.save().expect("persist store");

        let context = WalletSecurityContext::from_store(store);
        let combined =
            context.resolve_roles(&[token_identity.clone(), certificate_identity.clone()]);
        assert!(combined.contains(&WalletRole::Operator));
        assert!(combined.contains(&WalletRole::Viewer));

        let token_only = context.resolve_roles(&[token_identity]);
        assert_eq!(token_only, operator_roles);
        let certificate_only = context.resolve_roles(&[certificate_identity]);
        assert_eq!(certificate_only, viewer_roles);
    }
}
