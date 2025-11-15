use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::errors::{ChainError, ChainResult};

/// Wallet roles recognised by the runtime RBAC layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletRole {
    /// Full administrative control over the wallet runtime.
    Admin,
    /// Operational control (e.g. rescans, draft creation).
    Operator,
    /// Read-only access to wallet state.
    Viewer,
}

/// Collection type tracking the roles associated with a request or identity.
pub type WalletRoleSet = BTreeSet<WalletRole>;

/// Identity extracted from an RPC request.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "id")]
pub enum WalletIdentity {
    /// Bearer token presented via the `Authorization` header.
    Token(String),
    /// TLS client certificate fingerprint (SHA-256).
    Certificate(String),
}

impl WalletIdentity {
    /// Construct an identity from a bearer token by hashing it with SHA-256.
    pub fn from_bearer_token(token: &str) -> Self {
        Self::Token(hex_digest(token.as_bytes()))
    }

    /// Construct an identity from a DER-encoded certificate.
    pub fn from_certificate_der(der: &[u8]) -> Self {
        Self::Certificate(hex_digest(der))
    }

    /// Construct an identity from a PEM-encoded certificate.
    pub fn from_certificate_pem(pem: &str) -> ChainResult<Self> {
        let der = decode_pem(pem)?;
        Ok(Self::from_certificate_der(&der))
    }

    /// Construct an identity from a pre-computed fingerprint.
    pub fn from_certificate_fingerprint(fingerprint: &str) -> ChainResult<Self> {
        let trimmed = fingerprint.trim();
        if trimmed.is_empty() {
            return Err(ChainError::Config(
                "certificate fingerprint must not be empty".to_string(),
            ));
        }
        let normalised = trimmed.to_lowercase();
        if normalised.chars().any(|ch| !ch.is_ascii_hexdigit()) {
            return Err(ChainError::Config(
                "certificate fingerprint must be hexadecimal".to_string(),
            ));
        }
        Ok(Self::Certificate(normalised))
    }
}

fn decode_pem(pem: &str) -> ChainResult<Vec<u8>> {
    let mut body = String::new();
    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") || trimmed.starts_with("-----END") {
            continue;
        }
        body.push_str(trimmed);
    }
    Base64::decode_vec(body.as_bytes())
        .map_err(|err| ChainError::Config(format!("invalid certificate pem: {err}")))
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
        let identity = WalletIdentity::from_certificate_fingerprint(fingerprint)?;
        Ok(self.resolve_roles(&[identity]))
    }

    /// Access the underlying RBAC store snapshot.
    pub fn snapshot(&self) -> BTreeMap<WalletIdentity, WalletRoleSet> {
        self.store.snapshot()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_identity_hashes_secret() {
        let identity = WalletIdentity::from_bearer_token("secret");
        assert!(matches!(identity, WalletIdentity::Token(hash) if hash.len() == 64));
    }

    #[test]
    fn certificate_identity_from_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\nZmFrZWNlcnQ=\n-----END CERTIFICATE-----";
        let identity = WalletIdentity::from_certificate_pem(pem).expect("identity");
        assert!(matches!(identity, WalletIdentity::Certificate(_)));
    }
}
