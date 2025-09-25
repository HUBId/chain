use std::fs;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose};
use libp2p::PeerId;
use libp2p::identity::{self, Keypair};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding error: {0}")]
    Encoding(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIdentity {
    key: String,
}

#[derive(Debug, Clone)]
pub struct NodeIdentity {
    keypair: Keypair,
    peer_id: PeerId,
    path: PathBuf,
}

impl NodeIdentity {
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        if path.exists() {
            Self::load(path)
        } else {
            let identity = Keypair::generate_ed25519();
            Self::persist(path, &identity)?;
            Self::from_keypair(path.to_path_buf(), identity)
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn keypair(&self) -> &Keypair {
        &self.keypair
    }

    pub fn clone_keypair(&self) -> Keypair {
        self.keypair.clone()
    }

    fn load(path: &Path) -> Result<Self, IdentityError> {
        let raw = fs::read_to_string(path)?;
        let stored: StoredIdentity =
            toml::from_str(&raw).map_err(|err| IdentityError::Encoding(err.to_string()))?;
        let bytes = general_purpose::STANDARD
            .decode(stored.key)
            .map_err(|err| IdentityError::Encoding(err.to_string()))?;
        let keypair = Keypair::from_protobuf_encoding(&bytes)
            .map_err(|err| IdentityError::Encoding(err.to_string()))?;
        Self::from_keypair(path.to_path_buf(), keypair)
    }

    fn persist(path: &Path, keypair: &Keypair) -> Result<(), IdentityError> {
        let bytes = keypair
            .to_protobuf_encoding()
            .map_err(|err| IdentityError::Encoding(err.to_string()))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let stored = StoredIdentity {
            key: general_purpose::STANDARD.encode(bytes),
        };
        let encoded = toml::to_string_pretty(&stored)
            .map_err(|err| IdentityError::Encoding(err.to_string()))?;
        fs::write(path, encoded)?;
        Ok(())
    }

    fn from_keypair(path: PathBuf, keypair: Keypair) -> Result<Self, IdentityError> {
        let peer_id = PeerId::from(keypair.public());
        Ok(Self {
            keypair,
            peer_id,
            path,
        })
    }

    pub fn persist_current(&self) -> Result<(), IdentityError> {
        Self::persist(&self.path, &self.keypair)
    }
}

impl From<&NodeIdentity> for identity::PublicKey {
    fn from(value: &NodeIdentity) -> Self {
        value.keypair.public()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generates_and_persists_identity() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("node.key");
        let identity = NodeIdentity::load_or_generate(&path).expect("generate");
        identity.persist_current().expect("persist");

        let reloaded = NodeIdentity::load_or_generate(&path).expect("load");
        assert_eq!(identity.peer_id(), reloaded.peer_id());
        assert_eq!(identity.keypair().public(), reloaded.keypair().public());
    }
}
