use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose, Engine as _};
use libp2p::identity::{self, Keypair};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::tier::TierLevel;
use crate::topics::GossipTopic;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding error: {0}")]
    Encoding(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TopicPermission {
    pub subscribe: TierLevel,
    pub publish: TierLevel,
}

impl TopicPermission {
    pub const fn default_for(topic: GossipTopic) -> Self {
        match topic {
            GossipTopic::Blocks | GossipTopic::Votes => Self {
                subscribe: TierLevel::Tl0,
                publish: TierLevel::Tl3,
            },
            GossipTopic::Proofs | GossipTopic::Snapshots => Self {
                subscribe: TierLevel::Tl0,
                publish: TierLevel::Tl1,
            },
            GossipTopic::Meta => Self {
                subscribe: TierLevel::Tl0,
                publish: TierLevel::Tl0,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMetadata {
    #[serde(default)]
    topics: HashMap<String, TopicPermission>,
}

impl Default for IdentityMetadata {
    fn default() -> Self {
        let mut topics = HashMap::new();
        for topic in GossipTopic::all() {
            topics.insert(
                topic.as_str().to_string(),
                TopicPermission::default_for(topic),
            );
        }
        Self { topics }
    }
}

impl IdentityMetadata {
    pub fn policy_for(&self, topic: GossipTopic) -> TopicPermission {
        self.topics
            .get(topic.as_str())
            .copied()
            .unwrap_or_else(|| TopicPermission::default_for(topic))
    }

    pub fn set_topic_policy(&mut self, topic: GossipTopic, policy: TopicPermission) {
        self.topics.insert(topic.as_str().to_string(), policy);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIdentity {
    key: String,
    #[serde(default)]
    metadata: IdentityMetadata,
}

#[derive(Debug, Clone)]
pub struct NodeIdentity {
    keypair: Keypair,
    peer_id: PeerId,
    path: PathBuf,
    metadata: IdentityMetadata,
}

impl NodeIdentity {
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        if path.exists() {
            Self::load(path)
        } else {
            let identity = Keypair::generate_ed25519();
            let metadata = IdentityMetadata::default();
            Self::persist(path, &identity, &metadata)?;
            Self::from_keypair(path.to_path_buf(), identity, metadata)
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

    pub fn metadata(&self) -> &IdentityMetadata {
        &self.metadata
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
        Self::from_keypair(path.to_path_buf(), keypair, stored.metadata)
    }

    fn persist(
        path: &Path,
        keypair: &Keypair,
        metadata: &IdentityMetadata,
    ) -> Result<(), IdentityError> {
        let bytes = keypair
            .to_protobuf_encoding()
            .map_err(|err| IdentityError::Encoding(err.to_string()))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let stored = StoredIdentity {
            key: general_purpose::STANDARD.encode(bytes),
            metadata: metadata.clone(),
        };
        let encoded = toml::to_string_pretty(&stored)
            .map_err(|err| IdentityError::Encoding(err.to_string()))?;
        fs::write(path, encoded)?;
        Ok(())
    }

    fn from_keypair(
        path: PathBuf,
        keypair: Keypair,
        metadata: IdentityMetadata,
    ) -> Result<Self, IdentityError> {
        let peer_id = PeerId::from(keypair.public());
        Ok(Self {
            keypair,
            peer_id,
            path,
            metadata,
        })
    }

    pub fn persist_current(&self) -> Result<(), IdentityError> {
        Self::persist(&self.path, &self.keypair, &self.metadata)
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
    use crate::topics::GossipTopic;
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
        let votes_policy = identity.metadata().policy_for(GossipTopic::Votes);
        assert_eq!(votes_policy.publish, TierLevel::Tl3);
        assert_eq!(votes_policy.subscribe, TierLevel::Tl0);
        let meta_policy = reloaded.metadata().policy_for(GossipTopic::Meta);
        assert_eq!(meta_policy.publish, TierLevel::Tl0);
    }
}
