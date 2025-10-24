use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::vendor::identity::{self, Keypair};
use crate::vendor::PeerId;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::sync::{Arc, OnceLock, RwLock};
use thiserror::Error;

use crate::tier::TierLevel;
use crate::topics::GossipTopic;
use schnorrkel::keys::{ExpansionMode, MiniSecretKey};

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
            GossipTopic::VrfProofs => Self {
                subscribe: TierLevel::Tl0,
                publish: TierLevel::Tl2,
            },
            GossipTopic::Meta => Self {
                subscribe: TierLevel::Tl0,
                publish: TierLevel::Tl0,
            },
            GossipTopic::VrfMeta => Self {
                subscribe: TierLevel::Tl0,
                publish: TierLevel::Tl1,
            },
            GossipTopic::WitnessProofs => Self {
                subscribe: TierLevel::Tl0,
                publish: TierLevel::Tl2,
            },
            GossipTopic::WitnessMeta => Self {
                subscribe: TierLevel::Tl0,
                publish: TierLevel::Tl1,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMetadata {
    #[serde(default)]
    topics: HashMap<String, TopicPermission>,
    #[serde(default)]
    tier: TierLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vrf_secret: Option<String>,
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
        Self {
            topics,
            tier: TierLevel::default(),
            vrf_secret: None,
        }
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

    pub fn tier(&self) -> TierLevel {
        self.tier
    }

    pub fn set_tier(&mut self, tier: TierLevel) {
        self.tier = tier;
    }

    pub fn vrf_secret_bytes(&self) -> Result<Option<Vec<u8>>, IdentityError> {
        if let Some(secret) = &self.vrf_secret {
            let decoded = general_purpose::STANDARD
                .decode(secret)
                .map_err(|err| IdentityError::Encoding(err.to_string()))?;
            Ok(Some(decoded))
        } else {
            Ok(None)
        }
    }

    pub fn set_vrf_secret_bytes(&mut self, secret: Option<&[u8]>) {
        self.vrf_secret = secret.map(|bytes| general_purpose::STANDARD.encode(bytes));
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredIdentity {
    key: String,
    #[serde(default)]
    metadata: IdentityMetadata,
}

#[derive(Debug, Clone)]
struct IdentityHookState {
    inner: Arc<RwLock<IdentityHookData>>,
}

#[derive(Debug)]
struct IdentityHookData {
    public_key: identity::PublicKey,
    vrf_secret: Option<Vec<u8>>,
}

static GLOBAL_HOOKS: OnceLock<RwLock<Option<IdentityHookState>>> = OnceLock::new();

fn hooks_storage() -> &'static RwLock<Option<IdentityHookState>> {
    GLOBAL_HOOKS.get_or_init(|| RwLock::new(None))
}

impl IdentityHookState {
    fn new(public_key: identity::PublicKey, vrf_secret: Option<Vec<u8>>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(IdentityHookData {
                public_key,
                vrf_secret,
            })),
        }
    }

    fn install(&self) {
        *hooks_storage().write().expect("identity hooks poisoned") = Some(self.clone());
    }

    fn set_vrf_secret(&self, secret: Option<Vec<u8>>) {
        let mut guard = self.inner.write().expect("identity hooks poisoned");
        guard.vrf_secret = secret;
    }

    fn vrf_public_key(&self, target: &identity::PublicKey) -> Option<Vec<u8>> {
        let secret = {
            let guard = self.inner.read().expect("identity hooks poisoned");
            if target != &guard.public_key {
                return None;
            }
            guard.vrf_secret.clone()?
        };
        let mini = Self::decode_secret(&secret)?;
        let keypair = mini.expand_to_keypair(ExpansionMode::Uniform);
        Some(keypair.public.to_bytes().to_vec())
    }

    fn vrf_sign(
        &self,
        keypair: &identity::Keypair,
        context: &[u8],
        message: &[u8],
    ) -> Option<Vec<u8>> {
        let secret = {
            let guard = self.inner.read().expect("identity hooks poisoned");
            if keypair.public() != guard.public_key {
                return None;
            }
            guard.vrf_secret.clone()?
        };

        let mini = Self::decode_secret(&secret)?;
        let derived = mini.expand_to_keypair(ExpansionMode::Uniform);
        Some(derived.sign_simple(context, message).to_bytes().to_vec())
    }

    fn decode_secret(secret: &[u8]) -> Option<MiniSecretKey> {
        let bytes: [u8; 32] = secret.try_into().ok()?;
        MiniSecretKey::from_bytes(&bytes).ok()
    }
}

fn with_hooks<R>(f: impl FnOnce(&IdentityHookState) -> Option<R>) -> Option<R> {
    let guard = hooks_storage().read().expect("identity hooks poisoned");
    guard.as_ref().and_then(f)
}

pub trait IdentityKeypairExt {
    fn sign_with_extensions(&self, msg: &[u8]) -> Result<Vec<u8>, identity::SigningError>;
    fn vrf_sign(&self, context: &[u8], message: &[u8]) -> Option<Vec<u8>>;
    fn vrf_public_key(&self) -> Option<Vec<u8>>;
}

impl IdentityKeypairExt for identity::Keypair {
    fn sign_with_extensions(&self, msg: &[u8]) -> Result<Vec<u8>, identity::SigningError> {
        self.sign(msg)
    }

    fn vrf_sign(&self, context: &[u8], message: &[u8]) -> Option<Vec<u8>> {
        with_hooks(|hooks| hooks.vrf_sign(self, context, message))
    }

    fn vrf_public_key(&self) -> Option<Vec<u8>> {
        with_hooks(|hooks| hooks.vrf_public_key(&self.public()))
    }
}

pub trait IdentityPublicKeyExt {
    fn verify_with_extensions(&self, msg: &[u8], signature: &[u8]) -> bool;
}

impl IdentityPublicKeyExt for identity::PublicKey {
    fn verify_with_extensions(&self, msg: &[u8], signature: &[u8]) -> bool {
        self.verify(msg, signature)
    }
}

#[derive(Debug, Clone)]
pub struct NodeIdentity {
    keypair: Keypair,
    peer_id: PeerId,
    path: PathBuf,
    metadata: IdentityMetadata,
    vrf_secret: Option<Vec<u8>>,
    hooks: IdentityHookState,
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

    pub fn tier(&self) -> TierLevel {
        self.metadata.tier()
    }

    pub fn set_tier(&mut self, tier: TierLevel) {
        self.metadata.set_tier(tier);
    }

    pub fn vrf_public_key(&self) -> Option<Vec<u8>> {
        self.vrf_secret.as_ref().and_then(|secret| {
            IdentityHookState::decode_secret(secret).map(|mini| {
                mini.expand_to_keypair(ExpansionMode::Uniform)
                    .public
                    .to_bytes()
                    .to_vec()
            })
        })
    }

    pub fn vrf_secret(&self) -> Option<MiniSecretKey> {
        self.vrf_secret
            .as_ref()
            .and_then(|secret| IdentityHookState::decode_secret(secret))
    }

    pub fn set_vrf_secret(&mut self, secret: Option<&MiniSecretKey>) {
        self.vrf_secret = secret.map(|sk| sk.to_bytes().to_vec());
        self.metadata
            .set_vrf_secret_bytes(self.vrf_secret.as_deref());
        self.hooks.set_vrf_secret(self.vrf_secret.clone());
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
        let public_key = keypair.public();
        let peer_id = PeerId::from(public_key.clone());
        let vrf_secret = metadata.vrf_secret_bytes()?;
        let hooks = IdentityHookState::new(public_key, vrf_secret.clone());
        hooks.install();
        Ok(Self {
            keypair,
            peer_id,
            path,
            metadata,
            vrf_secret,
            hooks,
        })
    }

    pub fn persist_current(&self) -> Result<(), IdentityError> {
        let mut metadata = self.metadata.clone();
        metadata.set_vrf_secret_bytes(self.vrf_secret.as_deref());
        Self::persist(&self.path, &self.keypair, &metadata)
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
    use crate::handshake::HandshakePayload;
    use crate::topics::GossipTopic;
    use rand::rngs::OsRng;
    use schnorrkel::keys::ExpansionMode;
    use tempfile::tempdir;

    #[test]
    fn generates_and_persists_identity() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("node.key");
        let mut identity = NodeIdentity::load_or_generate(&path).expect("generate");
        identity.set_tier(TierLevel::Tl2);
        let mut rng = OsRng;
        let vrf_secret = MiniSecretKey::generate_with(&mut rng);
        let expected_public = vrf_secret
            .expand_to_keypair(ExpansionMode::Uniform)
            .public
            .to_bytes()
            .to_vec();
        identity.set_vrf_secret(Some(&vrf_secret));
        identity.persist_current().expect("persist");

        let reloaded = NodeIdentity::load_or_generate(&path).expect("load");
        assert_eq!(identity.peer_id(), reloaded.peer_id());
        assert_eq!(identity.keypair().public(), reloaded.keypair().public());
        assert_eq!(identity.tier(), TierLevel::Tl2);
        assert_eq!(reloaded.tier(), TierLevel::Tl2);
        assert_eq!(identity.vrf_public_key(), Some(expected_public.clone()));
        assert_eq!(
            reloaded
                .vrf_secret()
                .expect("reload secret")
                .to_bytes()
                .to_vec(),
            vrf_secret.to_bytes().to_vec()
        );
        let signed = HandshakePayload::new("node", None, None, identity.tier())
            .signed(identity.keypair())
            .expect("sign");
        assert_eq!(signed.vrf_public_key, Some(expected_public.clone()));
        assert!(signed
            .vrf_proof
            .as_ref()
            .map_or(false, |proof| !proof.is_empty()));
        let signed_reload = HandshakePayload::new("node", None, None, reloaded.tier())
            .signed(reloaded.keypair())
            .expect("sign reload");
        assert_eq!(signed_reload.vrf_public_key, Some(expected_public));
        assert_eq!(signed_reload.vrf_proof, signed.vrf_proof);
        let votes_policy = identity.metadata().policy_for(GossipTopic::Votes);
        assert_eq!(votes_policy.publish, TierLevel::Tl3);
        assert_eq!(votes_policy.subscribe, TierLevel::Tl0);
        let meta_policy = reloaded.metadata().policy_for(GossipTopic::Meta);
        assert_eq!(meta_policy.publish, TierLevel::Tl0);
    }
}
