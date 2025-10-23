use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use crate::vendor::PeerId;
use blake3::Hash;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::topics::GossipTopic;

#[derive(Debug, Error)]
pub enum GossipStateError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding error: {0}")]
    Encoding(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoredGossipState {
    subscriptions: Vec<String>,
    mesh_peers: HashMap<String, Vec<String>>,
    recent_digests: Vec<String>,
}

impl StoredGossipState {
    fn push_subscription(&mut self, topic: GossipTopic) {
        let key = topic.as_str().to_string();
        if !self.subscriptions.iter().any(|entry| entry == &key) {
            self.subscriptions.push(key);
        }
    }

    fn remove_subscription(&mut self, topic: GossipTopic) {
        let key = topic.as_str();
        self.subscriptions.retain(|entry| entry != key);
    }

    fn record_peer(&mut self, topic: GossipTopic, peer: PeerId, capacity: usize) {
        let entry = self
            .mesh_peers
            .entry(topic.as_str().to_string())
            .or_default();
        let peer_id = peer.to_base58();
        if !entry.iter().any(|p| p == &peer_id) {
            entry.push(peer_id);
            if entry.len() > capacity {
                entry.remove(0);
            }
        }
    }

    fn record_digest(&mut self, digest: Hash, capacity: usize) {
        let hex = digest.to_hex().to_string();
        if self.recent_digests.iter().any(|entry| entry == &hex) {
            return;
        }
        self.recent_digests.push(hex);
        if self.recent_digests.len() > capacity {
            let overflow = self.recent_digests.len() - capacity;
            self.recent_digests.drain(0..overflow);
        }
    }
}

#[derive(Debug)]
pub struct GossipStateStore {
    path: PathBuf,
    capacity: usize,
    state: RwLock<StoredGossipState>,
}

impl GossipStateStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, GossipStateError> {
        Self::with_capacity(path, 64)
    }

    pub fn with_capacity(
        path: impl Into<PathBuf>,
        capacity: usize,
    ) -> Result<Self, GossipStateError> {
        let path = path.into();
        let state = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            serde_json::from_str(&raw).map_err(|err| GossipStateError::Encoding(err.to_string()))?
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            StoredGossipState::default()
        };
        Ok(Self {
            path,
            capacity: capacity.max(8),
            state: RwLock::new(state),
        })
    }

    pub fn subscriptions(&self) -> Vec<GossipTopic> {
        self.state
            .read()
            .subscriptions
            .iter()
            .filter_map(|value| GossipTopic::from_str(value))
            .collect()
    }

    pub fn peers_for(&self, topic: GossipTopic) -> Vec<PeerId> {
        self.state
            .read()
            .mesh_peers
            .get(topic.as_str())
            .into_iter()
            .flat_map(|peers| peers.iter())
            .filter_map(|value| value.parse().ok())
            .collect()
    }

    pub fn recent_digests(&self) -> Vec<Hash> {
        self.state
            .read()
            .recent_digests
            .iter()
            .filter_map(|hex| {
                let mut bytes = [0u8; 32];
                let decoded = hex::decode(hex).ok()?;
                if decoded.len() != 32 {
                    return None;
                }
                bytes.copy_from_slice(&decoded);
                Some(Hash::from(bytes))
            })
            .collect()
    }

    pub fn record_subscription(&self, topic: GossipTopic) -> Result<(), GossipStateError> {
        {
            let mut guard = self.state.write();
            guard.push_subscription(topic);
        }
        self.persist()
    }

    pub fn record_unsubscribe(&self, topic: GossipTopic) -> Result<(), GossipStateError> {
        {
            let mut guard = self.state.write();
            guard.remove_subscription(topic);
        }
        self.persist()
    }

    pub fn record_message(
        &self,
        topic: GossipTopic,
        peer: PeerId,
        digest: Hash,
    ) -> Result<(), GossipStateError> {
        {
            let mut guard = self.state.write();
            guard.record_peer(topic, peer, self.capacity);
            guard.record_digest(digest, self.capacity * 4);
        }
        self.persist()
    }

    fn persist(&self) -> Result<(), GossipStateError> {
        let snapshot = self.state.read().clone();
        let encoded = serde_json::to_string_pretty(&snapshot)
            .map_err(|err| GossipStateError::Encoding(err.to_string()))?;
        fs::write(&self.path, encoded)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn persists_and_recovers_state() {
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("gossip.json");
        let store = GossipStateStore::with_capacity(&path, 4).expect("store");
        let peer = PeerId::random();

        store
            .record_subscription(GossipTopic::Blocks)
            .expect("subscription");
        store
            .record_message(GossipTopic::Blocks, peer, blake3::hash(b"payload"))
            .expect("message");

        let reloaded = GossipStateStore::with_capacity(&path, 4).expect("reload");
        assert_eq!(reloaded.subscriptions(), vec![GossipTopic::Blocks]);
        let peers = reloaded.peers_for(GossipTopic::Blocks);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0], peer);
        assert!(!reloaded.recent_digests().is_empty());
    }
}
