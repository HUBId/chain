use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose, Engine as _};
use libp2p::Multiaddr;
use libp2p::PeerId;
use libp2p::{identity, multihash::Multihash};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::handshake::HandshakePayload;
use crate::tier::TierLevel;

#[derive(Debug, Error)]
pub enum PeerstoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("missing signature in handshake")]
    MissingSignature,
    #[error("missing public key for peer {peer}")]
    MissingPublicKey { peer: PeerId },
    #[error("invalid signature for peer {peer}")]
    InvalidSignature { peer: PeerId },
    #[error("invalid vrf proof for peer {peer}: {reason}")]
    InvalidVrf { peer: PeerId, reason: String },
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
    pub zsi_id: Option<String>,
    pub vrf_proof: Option<Vec<u8>>,
    pub tier: TierLevel,
    pub reputation: f64,
    pub last_seen: Option<SystemTime>,
    pub ban_until: Option<SystemTime>,
    pub public_key: Option<identity::PublicKey>,
}

impl PeerRecord {
    fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            addresses: Vec::new(),
            zsi_id: None,
            vrf_proof: None,
            tier: TierLevel::Tl0,
            reputation: 0.0,
            last_seen: None,
            ban_until: None,
            public_key: None,
        }
    }

    fn apply_handshake(&mut self, payload: &HandshakePayload) {
        self.zsi_id = Some(payload.zsi_id.clone());
        self.vrf_proof = payload.vrf_proof.clone();
        self.tier = payload.tier;
        self.last_seen = Some(SystemTime::now());
    }

    fn set_public_key(&mut self, key: identity::PublicKey) {
        self.public_key = Some(key);
        self.last_seen = Some(SystemTime::now());
    }

    fn record_address(&mut self, addr: Multiaddr) {
        if !self.addresses.iter().any(|existing| existing == &addr) {
            self.addresses.push(addr);
        }
        self.last_seen = Some(SystemTime::now());
    }

    fn apply_reputation_delta(&mut self, delta: f64) -> TierLevel {
        let mut score = (self.reputation + delta).max(0.0);
        if !score.is_finite() {
            score = 0.0;
        }
        self.reputation = score;
        self.tier = TierLevel::from_reputation(self.reputation);
        self.last_seen = Some(SystemTime::now());
        self.tier
    }

    fn set_reputation(&mut self, score: f64) -> TierLevel {
        let clamped = if score.is_finite() {
            score.max(0.0)
        } else {
            0.0
        };
        self.reputation = clamped;
        self.tier = TierLevel::from_reputation(self.reputation);
        self.last_seen = Some(SystemTime::now());
        self.tier
    }

    fn clear_ban_if_elapsed(&mut self) {
        if let Some(until) = self.ban_until {
            if SystemTime::now() >= until {
                self.ban_until = None;
            }
        }
    }

    fn set_ban(&mut self, until: SystemTime) {
        self.ban_until = Some(until);
        self.last_seen = Some(SystemTime::now());
    }

    fn remove_ban(&mut self) {
        self.ban_until = None;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPeerRecord {
    peer_id: String,
    addresses: Vec<String>,
    zsi_id: Option<String>,
    vrf_proof: Option<String>,
    tier: TierLevel,
    reputation: f64,
    last_seen: Option<u64>,
    ban_until: Option<u64>,
    public_key: Option<String>,
}

impl From<&PeerRecord> for StoredPeerRecord {
    fn from(record: &PeerRecord) -> Self {
        Self {
            peer_id: record.peer_id.to_base58(),
            addresses: record.addresses.iter().map(|a| a.to_string()).collect(),
            zsi_id: record.zsi_id.clone(),
            vrf_proof: record.vrf_proof.as_ref().map(|bytes| hex::encode(bytes)),
            tier: record.tier,
            reputation: record.reputation,
            last_seen: record.last_seen.map(|time| {
                time.duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            }),
            ban_until: record.ban_until.map(|time| {
                time.duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            }),
            public_key: record.public_key.as_ref().map(|key| {
                let encoded = key.encode_protobuf();
                general_purpose::STANDARD.encode(encoded)
            }),
        }
    }
}

impl TryFrom<StoredPeerRecord> for PeerRecord {
    type Error = PeerstoreError;

    fn try_from(value: StoredPeerRecord) -> Result<Self, Self::Error> {
        let peer_id = value
            .peer_id
            .parse()
            .map_err(|err| PeerstoreError::Encoding(format!("invalid peer id: {err}")))?;
        let mut record = PeerRecord::new(peer_id);
        record.addresses = value
            .addresses
            .into_iter()
            .filter_map(|addr| addr.parse().ok())
            .collect();
        record.zsi_id = value.zsi_id;
        record.vrf_proof = value
            .vrf_proof
            .map(|hex| hex::decode(hex).map_err(|err| PeerstoreError::Encoding(err.to_string())))
            .transpose()?;
        record.tier = value.tier;
        record.reputation = value.reputation;
        record.last_seen = value
            .last_seen
            .map(|secs| UNIX_EPOCH + std::time::Duration::from_secs(secs));
        record.ban_until = value
            .ban_until
            .map(|secs| UNIX_EPOCH + Duration::from_secs(secs));
        record.public_key = value
            .public_key
            .map(|b64| {
                let bytes = general_purpose::STANDARD
                    .decode(b64)
                    .map_err(|err| PeerstoreError::Encoding(err.to_string()))?;
                identity::PublicKey::try_decode_protobuf(&bytes)
                    .map_err(|err| PeerstoreError::Encoding(err.to_string()))
            })
            .transpose()?;
        Ok(record)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReputationSnapshot {
    pub peer_id: PeerId,
    pub reputation: f64,
    pub tier: TierLevel,
    pub banned_until: Option<SystemTime>,
}

#[derive(Debug, Clone)]
pub struct PeerstoreConfig {
    path: Option<PathBuf>,
}

impl PeerstoreConfig {
    pub fn memory() -> Self {
        Self { path: None }
    }

    pub fn persistent(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Some(path.into()),
        }
    }
}

#[derive(Debug)]
pub struct Peerstore {
    config: PeerstoreConfig,
    peers: RwLock<HashMap<PeerId, PeerRecord>>,
}

impl Peerstore {
    pub fn open(config: PeerstoreConfig) -> Result<Self, PeerstoreError> {
        let peers = if let Some(path) = &config.path {
            if path.exists() {
                let raw = fs::read_to_string(path)?;
                let stored: Vec<StoredPeerRecord> = serde_json::from_str(&raw)
                    .map_err(|err| PeerstoreError::Encoding(err.to_string()))?;
                stored
                    .into_iter()
                    .map(|record| {
                        let peer = PeerRecord::try_from(record)?;
                        Ok((peer.peer_id, peer))
                    })
                    .collect::<Result<HashMap<_, _>, PeerstoreError>>()?
            } else {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                HashMap::new()
            }
        } else {
            HashMap::new()
        };

        Ok(Self {
            config,
            peers: RwLock::new(peers),
        })
    }

    pub fn record_public_key(
        &self,
        peer_id: PeerId,
        public_key: identity::PublicKey,
    ) -> Result<(), PeerstoreError> {
        if PeerId::from(&public_key) != peer_id {
            return Err(PeerstoreError::Encoding(
                "public key does not match peer id".to_string(),
            ));
        }
        {
            let mut guard = self.peers.write();
            let entry = guard
                .entry(peer_id)
                .or_insert_with(|| PeerRecord::new(peer_id));
            entry.set_public_key(public_key);
        }
        self.persist()
    }

    pub fn record_handshake(
        &self,
        peer_id: PeerId,
        payload: &HandshakePayload,
    ) -> Result<(), PeerstoreError> {
        let public_key = self.resolve_public_key(peer_id)?;
        self.verify_signature(peer_id, payload, &public_key)?;
        self.verify_vrf(peer_id, payload, &public_key)?;

        {
            let mut guard = self.peers.write();
            let entry = guard
                .entry(peer_id)
                .or_insert_with(|| PeerRecord::new(peer_id));
            if entry.public_key.is_none() {
                entry.public_key = Some(public_key);
            }
            entry.apply_handshake(payload);
            entry.clear_ban_if_elapsed();
        }
        self.persist()
    }

    pub fn record_address(&self, peer_id: PeerId, addr: Multiaddr) -> Result<(), PeerstoreError> {
        {
            let mut guard = self.peers.write();
            let entry = guard
                .entry(peer_id)
                .or_insert_with(|| PeerRecord::new(peer_id));
            entry.record_address(addr);
        }
        self.persist()
    }

    pub fn known_peers(&self) -> Vec<(PeerId, Vec<Multiaddr>)> {
        self.peers
            .read()
            .iter()
            .map(|(peer, record)| (peer.clone(), record.addresses.clone()))
            .collect()
    }

    pub fn get(&self, peer_id: &PeerId) -> Option<PeerRecord> {
        let mut guard = self.peers.write();
        guard.get_mut(peer_id).map(|record| {
            record.clear_ban_if_elapsed();
            record.clone()
        })
    }

    pub fn reputation_snapshot(&self, peer_id: &PeerId) -> Option<ReputationSnapshot> {
        let mut guard = self.peers.write();
        guard.get_mut(peer_id).map(|record| {
            record.clear_ban_if_elapsed();
            ReputationSnapshot {
                peer_id: record.peer_id,
                reputation: record.reputation,
                tier: record.tier,
                banned_until: record.ban_until,
            }
        })
    }

    pub fn update_reputation(
        &self,
        peer_id: PeerId,
        delta: f64,
    ) -> Result<ReputationSnapshot, PeerstoreError> {
        let snapshot = {
            let mut guard = self.peers.write();
            let entry = guard
                .entry(peer_id)
                .or_insert_with(|| PeerRecord::new(peer_id));
            entry.apply_reputation_delta(delta);
            entry.clear_ban_if_elapsed();
            ReputationSnapshot {
                peer_id,
                reputation: entry.reputation,
                tier: entry.tier,
                banned_until: entry.ban_until,
            }
        };
        self.persist()?;
        Ok(snapshot)
    }

    pub fn set_reputation(
        &self,
        peer_id: PeerId,
        score: f64,
    ) -> Result<ReputationSnapshot, PeerstoreError> {
        let snapshot = {
            let mut guard = self.peers.write();
            let entry = guard
                .entry(peer_id)
                .or_insert_with(|| PeerRecord::new(peer_id));
            entry.set_reputation(score);
            entry.clear_ban_if_elapsed();
            ReputationSnapshot {
                peer_id,
                reputation: entry.reputation,
                tier: entry.tier,
                banned_until: entry.ban_until,
            }
        };
        self.persist()?;
        Ok(snapshot)
    }

    pub fn ban_peer_until(
        &self,
        peer_id: PeerId,
        until: SystemTime,
    ) -> Result<ReputationSnapshot, PeerstoreError> {
        let snapshot = {
            let mut guard = self.peers.write();
            let entry = guard
                .entry(peer_id)
                .or_insert_with(|| PeerRecord::new(peer_id));
            entry.set_ban(until);
            ReputationSnapshot {
                peer_id,
                reputation: entry.reputation,
                tier: entry.tier,
                banned_until: entry.ban_until,
            }
        };
        self.persist()?;
        Ok(snapshot)
    }

    pub fn unban_peer(&self, peer_id: PeerId) -> Result<ReputationSnapshot, PeerstoreError> {
        let snapshot = {
            let mut guard = self.peers.write();
            let entry = guard
                .entry(peer_id)
                .or_insert_with(|| PeerRecord::new(peer_id));
            entry.remove_ban();
            entry.clear_ban_if_elapsed();
            ReputationSnapshot {
                peer_id,
                reputation: entry.reputation,
                tier: entry.tier,
                banned_until: entry.ban_until,
            }
        };
        self.persist()?;
        Ok(snapshot)
    }

    pub fn tier_of(&self, peer_id: &PeerId) -> TierLevel {
        self.reputation_snapshot(peer_id)
            .map(|snapshot| snapshot.tier)
            .unwrap_or_default()
    }

    pub fn reputation_of(&self, peer_id: &PeerId) -> f64 {
        self.reputation_snapshot(peer_id)
            .map(|snapshot| snapshot.reputation)
            .unwrap_or(0.0)
    }

    pub fn is_banned(&self, peer_id: &PeerId) -> Option<SystemTime> {
        self.reputation_snapshot(peer_id)
            .and_then(|snapshot| snapshot.banned_until)
    }

    fn resolve_public_key(&self, peer_id: PeerId) -> Result<identity::PublicKey, PeerstoreError> {
        if let Some(key) = self
            .peers
            .read()
            .get(&peer_id)
            .and_then(|record| record.public_key.clone())
        {
            return Ok(key);
        }

        if let Some(derived) = derive_public_key(&peer_id) {
            return Ok(derived);
        }

        Err(PeerstoreError::MissingPublicKey { peer: peer_id })
    }

    fn verify_signature(
        &self,
        peer_id: PeerId,
        payload: &HandshakePayload,
        public_key: &identity::PublicKey,
    ) -> Result<(), PeerstoreError> {
        if payload.signature.is_empty() {
            return Err(PeerstoreError::MissingSignature);
        }
        if !payload.verify_signature_with(public_key) {
            return Err(PeerstoreError::InvalidSignature { peer: peer_id });
        }
        Ok(())
    }

    fn verify_vrf(
        &self,
        peer_id: PeerId,
        payload: &HandshakePayload,
        public_key: &identity::PublicKey,
    ) -> Result<(), PeerstoreError> {
        let Some(proof) = payload.vrf_proof.as_ref() else {
            return Ok(());
        };
        if proof.is_empty() {
            return Err(PeerstoreError::InvalidVrf {
                peer: peer_id,
                reason: "empty proof".into(),
            });
        }
        if !public_key.verify(&payload.vrf_message(), proof) {
            return Err(PeerstoreError::InvalidVrf {
                peer: peer_id,
                reason: "verification failed".into(),
            });
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), PeerstoreError> {
        let Some(path) = &self.config.path else {
            return Ok(());
        };
        let snapshot: Vec<StoredPeerRecord> = self
            .peers
            .read()
            .values()
            .map(StoredPeerRecord::from)
            .collect();
        let encoded = serde_json::to_string_pretty(&snapshot)
            .map_err(|err| PeerstoreError::Encoding(err.to_string()))?;
        fs::write(path, encoded)?;
        Ok(())
    }
}

fn derive_public_key(peer_id: &PeerId) -> Option<identity::PublicKey> {
    let multihash: &Multihash<64> = peer_id.as_ref();
    if multihash.code() != 0 {
        return None;
    }
    let digest = multihash.digest();
    identity::PublicKey::try_decode_protobuf(digest).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity;
    use tempfile::tempdir;

    fn signed_handshake(
        keypair: &identity::Keypair,
        zsi: &str,
        tier: TierLevel,
        include_vrf: bool,
    ) -> HandshakePayload {
        let base = HandshakePayload::new(zsi.to_string(), None, tier);
        let vrf_proof = include_vrf
            .then(|| keypair.sign(&base.vrf_message()).expect("vrf proof"));
        let template = HandshakePayload::new(zsi.to_string(), vrf_proof, tier);
        template.signed(keypair).expect("sign handshake")
    }

    #[test]
    fn records_and_persists_peer_metadata() {
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("peerstore.json");
        let store = Peerstore::open(PeerstoreConfig::persistent(&path)).expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
        let payload = signed_handshake(&keypair, "zsi", TierLevel::Tl3, true);

        store.record_address(peer_id, addr.clone()).expect("addr");
        store
            .record_handshake(peer_id, &payload)
            .expect("handshake");

        let loaded = Peerstore::open(PeerstoreConfig::persistent(&path)).expect("reload");
        let record = loaded.get(&peer_id).expect("record exists");
        assert_eq!(record.addresses, vec![addr]);
        assert_eq!(record.zsi_id.as_deref(), Some("zsi"));
        assert_eq!(record.vrf_proof, payload.vrf_proof);
        assert_eq!(record.tier, TierLevel::Tl3);
    }

    #[test]
    fn updates_reputation_and_ban_state() {
        let store = Peerstore::open(PeerstoreConfig::memory()).expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let payload = signed_handshake(&keypair, "peer", TierLevel::Tl1, false);

        store
            .record_handshake(peer_id, &payload)
            .expect("handshake");

        let snapshot = store
            .update_reputation(peer_id, 2.4)
            .expect("update reputation");
        assert_eq!(snapshot.tier, TierLevel::Tl2);
        assert!(snapshot.banned_until.is_none());

        let ban_until = SystemTime::now() + Duration::from_secs(10);
        store.ban_peer_until(peer_id, ban_until).expect("ban peer");

        let snapshot = store.reputation_snapshot(&peer_id).expect("snapshot");
        assert!(snapshot.banned_until.is_some());

        store.unban_peer(peer_id).expect("unban");
        let snapshot = store.reputation_snapshot(&peer_id).expect("snapshot");
        assert!(snapshot.banned_until.is_none());
    }

    #[test]
    fn rejects_invalid_handshake_signature() {
        let store = Peerstore::open(PeerstoreConfig::memory()).expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let mut payload = signed_handshake(&keypair, "peer", TierLevel::Tl2, false);
        payload.signature[0] ^= 0x01;

        let result = store.record_handshake(peer_id, &payload);
        assert!(matches!(
            result,
            Err(PeerstoreError::InvalidSignature { peer }) if peer == peer_id
        ));
    }

    #[test]
    fn rejects_invalid_vrf_proof() {
        let store = Peerstore::open(PeerstoreConfig::memory()).expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let mut payload = signed_handshake(&keypair, "peer", TierLevel::Tl3, true);
        if let Some(proof) = payload.vrf_proof.as_mut() {
            proof[0] ^= 0xFF;
        }
        payload = payload.signed(&keypair).expect("resign");

        let result = store.record_handshake(peer_id, &payload);
        assert!(matches!(
            result,
            Err(PeerstoreError::InvalidVrf { peer, .. }) if peer == peer_id
        ));
    }

    #[test]
    fn exposes_known_peers() {
        let store = Peerstore::open(PeerstoreConfig::memory()).expect("open");
        let peer = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/7000".parse().expect("addr");

        store
            .record_address(peer, addr.clone())
            .expect("record address");

        let known = store.known_peers();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].0, peer);
        assert_eq!(known[0].1, vec![addr]);
    }
}
