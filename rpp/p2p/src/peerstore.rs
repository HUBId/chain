use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::vendor::core::multihash::Multihash;
use crate::vendor::{identity, Multiaddr, PeerId};
use base64::{engine::general_purpose, Engine as _};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::handshake::{
    emit_handshake_telemetry, HandshakeOutcome, HandshakePayload, TelemetryMetadata,
    VRF_HANDSHAKE_CONTEXT,
};
use crate::tier::TierLevel;
use schnorrkel::{keys::PublicKey as Sr25519PublicKey, Signature};

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
    #[error("peer {peer} is blocklisted")]
    Blocklisted { peer: PeerId },
    #[error("peer {peer} tier {actual:?} below allowlist requirement {required:?}")]
    TierBelowAllowlist {
        peer: PeerId,
        required: TierLevel,
        actual: TierLevel,
    },
}

pub trait IdentityVerifier: Send + Sync {
    fn expected_vrf_public_key(&self, zsi_id: &str) -> Option<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub peer_id: PeerId,
    pub addresses: Vec<Multiaddr>,
    pub zsi_id: Option<String>,
    pub vrf_public_key: Option<Vec<u8>>,
    pub vrf_proof: Option<Vec<u8>>,
    pub tier: TierLevel,
    pub reputation: f64,
    pub last_seen: Option<SystemTime>,
    pub ban_until: Option<SystemTime>,
    pub public_key: Option<identity::PublicKey>,
    pub telemetry: Option<TelemetryMetadata>,
    pub last_ping_rtt: Option<Duration>,
    pub ping_failures: u32,
    pub features: BTreeMap<String, bool>,
}

impl PeerRecord {
    fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            addresses: Vec::new(),
            zsi_id: None,
            vrf_public_key: None,
            vrf_proof: None,
            tier: TierLevel::Tl0,
            reputation: 0.0,
            last_seen: None,
            ban_until: None,
            public_key: None,
            telemetry: None,
            last_ping_rtt: None,
            ping_failures: 0,
            features: BTreeMap::new(),
        }
    }

    fn apply_handshake(&mut self, payload: &HandshakePayload) {
        self.zsi_id = Some(payload.zsi_id.clone());
        self.vrf_public_key = payload.vrf_public_key.clone();
        self.vrf_proof = payload.vrf_proof.clone();
        self.tier = payload.tier;
        self.last_seen = Some(SystemTime::now());
        self.telemetry = payload.telemetry.clone();
        self.features = payload.features.clone();
    }

    fn set_public_key(&mut self, key: identity::PublicKey) {
        self.public_key = Some(key);
        self.last_seen = Some(SystemTime::now());
    }

    fn apply_allowlist_tier(&mut self, tier: TierLevel) {
        self.tier = tier;
        self.reputation = reputation_floor_for_tier(tier);
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

    fn record_ping_success(&mut self, rtt: Duration) {
        self.last_seen = Some(SystemTime::now());
        self.last_ping_rtt = Some(rtt);
        self.ping_failures = 0;
    }

    fn record_ping_failure(&mut self) -> u32 {
        self.ping_failures = self.ping_failures.saturating_add(1);
        self.ping_failures
    }
}

fn reputation_floor_for_tier(tier: TierLevel) -> f64 {
    match tier {
        TierLevel::Tl0 => 0.0,
        TierLevel::Tl1 => 1.0,
        TierLevel::Tl2 => 2.0,
        TierLevel::Tl3 => 3.0,
        TierLevel::Tl4 => 4.0,
        TierLevel::Tl5 => 5.0,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPeerRecord {
    peer_id: String,
    addresses: Vec<String>,
    zsi_id: Option<String>,
    vrf_public_key: Option<String>,
    vrf_proof: Option<String>,
    tier: TierLevel,
    reputation: f64,
    last_seen: Option<u64>,
    ban_until: Option<u64>,
    public_key: Option<String>,
    telemetry: Option<TelemetryMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_ping_rtt_ms: Option<u64>,
    #[serde(default)]
    ping_failures: u32,
    #[serde(default)]
    features: BTreeMap<String, bool>,
}

impl From<&PeerRecord> for StoredPeerRecord {
    fn from(record: &PeerRecord) -> Self {
        Self {
            peer_id: record.peer_id.to_base58(),
            addresses: record.addresses.iter().map(|a| a.to_string()).collect(),
            zsi_id: record.zsi_id.clone(),
            vrf_public_key: record
                .vrf_public_key
                .as_ref()
                .map(|bytes| hex::encode(bytes)),
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
            telemetry: record.telemetry.clone(),
            last_ping_rtt_ms: record
                .last_ping_rtt
                .map(|rtt| (rtt.as_millis().min(u128::from(u64::MAX))) as u64),
            ping_failures: record.ping_failures,
            features: record.features.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct StoredAccessLists {
    #[serde(default)]
    allowlist: Vec<StoredAllowlistEntry>,
    #[serde(default)]
    blocklist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredAllowlistEntry {
    peer_id: String,
    tier: TierLevel,
}

impl From<&AllowlistedPeer> for StoredAllowlistEntry {
    fn from(entry: &AllowlistedPeer) -> Self {
        Self {
            peer_id: entry.peer.to_base58(),
            tier: entry.tier,
        }
    }
}

impl TryFrom<StoredAllowlistEntry> for AllowlistedPeer {
    type Error = PeerstoreError;

    fn try_from(entry: StoredAllowlistEntry) -> Result<Self, Self::Error> {
        let peer = PeerId::from_str(&entry.peer_id)
            .map_err(|err| PeerstoreError::Encoding(err.to_string()))?;
        Ok(Self {
            peer,
            tier: entry.tier,
        })
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
        record.vrf_public_key = value
            .vrf_public_key
            .map(|hex| hex::decode(hex).map_err(|err| PeerstoreError::Encoding(err.to_string())))
            .transpose()?;
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
        record.telemetry = value.telemetry;
        record.last_ping_rtt = value.last_ping_rtt_ms.map(Duration::from_millis);
        record.ping_failures = value.ping_failures;
        record.features = value.features;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowlistedPeer {
    pub peer: PeerId,
    pub tier: TierLevel,
}

pub struct PeerstoreConfig {
    path: Option<PathBuf>,
    identity_verifier: Option<Arc<dyn IdentityVerifier>>,
    allowlist: Vec<AllowlistedPeer>,
    blocklist: Vec<PeerId>,
}

impl fmt::Debug for PeerstoreConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerstoreConfig")
            .field("path", &self.path)
            .field("allowlist", &self.allowlist)
            .field("blocklist", &self.blocklist)
            .finish()
    }
}

impl PeerstoreConfig {
    pub fn memory() -> Self {
        Self {
            path: None,
            identity_verifier: None,
            allowlist: Vec::new(),
            blocklist: Vec::new(),
        }
    }

    pub fn persistent(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Some(path.into()),
            identity_verifier: None,
            allowlist: Vec::new(),
            blocklist: Vec::new(),
        }
    }

    pub fn with_identity_verifier(mut self, verifier: Arc<dyn IdentityVerifier>) -> Self {
        self.identity_verifier = Some(verifier);
        self
    }

    pub fn with_allowlist(mut self, entries: Vec<AllowlistedPeer>) -> Self {
        self.allowlist = entries;
        self
    }

    pub fn with_blocklist(mut self, peers: Vec<PeerId>) -> Self {
        self.blocklist = peers;
        self
    }

    pub fn allowlist(&self) -> &[AllowlistedPeer] {
        &self.allowlist
    }

    pub fn blocklist(&self) -> &[PeerId] {
        &self.blocklist
    }
}

pub struct Peerstore {
    path: Option<PathBuf>,
    access_path: Option<PathBuf>,
    peers: RwLock<HashMap<PeerId, PeerRecord>>,
    identity_verifier: Option<Arc<dyn IdentityVerifier>>,
    allowlist: RwLock<Vec<AllowlistedPeer>>,
    blocklisted: RwLock<HashSet<PeerId>>,
}

impl fmt::Debug for Peerstore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peerstore")
            .field("path", &self.path)
            .field("access_path", &self.access_path)
            .field("identity_verifier", &self.identity_verifier.is_some())
            .field("allowlist_len", &self.allowlist.read().len())
            .field("blocklisted_len", &self.blocklisted.read().len())
            .finish()
    }
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

        let access_path = config
            .path
            .as_ref()
            .map(|path| path.with_extension("access.json"));

        let (allowlist, blocklisted) = if let Some(path) = &access_path {
            if path.exists() {
                let raw = fs::read_to_string(path)?;
                let stored: StoredAccessLists = serde_json::from_str(&raw)
                    .map_err(|err| PeerstoreError::Encoding(err.to_string()))?;
                let allowlist = stored
                    .allowlist
                    .into_iter()
                    .map(AllowlistedPeer::try_from)
                    .collect::<Result<Vec<_>, PeerstoreError>>()?;
                let blocklisted = stored
                    .blocklist
                    .into_iter()
                    .map(|peer| {
                        PeerId::from_str(&peer)
                            .map_err(|err| PeerstoreError::Encoding(err.to_string()))
                    })
                    .collect::<Result<HashSet<_>, _>>()?;
                (allowlist, blocklisted)
            } else {
                (
                    config.allowlist.clone(),
                    config.blocklist.iter().cloned().collect(),
                )
            }
        } else {
            (
                config.allowlist.clone(),
                config.blocklist.iter().cloned().collect(),
            )
        };
        let store = Self {
            path: config.path,
            access_path,
            identity_verifier: config.identity_verifier,
            peers: RwLock::new(peers),
            allowlist: RwLock::new(allowlist),
            blocklisted: RwLock::new(blocklisted),
        };
        store.apply_access_control()?;
        store.persist_access_lists()?;
        Ok(store)
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
        self.persist_access_lists()?;
        self.persist()
    }

    pub fn record_handshake(
        &self,
        peer_id: PeerId,
        payload: &HandshakePayload,
    ) -> Result<HandshakeOutcome, PeerstoreError> {
        if self.is_blocklisted(&peer_id) {
            let outcome = HandshakeOutcome::Blocklisted;
            emit_handshake_telemetry(&peer_id, payload, &outcome);
            return Err(PeerstoreError::Blocklisted { peer: peer_id });
        }

        let allowlisted_tier = self.allowlist_tier(&peer_id);
        if let Some(required) = allowlisted_tier {
            if payload.tier < required {
                let outcome = HandshakeOutcome::AllowlistTierMismatch {
                    required,
                    actual: payload.tier,
                };
                emit_handshake_telemetry(&peer_id, payload, &outcome);
                return Err(PeerstoreError::TierBelowAllowlist {
                    peer: peer_id,
                    required,
                    actual: payload.tier,
                });
            }
        }

        let public_key = match self.resolve_public_key(peer_id.clone()) {
            Ok(key) => key,
            Err(err) => {
                if matches!(err, PeerstoreError::MissingPublicKey { .. }) {
                    let outcome = HandshakeOutcome::MissingPublicKey;
                    emit_handshake_telemetry(&peer_id, payload, &outcome);
                }
                return Err(err);
            }
        };

        if let Err(err) = self.verify_signature(peer_id.clone(), payload, &public_key) {
            if let Some(outcome) = match &err {
                PeerstoreError::MissingSignature => Some(HandshakeOutcome::MissingSignature),
                PeerstoreError::InvalidSignature { .. } => Some(HandshakeOutcome::InvalidSignature),
                _ => None,
            } {
                emit_handshake_telemetry(&peer_id, payload, &outcome);
            }
            return Err(err);
        }

        if let Err(err) = self.verify_vrf(peer_id.clone(), payload) {
            if let PeerstoreError::InvalidVrf { reason, .. } = &err {
                let outcome = HandshakeOutcome::InvalidVrf {
                    reason: reason.clone(),
                };
                emit_handshake_telemetry(&peer_id, payload, &outcome);
            }
            return Err(err);
        }

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
        self.persist()?;
        let outcome = HandshakeOutcome::Accepted {
            tier: payload.tier,
            allowlisted: allowlisted_tier.is_some(),
        };
        emit_handshake_telemetry(&peer_id, payload, &outcome);
        Ok(outcome)
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

    pub fn record_ping_success(
        &self,
        peer_id: PeerId,
        rtt: Duration,
    ) -> Result<(), PeerstoreError> {
        {
            let mut guard = self.peers.write();
            let entry = guard
                .entry(peer_id)
                .or_insert_with(|| PeerRecord::new(peer_id));
            entry.record_ping_success(rtt);
        }
        self.persist()
    }

    pub fn record_ping_failure(&self, peer_id: PeerId) -> Result<u32, PeerstoreError> {
        let failures = {
            let mut guard = self.peers.write();
            let entry = guard
                .entry(peer_id)
                .or_insert_with(|| PeerRecord::new(peer_id));
            entry.record_ping_failure()
        };
        self.persist()?;
        Ok(failures)
    }

    pub fn get(&self, peer_id: &PeerId) -> Option<PeerRecord> {
        let mut guard = self.peers.write();
        guard.get_mut(peer_id).map(|record| {
            record.clear_ban_if_elapsed();
            record.clone()
        })
    }

    pub fn known_peers(&self) -> Vec<PeerRecord> {
        let mut guard = self.peers.write();
        guard
            .values_mut()
            .map(|record| {
                record.clear_ban_if_elapsed();
                record.clone()
            })
            .collect()
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

    pub fn is_blocklisted(&self, peer_id: &PeerId) -> bool {
        self.blocklisted.read().contains(peer_id)
    }

    fn allowlist_tier(&self, peer_id: &PeerId) -> Option<TierLevel> {
        self.allowlist
            .read()
            .iter()
            .find(|entry| entry.peer == *peer_id)
            .map(|entry| entry.tier)
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
    ) -> Result<(), PeerstoreError> {
        let requires_proof = payload.tier >= TierLevel::Tl1;
        let Some(public_key_bytes) = payload.vrf_public_key.as_ref() else {
            return if requires_proof {
                Err(PeerstoreError::InvalidVrf {
                    peer: peer_id,
                    reason: "missing vrf public key".into(),
                })
            } else {
                Ok(())
            };
        };
        let Some(proof_bytes) = payload.vrf_proof.as_ref() else {
            return if requires_proof {
                Err(PeerstoreError::InvalidVrf {
                    peer: peer_id,
                    reason: "missing vrf proof".into(),
                })
            } else {
                Ok(())
            };
        };
        if public_key_bytes.is_empty() || proof_bytes.is_empty() {
            return Err(PeerstoreError::InvalidVrf {
                peer: peer_id,
                reason: "empty vrf material".into(),
            });
        }

        if let Some(verifier) = &self.identity_verifier {
            match verifier.expected_vrf_public_key(&payload.zsi_id) {
                Some(expected) => {
                    if expected.as_slice() != public_key_bytes.as_slice() {
                        return Err(PeerstoreError::InvalidVrf {
                            peer: peer_id,
                            reason: "public key mismatch".into(),
                        });
                    }
                }
                None => {
                    return Err(PeerstoreError::InvalidVrf {
                        peer: peer_id,
                        reason: "unknown identity".into(),
                    });
                }
            }
        }

        let public_key = Sr25519PublicKey::from_bytes(public_key_bytes).map_err(|err| {
            PeerstoreError::InvalidVrf {
                peer: peer_id,
                reason: format!("invalid vrf public key: {err}"),
            }
        })?;
        let signature =
            Signature::from_bytes(proof_bytes).map_err(|err| PeerstoreError::InvalidVrf {
                peer: peer_id,
                reason: format!("invalid vrf proof bytes: {err}"),
            })?;
        public_key
            .verify_simple(VRF_HANDSHAKE_CONTEXT, &payload.vrf_message(), &signature)
            .map_err(|err| PeerstoreError::InvalidVrf {
                peer: peer_id,
                reason: format!("verification failed: {err}"),
            })?;
        Ok(())
    }

    fn persist(&self) -> Result<(), PeerstoreError> {
        let Some(path) = &self.path else {
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

    fn persist_access_lists(&self) -> Result<(), PeerstoreError> {
        let Some(path) = &self.access_path else {
            return Ok(());
        };
        let allowlist: Vec<StoredAllowlistEntry> = self
            .allowlist
            .read()
            .iter()
            .map(StoredAllowlistEntry::from)
            .collect();
        let blocklist: Vec<String> = self
            .blocklisted
            .read()
            .iter()
            .map(|peer| peer.to_base58())
            .collect();
        let stored = StoredAccessLists {
            allowlist,
            blocklist,
        };
        let encoded = serde_json::to_string_pretty(&stored)
            .map_err(|err| PeerstoreError::Encoding(err.to_string()))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, encoded)?;
        Ok(())
    }
}

impl Peerstore {
    fn apply_access_control(&self) -> Result<(), PeerstoreError> {
        let allowlist = self.allowlist.read().clone();
        let blocklist: Vec<PeerId> = self.blocklisted.read().iter().cloned().collect();

        if allowlist.is_empty() && blocklist.is_empty() {
            return Ok(());
        }

        {
            let mut guard = self.peers.write();
            for peer in &blocklist {
                let entry = guard.entry(*peer).or_insert_with(|| PeerRecord::new(*peer));
                entry.set_ban(Self::blocklist_ban_until());
            }
            let blocklist: HashSet<PeerId> = blocklist.into_iter().collect();
            for entry in &allowlist {
                let record = guard
                    .entry(entry.peer)
                    .or_insert_with(|| PeerRecord::new(entry.peer));
                record.apply_allowlist_tier(entry.tier);
                if !blocklist.contains(&entry.peer) {
                    record.clear_ban_if_elapsed();
                }
            }
        }
        self.persist()
    }

    pub fn reload_access_lists(
        &self,
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<PeerId>,
    ) -> Result<(), PeerstoreError> {
        let new_blocklisted: HashSet<PeerId> = blocklist.iter().cloned().collect();
        let previous_blocklisted = {
            let mut guard = self.blocklisted.write();
            let previous = guard.clone();
            *guard = new_blocklisted.clone();
            previous
        };

        {
            let mut guard = self.allowlist.write();
            *guard = allowlist.clone();
        }

        {
            let mut peers = self.peers.write();
            for removed in previous_blocklisted.difference(&new_blocklisted) {
                if let Some(record) = peers.get_mut(removed) {
                    record.remove_ban();
                }
            }
            for peer in &new_blocklisted {
                let entry = peers.entry(*peer).or_insert_with(|| PeerRecord::new(*peer));
                entry.set_ban(Self::blocklist_ban_until());
            }
            for entry in &allowlist {
                let record = peers
                    .entry(entry.peer)
                    .or_insert_with(|| PeerRecord::new(entry.peer));
                record.apply_allowlist_tier(entry.tier);
                if !new_blocklisted.contains(&entry.peer) {
                    record.clear_ban_if_elapsed();
                }
            }
        }

        self.persist_access_lists()?;
        self.persist()
    }

    fn blocklist_ban_until() -> SystemTime {
        const YEARS: u64 = 100;
        SystemTime::now() + Duration::from_secs(YEARS * 365 * 24 * 60 * 60)
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
    use crate::handshake::VRF_HANDSHAKE_CONTEXT;
    use crate::vendor::identity;
    use rand::rngs::OsRng;
    use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
    use std::collections::HashMap;
    use std::sync::Arc;
    use tempfile::tempdir;

    #[derive(Default)]
    struct StaticVerifier {
        expected: HashMap<String, Vec<u8>>,
    }

    impl StaticVerifier {
        fn new(entries: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
            Self {
                expected: entries.into_iter().collect(),
            }
        }
    }

    impl IdentityVerifier for StaticVerifier {
        fn expected_vrf_public_key(&self, zsi_id: &str) -> Option<Vec<u8>> {
            self.expected.get(zsi_id).cloned()
        }
    }

    fn sign_vrf_message(secret: &MiniSecretKey, payload: &HandshakePayload) -> Vec<u8> {
        let keypair = secret.expand_to_keypair(ExpansionMode::Uniform);
        keypair
            .sign_simple(VRF_HANDSHAKE_CONTEXT, &payload.vrf_message())
            .to_bytes()
            .to_vec()
    }

    fn signed_handshake(
        keypair: &identity::Keypair,
        zsi: &str,
        tier: TierLevel,
        vrf_secret: Option<&MiniSecretKey>,
    ) -> HandshakePayload {
        let (vrf_public_key, vrf_proof) = if let Some(secret) = vrf_secret {
            let public = secret
                .expand_to_keypair(ExpansionMode::Uniform)
                .public
                .to_bytes()
                .to_vec();
            let template = HandshakePayload::new(zsi.to_string(), Some(public.clone()), None, tier);
            let proof = sign_vrf_message(secret, &template);
            (Some(public), Some(proof))
        } else {
            (None, None)
        };
        let template = HandshakePayload::new(zsi.to_string(), vrf_public_key, vrf_proof, tier);
        template.signed(keypair).expect("sign handshake")
    }

    #[test]
    fn records_and_persists_peer_metadata() {
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("peerstore.json");
        let mut rng = OsRng;
        let secret = MiniSecretKey::generate_with(&mut rng);
        let public = secret
            .expand_to_keypair(ExpansionMode::Uniform)
            .public
            .to_bytes()
            .to_vec();
        let verifier = Arc::new(StaticVerifier::new(vec![(
            "zsi".to_string(),
            public.clone(),
        )]));
        let store = Peerstore::open(
            PeerstoreConfig::persistent(&path).with_identity_verifier(verifier.clone()),
        )
        .expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/1234".parse().unwrap();
        let payload = signed_handshake(&keypair, "zsi", TierLevel::Tl3, Some(&secret));

        store.record_address(peer_id, addr.clone()).expect("addr");
        let outcome = store
            .record_handshake(peer_id, &payload)
            .expect("handshake");
        assert!(matches!(
            outcome,
            HandshakeOutcome::Accepted {
                tier: TierLevel::Tl3,
                ..
            }
        ));

        let loaded =
            Peerstore::open(PeerstoreConfig::persistent(&path).with_identity_verifier(verifier))
                .expect("reload");
        let record = loaded.get(&peer_id).expect("record exists");
        assert_eq!(record.addresses, vec![addr]);
        assert_eq!(record.zsi_id.as_deref(), Some("zsi"));
        assert_eq!(record.vrf_public_key, payload.vrf_public_key);
        assert_eq!(record.vrf_proof, payload.vrf_proof);
        assert_eq!(record.tier, TierLevel::Tl3);
    }

    #[test]
    fn updates_reputation_and_ban_state_across_restart() {
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("peerstore.json");
        let mut rng = OsRng;
        let secret = MiniSecretKey::generate_with(&mut rng);
        let public = secret
            .expand_to_keypair(ExpansionMode::Uniform)
            .public
            .to_bytes()
            .to_vec();
        let verifier = Arc::new(StaticVerifier::new(vec![(
            "peer".to_string(),
            public.clone(),
        )]));
        let store = Peerstore::open(
            PeerstoreConfig::persistent(&path).with_identity_verifier(verifier.clone()),
        )
        .expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let payload = signed_handshake(&keypair, "peer", TierLevel::Tl1, Some(&secret));

        let outcome = store
            .record_handshake(peer_id, &payload)
            .expect("handshake");
        assert!(matches!(
            outcome,
            HandshakeOutcome::Accepted {
                tier: TierLevel::Tl1,
                ..
            }
        ));

        let snapshot = store
            .update_reputation(peer_id, 2.4)
            .expect("update reputation");
        assert_eq!(snapshot.tier, TierLevel::Tl2);
        assert!(snapshot.banned_until.is_none());

        let ban_until = SystemTime::now() + Duration::from_secs(10);
        store.ban_peer_until(peer_id, ban_until).expect("ban peer");

        drop(store);

        let reloaded = Peerstore::open(
            PeerstoreConfig::persistent(&path).with_identity_verifier(verifier.clone()),
        )
        .expect("reload");
        let snapshot = reloaded.reputation_snapshot(&peer_id).expect("snapshot");
        assert_eq!(snapshot.tier, TierLevel::Tl2);
        assert_eq!(snapshot.reputation, 2.4);
        let banned_until = snapshot.banned_until.expect("ban persisted");
        let original = ban_until
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("original duration")
            .as_secs();
        let restored = banned_until
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("restored duration")
            .as_secs();
        assert_eq!(original, restored);

        reloaded.unban_peer(peer_id).expect("unban");
        drop(reloaded);

        let clean =
            Peerstore::open(PeerstoreConfig::persistent(&path).with_identity_verifier(verifier))
                .expect("clean");
        let snapshot = clean.reputation_snapshot(&peer_id).expect("snapshot");
        assert!(snapshot.banned_until.is_none());
    }

    #[test]
    fn rejects_invalid_handshake_signature() {
        let mut rng = OsRng;
        let secret = MiniSecretKey::generate_with(&mut rng);
        let public = secret
            .expand_to_keypair(ExpansionMode::Uniform)
            .public
            .to_bytes()
            .to_vec();
        let verifier = Arc::new(StaticVerifier::new(vec![("peer".to_string(), public)]));
        let store = Peerstore::open(PeerstoreConfig::memory().with_identity_verifier(verifier))
            .expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let mut payload = signed_handshake(&keypair, "peer", TierLevel::Tl2, Some(&secret));
        payload.signature[0] ^= 0x01;

        let result = store.record_handshake(peer_id, &payload);
        assert!(matches!(
            result,
            Err(PeerstoreError::InvalidSignature { peer }) if peer == peer_id
        ));
    }

    #[test]
    fn rejects_invalid_vrf_proof() {
        let mut rng = OsRng;
        let secret = MiniSecretKey::generate_with(&mut rng);
        let public = secret
            .expand_to_keypair(ExpansionMode::Uniform)
            .public
            .to_bytes()
            .to_vec();
        let verifier = Arc::new(StaticVerifier::new(vec![("peer".to_string(), public)]));
        let store = Peerstore::open(PeerstoreConfig::memory().with_identity_verifier(verifier))
            .expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let mut payload = signed_handshake(&keypair, "peer", TierLevel::Tl3, Some(&secret));
        let proof = payload.vrf_proof.as_mut().expect("proof");
        proof[0] ^= 0xFF;
        payload = payload.signed(&keypair).expect("resign");

        let result = store.record_handshake(peer_id, &payload);
        assert!(matches!(
            result,
            Err(PeerstoreError::InvalidVrf { peer, .. }) if peer == peer_id
        ));
    }

    #[test]
    fn rejects_mismatched_vrf_identity() {
        let mut rng = OsRng;
        let secret = MiniSecretKey::generate_with(&mut rng);
        let advertised_public = secret
            .expand_to_keypair(ExpansionMode::Uniform)
            .public
            .to_bytes()
            .to_vec();
        let fake_secret = MiniSecretKey::generate_with(&mut rng);
        let verifier = Arc::new(StaticVerifier::new(vec![(
            "peer".to_string(),
            advertised_public.clone(),
        )]));
        let store = Peerstore::open(PeerstoreConfig::memory().with_identity_verifier(verifier))
            .expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let payload = signed_handshake(&keypair, "peer", TierLevel::Tl2, Some(&fake_secret));

        let result = store.record_handshake(peer_id, &payload);
        assert!(matches!(
            result,
            Err(PeerstoreError::InvalidVrf { peer, .. }) if peer == peer_id
        ));
    }

    #[test]
    fn rejects_missing_vrf_for_high_tier() {
        let verifier = Arc::new(StaticVerifier::default());
        let store = Peerstore::open(PeerstoreConfig::memory().with_identity_verifier(verifier))
            .expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let payload = signed_handshake(&keypair, "peer", TierLevel::Tl2, None);

        let result = store.record_handshake(peer_id, &payload);
        assert!(matches!(
            result,
            Err(PeerstoreError::InvalidVrf { peer, .. }) if peer == peer_id
        ));
    }

    #[test]
    fn accepts_low_tier_without_vrf_proof() {
        let store = Peerstore::open(PeerstoreConfig::memory()).expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let payload = signed_handshake(&keypair, "peer", TierLevel::Tl0, None);

        let outcome = store
            .record_handshake(peer_id, &payload)
            .expect("handshake should be accepted");
        assert!(matches!(
            outcome,
            HandshakeOutcome::Accepted {
                tier: TierLevel::Tl0,
                ..
            }
        ));
    }

    #[test]
    fn accepts_valid_vrf_without_identity_verifier() {
        let mut rng = OsRng;
        let secret = MiniSecretKey::generate_with(&mut rng);
        let store = Peerstore::open(PeerstoreConfig::memory()).expect("open");
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());
        let payload = signed_handshake(&keypair, "peer", TierLevel::Tl3, Some(&secret));

        let outcome = store
            .record_handshake(peer_id, &payload)
            .expect("handshake should be accepted");
        assert!(matches!(
            outcome,
            HandshakeOutcome::Accepted {
                tier: TierLevel::Tl3,
                ..
            }
        ));
    }

    #[test]
    fn ping_metrics_are_tracked_in_memory() {
        let store = Peerstore::open(PeerstoreConfig::memory()).expect("open");
        let peer = PeerId::random();

        let first = store.record_ping_failure(peer).expect("failure count");
        assert_eq!(first, 1);
        let second = store.record_ping_failure(peer).expect("failure count");
        assert_eq!(second, 2);

        store
            .record_ping_success(peer, Duration::from_millis(37))
            .expect("success");

        let record = store.get(&peer).expect("record");
        assert_eq!(record.ping_failures, 0);
        assert_eq!(record.last_ping_rtt, Some(Duration::from_millis(37)));
        assert!(record.last_seen.is_some());
    }

    #[test]
    fn ping_metrics_survive_persistence_roundtrip() {
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("peerstore.json");
        let store = Peerstore::open(PeerstoreConfig::persistent(&path)).expect("open");
        let peer = PeerId::random();

        store.record_ping_failure(peer).expect("failure recorded");
        store
            .record_ping_success(peer, Duration::from_millis(12))
            .expect("success");
        drop(store);

        let reloaded = Peerstore::open(PeerstoreConfig::persistent(&path)).expect("reload");
        let record = reloaded.get(&peer).expect("record");
        assert_eq!(record.ping_failures, 0);
        assert_eq!(record.last_ping_rtt, Some(Duration::from_millis(12)));
    }

    #[test]
    fn known_peers_exposes_records() {
        let store = Peerstore::open(PeerstoreConfig::memory()).expect("open");
        let peer = PeerId::random();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/12345".parse().expect("addr");
        store.record_address(peer, addr.clone()).expect("address");

        let known = store.known_peers();
        assert!(known.iter().any(|record| record.peer_id == peer));
        let entry = known
            .into_iter()
            .find(|record| record.peer_id == peer)
            .expect("record");
        assert!(entry.addresses.contains(&addr));
    }
}
