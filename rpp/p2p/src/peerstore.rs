use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::vendor::core::multihash::Multihash;
use crate::vendor::{identity, Multiaddr, PeerId};
use base64::{engine::general_purpose, Engine as _};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, info, warn};

use crate::handshake::{
    emit_handshake_telemetry, HandshakeOutcome, HandshakePayload, TelemetryMetadata,
    VRF_HANDSHAKE_CONTEXT,
};
use crate::policy_log::{
    AdmissionApprovalRecord, AdmissionPolicyChange, AdmissionPolicyLog, AdmissionPolicyLogEntry,
    AdmissionPolicyLogError, PolicyAllowlistState,
};
use crate::policy_signing::{PolicySignature, PolicySigner, PolicySigningError};
use crate::tier::TierLevel;
use schnorrkel::{keys::PublicKey as Sr25519PublicKey, Signature};

#[derive(Debug, Error)]
pub enum PeerstoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("admission audit log error: {0}")]
    AuditLog(#[from] AdmissionPolicyLogError),
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
    #[error("high-impact admission policy change missing approvals: {missing:?}")]
    MissingApprovals { missing: Vec<String> },
    #[error("admission policy backups are disabled")]
    PolicyBackupsDisabled,
    #[error("admission policy backup {name} not found")]
    PolicyBackupNotFound { name: String },
    #[error("failed to parse admission policy backup {name}")]
    PolicyBackupInvalid { name: String },
    #[error("policy signing error: {0}")]
    PolicySigning(#[from] PolicySigningError),
    #[error("admission policy log entry {id} missing signature")]
    MissingLogSignature { id: u64 },
}

pub trait IdentityVerifier: Send + Sync {
    fn expected_vrf_public_key(&self, zsi_id: &str) -> Option<Vec<u8>>;
}

const DEFAULT_POLICY_BACKUP_PREFIX: &str = "admission_policies";

#[derive(Debug, Clone)]
pub struct AdmissionPolicyBackup {
    pub name: String,
    pub timestamp_ms: u64,
    pub size: u64,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default, Debug, Clone, Serialize, Deserialize)]
struct StoredAccessLists {
    #[serde(default)]
    allowlist: Vec<StoredAllowlistEntry>,
    #[serde(default)]
    blocklist: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signature: Option<PolicySignature>,
}

impl StoredAccessLists {
    fn canonical_bytes(&self) -> Result<Vec<u8>, PeerstoreError> {
        let mut clone = self.clone();
        clone.signature = None;
        serde_json::to_vec(&clone).map_err(|err| PeerstoreError::Encoding(err.to_string()))
    }

    fn into_lists(self) -> Result<(Vec<AllowlistedPeer>, Vec<PeerId>), PeerstoreError> {
        let allowlist = self
            .allowlist
            .into_iter()
            .map(AllowlistedPeer::try_from)
            .collect::<Result<Vec<_>, PeerstoreError>>()?;
        let blocklist = self
            .blocklist
            .into_iter()
            .map(|peer| {
                PeerId::from_str(&peer).map_err(|err| PeerstoreError::Encoding(err.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((allowlist, blocklist))
    }
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

#[derive(Debug, Clone)]
pub struct AdmissionPolicies {
    pub allowlist: Vec<AllowlistedPeer>,
    pub blocklist: Vec<PeerId>,
    pub signature: Option<PolicySignature>,
}

impl AdmissionPolicies {
    pub fn new(
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<PeerId>,
        signature: Option<PolicySignature>,
    ) -> Self {
        Self {
            allowlist,
            blocklist,
            signature,
        }
    }

    pub fn allowlist(&self) -> &[AllowlistedPeer] {
        &self.allowlist
    }

    pub fn blocklist(&self) -> &[PeerId] {
        &self.blocklist
    }

    pub fn signature(&self) -> Option<&PolicySignature> {
        self.signature.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmissionApproval {
    role: String,
    approver: String,
}

impl AdmissionApproval {
    pub fn new(role: impl Into<String>, approver: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            approver: approver.into(),
        }
    }

    pub fn role(&self) -> &str {
        self.role.as_str()
    }

    pub fn approver(&self) -> &str {
        self.approver.as_str()
    }
}

#[derive(Debug, Clone)]
pub struct AdmissionAuditTrail {
    actor: String,
    reason: Option<String>,
    approvals: Vec<AdmissionApproval>,
}

impl AdmissionAuditTrail {
    pub fn new(actor: impl Into<String>, reason: Option<impl Into<String>>) -> Self {
        Self {
            actor: actor.into(),
            reason: reason.map(|value| value.into()),
            approvals: Vec::new(),
        }
    }

    pub fn with_approvals(mut self, approvals: Vec<AdmissionApproval>) -> Self {
        self.approvals = approvals;
        self
    }

    pub fn system(reason: impl Into<String>) -> Self {
        Self {
            actor: "system".into(),
            reason: Some(reason.into()),
            approvals: Vec::new(),
        }
    }

    pub fn actor(&self) -> &str {
        self.actor.as_str()
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    pub fn approvals(&self) -> &[AdmissionApproval] {
        &self.approvals
    }

    pub fn missing_roles<'a, I>(&self, roles: I) -> Vec<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        roles
            .into_iter()
            .filter(|role| !self.has_role(role))
            .map(|role| role.to_string())
            .collect()
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.approvals
            .iter()
            .any(|approval| approval.role.eq_ignore_ascii_case(role))
    }

    fn is_system(&self) -> bool {
        self.actor == "system"
    }
}

pub struct PeerstoreConfig {
    path: Option<PathBuf>,
    access_path: Option<PathBuf>,
    audit_log_path: Option<PathBuf>,
    identity_verifier: Option<Arc<dyn IdentityVerifier>>,
    allowlist: Vec<AllowlistedPeer>,
    blocklist: Vec<PeerId>,
    policy_backup_dir: Option<PathBuf>,
    policy_backup_retention: Option<Duration>,
    policy_signer: Option<PolicySigner>,
}

impl fmt::Debug for PeerstoreConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerstoreConfig")
            .field("path", &self.path)
            .field("access_path", &self.access_path)
            .field("audit_log_path", &self.audit_log_path)
            .field("allowlist", &self.allowlist)
            .field("blocklist", &self.blocklist)
            .field("policy_backup_dir", &self.policy_backup_dir)
            .field("policy_backup_retention", &self.policy_backup_retention)
            .field("policy_signer", &self.policy_signer.is_some())
            .finish()
    }
}

impl PeerstoreConfig {
    pub fn memory() -> Self {
        Self {
            path: None,
            access_path: None,
            audit_log_path: None,
            identity_verifier: None,
            allowlist: Vec::new(),
            blocklist: Vec::new(),
            policy_backup_dir: None,
            policy_backup_retention: None,
            policy_signer: None,
        }
    }

    pub fn persistent(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let access_path = path.with_extension("access.json");
        let audit_log_path = path.with_extension("audit.jsonl");
        Self {
            access_path: Some(access_path),
            audit_log_path: Some(audit_log_path),
            path: Some(path),
            identity_verifier: None,
            allowlist: Vec::new(),
            blocklist: Vec::new(),
            policy_backup_dir: None,
            policy_backup_retention: None,
            policy_signer: None,
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

    pub fn with_access_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.access_path = Some(path.into());
        self
    }

    pub fn with_policy_backups(mut self, dir: impl Into<PathBuf>, retention: Duration) -> Self {
        self.policy_backup_dir = Some(dir.into());
        self.policy_backup_retention = Some(retention);
        self
    }

    pub fn with_audit_log_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.audit_log_path = Some(path.into());
        self
    }

    pub fn with_policy_signer(mut self, signer: PolicySigner) -> Self {
        self.policy_signer = Some(signer);
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
    audit_log: Option<Arc<AdmissionPolicyLog>>,
    peers: RwLock<HashMap<PeerId, PeerRecord>>,
    identity_verifier: Option<Arc<dyn IdentityVerifier>>,
    allowlist: RwLock<Vec<AllowlistedPeer>>,
    blocklisted: RwLock<HashSet<PeerId>>,
    policy_backup_dir: Option<PathBuf>,
    policy_backup_retention: Option<Duration>,
    policy_backup_prefix: Option<String>,
    policy_signer: Option<PolicySigner>,
    policy_signature: RwLock<Option<PolicySignature>>,
}

impl fmt::Debug for Peerstore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peerstore")
            .field("path", &self.path)
            .field("access_path", &self.access_path)
            .field("audit_log", &self.audit_log.is_some())
            .field("identity_verifier", &self.identity_verifier.is_some())
            .field("allowlist_len", &self.allowlist.read().len())
            .field("blocklisted_len", &self.blocklisted.read().len())
            .field("policy_backup_dir", &self.policy_backup_dir)
            .field("policy_backup_retention", &self.policy_backup_retention)
            .field("policy_signer", &self.policy_signer.is_some())
            .finish()
    }
}

impl Peerstore {
    pub fn open(config: PeerstoreConfig) -> Result<Self, PeerstoreError> {
        let PeerstoreConfig {
            path,
            access_path,
            audit_log_path,
            identity_verifier,
            allowlist: configured_allowlist,
            blocklist: configured_blocklist,
            policy_backup_dir,
            policy_backup_retention,
            policy_signer,
        } = config;

        let peers = if let Some(path_ref) = &path {
            if path_ref.exists() {
                let raw = fs::read_to_string(path_ref)?;
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
                if let Some(parent) = path_ref.parent() {
                    fs::create_dir_all(parent)?;
                }
                HashMap::new()
            }
        } else {
            HashMap::new()
        };

        let access_path =
            access_path.or_else(|| path.as_ref().map(|path| path.with_extension("access.json")));

        let audit_log_path = audit_log_path.or_else(|| {
            access_path
                .as_ref()
                .map(|path| path.with_extension("audit.jsonl"))
                .or_else(|| path.as_ref().map(|path| path.with_extension("audit.jsonl")))
        });

        let audit_log = match audit_log_path {
            Some(path) => Some(Arc::new(AdmissionPolicyLog::open(path)?)),
            None => None,
        };

        let mut snapshot_signature: Option<PolicySignature> = None;
        let signer_ref = policy_signer.as_ref();
        let (allowlist, blocklisted) = if let Some(access_path) = &access_path {
            if access_path.exists() {
                let raw = fs::read_to_string(access_path)?;
                let stored: StoredAccessLists = serde_json::from_str(&raw)
                    .map_err(|err| PeerstoreError::Encoding(err.to_string()))?;
                let (allowlist, blocklist_vec, signature) =
                    Self::decode_access_lists(stored, signer_ref)?;
                snapshot_signature = signature;
                let blocklisted = blocklist_vec.into_iter().collect::<HashSet<_>>();
                (allowlist, blocklisted)
            } else {
                (
                    configured_allowlist.clone(),
                    configured_blocklist.iter().cloned().collect(),
                )
            }
        } else {
            (
                configured_allowlist.clone(),
                configured_blocklist.iter().cloned().collect(),
            )
        };

        let policy_backup_prefix = access_path
            .as_ref()
            .and_then(|path| path.file_stem())
            .and_then(|stem| stem.to_str())
            .map(|value| value.to_string());

        let store = Self {
            path,
            access_path,
            audit_log,
            identity_verifier,
            peers: RwLock::new(peers),
            allowlist: RwLock::new(allowlist),
            blocklisted: RwLock::new(blocklisted),
            policy_backup_dir,
            policy_backup_retention,
            policy_backup_prefix,
            policy_signer,
            policy_signature: RwLock::new(snapshot_signature),
        };
        store.apply_access_control()?;
        store.persist_access_lists(false)?;
        Ok(store)
    }

    pub fn admission_policies(&self) -> AdmissionPolicies {
        let allowlist = self.allowlist.read().clone();
        let blocklist = self.blocklisted.read().iter().cloned().collect::<Vec<_>>();
        let signature = self.policy_signature.read().clone();
        AdmissionPolicies::new(allowlist, blocklist, signature)
    }

    pub fn admission_audit_entries(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<AdmissionPolicyLogEntry>, usize), PeerstoreError> {
        match &self.audit_log {
            Some(log) => {
                let (entries, total) = log.read(offset, limit).map_err(PeerstoreError::from)?;
                self.verify_log_entries(&entries)?;
                Ok((entries, total))
            }
            None => Ok((Vec::new(), 0)),
        }
    }

    pub fn admission_policy_backups(&self) -> Result<Vec<AdmissionPolicyBackup>, PeerstoreError> {
        let dir = self
            .policy_backup_dir
            .as_ref()
            .ok_or(PeerstoreError::PolicyBackupsDisabled)?;
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let prefix = self.policy_backup_prefix();
        let mut backups = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => continue,
            };
            if !Self::is_valid_backup_name(&name, prefix) {
                continue;
            }
            let Some(timestamp) = Self::parse_backup_timestamp(&name) else {
                continue;
            };
            let size = entry.metadata()?.len();
            let timestamp_ms = if timestamp > u128::from(u64::MAX) {
                u64::MAX
            } else {
                timestamp as u64
            };
            backups.push(AdmissionPolicyBackup {
                name,
                timestamp_ms,
                size,
            });
        }
        backups.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        Ok(backups)
    }

    pub fn admission_policy_backup_contents(&self, name: &str) -> Result<Vec<u8>, PeerstoreError> {
        let dir = self
            .policy_backup_dir
            .as_ref()
            .ok_or(PeerstoreError::PolicyBackupsDisabled)?;
        let prefix = self.policy_backup_prefix();
        if !Self::is_valid_backup_name(name, prefix) {
            return Err(PeerstoreError::PolicyBackupNotFound {
                name: name.to_string(),
            });
        }
        let path = dir.join(name);
        if !path.exists() {
            return Err(PeerstoreError::PolicyBackupNotFound {
                name: name.to_string(),
            });
        }
        Ok(fs::read(path)?)
    }

    pub fn restore_admission_policies_from_backup(
        &self,
        name: &str,
        audit: AdmissionAuditTrail,
    ) -> Result<(), PeerstoreError> {
        let data = self.admission_policy_backup_contents(name)?;
        let stored: StoredAccessLists = serde_json::from_slice(&data)
            .map_err(|err| PeerstoreError::Encoding(err.to_string()))?;
        let (allowlist, blocklist, _) =
            Self::decode_access_lists(stored, self.policy_signer.as_ref())?;
        self.commit_access_lists(allowlist, blocklist, audit)
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
        self.persist_access_lists(false)?;
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

    fn persist_access_lists(&self, create_backup: bool) -> Result<(), PeerstoreError> {
        let Some(path) = &self.access_path else {
            return Ok(());
        };
        let allowlist: Vec<StoredAllowlistEntry> = self
            .allowlist
            .read()
            .iter()
            .map(StoredAllowlistEntry::from)
            .collect();
        let mut blocklist: Vec<String> = self
            .blocklisted
            .read()
            .iter()
            .map(|peer| peer.to_base58())
            .collect();
        blocklist.sort();
        let mut stored = StoredAccessLists {
            allowlist,
            blocklist,
            signature: None,
        };
        if let Some(signer) = self.policy_signer.as_ref() {
            let message = stored.canonical_bytes()?;
            let signature = signer.sign(&message)?;
            stored.signature = Some(signature);
        }
        let current_signature = stored.signature.clone();
        let encoded = serde_json::to_string_pretty(&stored)
            .map_err(|err| PeerstoreError::Encoding(err.to_string()))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, &encoded)?;
        if create_backup {
            self.snapshot_admission_policies(&encoded)?;
        }
        *self.policy_signature.write() = current_signature;
        Ok(())
    }

    fn snapshot_admission_policies(&self, contents: &str) -> Result<(), PeerstoreError> {
        let Some(dir) = &self.policy_backup_dir else {
            return Ok(());
        };
        let prefix = self.policy_backup_prefix();
        fs::create_dir_all(dir)?;
        let mut timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        loop {
            let filename = format!("{prefix}-{timestamp}.json");
            if !Self::is_valid_backup_name(&filename, prefix) {
                timestamp += 1;
                continue;
            }
            let path = dir.join(&filename);
            if path.exists() {
                timestamp += 1;
                continue;
            }
            fs::write(&path, contents)?;
            break;
        }
        self.prune_policy_backups(dir, prefix)?;
        Ok(())
    }

    fn prune_policy_backups(&self, dir: &Path, prefix: &str) -> Result<(), PeerstoreError> {
        let Some(retention) = self.policy_backup_retention else {
            return Ok(());
        };
        let cutoff_time = SystemTime::now()
            .checked_sub(retention)
            .unwrap_or(UNIX_EPOCH);
        let cutoff_ms = cutoff_time
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = match entry.file_name().into_string() {
                Ok(name) => name,
                Err(_) => continue,
            };
            if !Self::is_valid_backup_name(&name, prefix) {
                continue;
            }
            let Some(timestamp) = Self::parse_backup_timestamp(&name) else {
                continue;
            };
            if timestamp < cutoff_ms {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }

    fn policy_backup_prefix(&self) -> &str {
        self.policy_backup_prefix
            .as_deref()
            .unwrap_or(DEFAULT_POLICY_BACKUP_PREFIX)
    }

    fn decode_access_lists(
        stored: StoredAccessLists,
        signer: Option<&PolicySigner>,
    ) -> Result<(Vec<AllowlistedPeer>, Vec<PeerId>, Option<PolicySignature>), PeerstoreError> {
        let signature = stored.signature.clone();
        let canonical = stored.canonical_bytes()?;
        let (allowlist, blocklist) = stored.into_lists()?;
        if let Some(signer) = signer {
            if let Some(signature) = signature {
                signer.verify(&signature, &canonical)?;
                Ok((allowlist, blocklist, Some(signature)))
            } else {
                warn!(
                    target: "telemetry.admission",
                    "admission snapshot missing signature; scheduling re-sign"
                );
                Ok((allowlist, blocklist, None))
            }
        } else {
            Ok((allowlist, blocklist, signature))
        }
    }

    fn verify_log_entries(
        &self,
        entries: &[AdmissionPolicyLogEntry],
    ) -> Result<(), PeerstoreError> {
        let Some(signer) = self.policy_signer.as_ref() else {
            return Ok(());
        };
        for entry in entries {
            let signature = entry
                .signature
                .as_ref()
                .ok_or(PeerstoreError::MissingLogSignature { id: entry.id })?;
            let message = entry.canonical_bytes().map_err(PeerstoreError::from)?;
            signer.verify(signature, &message)?;
        }
        Ok(())
    }

    fn is_valid_backup_name(name: &str, prefix: &str) -> bool {
        !name.contains('/')
            && !name.contains("\\")
            && name.starts_with(prefix)
            && Self::parse_backup_timestamp(name).is_some()
    }

    fn parse_backup_timestamp(name: &str) -> Option<u128> {
        let (_, suffix) = name.rsplit_once('-')?;
        let value = suffix.strip_suffix(".json")?;
        value.parse().ok()
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
        self.commit_access_lists(
            allowlist,
            blocklist,
            AdmissionAuditTrail::system("peerstore.reload_access_lists"),
        )
    }

    pub fn update_admission_policies(
        &self,
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<PeerId>,
        audit: AdmissionAuditTrail,
    ) -> Result<(), PeerstoreError> {
        self.commit_access_lists(allowlist, blocklist, audit)
    }

    fn append_policy_change(
        &self,
        actor: &str,
        reason: Option<&str>,
        approvals: &[AdmissionApproval],
        change: AdmissionPolicyChange,
    ) -> Result<(), PeerstoreError> {
        if let Some(log) = &self.audit_log {
            let reason_owned = reason.map(|value| value.to_string());
            let reason_ref = reason_owned.as_deref();
            let approval_records: Vec<AdmissionApprovalRecord> = approvals
                .iter()
                .map(|approval| AdmissionApprovalRecord::new(approval.role(), approval.approver()))
                .collect();
            if let Err(err) = log.append(
                actor,
                reason_ref,
                &approval_records,
                change,
                self.policy_signer.as_ref(),
            ) {
                let label = reason_ref.unwrap_or("n/a");
                error!(
                    target: "telemetry.admission",
                    actor = %actor,
                    reason = %label,
                    error = %err,
                    "failed to append admission audit log"
                );
                return Err(err.into());
            }
        }
        Ok(())
    }

    fn commit_access_lists(
        &self,
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<PeerId>,
        audit: AdmissionAuditTrail,
    ) -> Result<(), PeerstoreError> {
        let new_blocklisted: HashSet<PeerId> = blocklist.iter().cloned().collect();
        let previous_blocklisted = self.blocklisted.read().clone();
        let previous_allowlist = self.allowlist.read().clone();

        let high_impact = Self::policies_differ(
            &previous_allowlist,
            &allowlist,
            &previous_blocklisted,
            &new_blocklisted,
        );

        if high_impact && !audit.is_system() {
            let missing = audit.missing_roles(["operations", "security"]);
            if !missing.is_empty() {
                return Err(PeerstoreError::MissingApprovals { missing });
            }
        }

        {
            let mut guard = self.blocklisted.write();
            *guard = new_blocklisted.clone();
        }
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

        self.persist_access_lists(high_impact)?;
        self.persist()?;

        self.emit_admission_audit(
            &audit,
            &previous_allowlist,
            &allowlist,
            &previous_blocklisted,
            &new_blocklisted,
        )?;

        Ok(())
    }

    fn emit_admission_audit(
        &self,
        audit: &AdmissionAuditTrail,
        previous_allowlist: &[AllowlistedPeer],
        next_allowlist: &[AllowlistedPeer],
        previous_blocklisted: &HashSet<PeerId>,
        next_blocklisted: &HashSet<PeerId>,
    ) -> Result<(), PeerstoreError> {
        let actor = audit.actor();
        let reason = audit.reason().unwrap_or("n/a");
        let previous_map: HashMap<PeerId, TierLevel> = previous_allowlist
            .iter()
            .map(|entry| (entry.peer, entry.tier))
            .collect();
        let next_map: HashMap<PeerId, TierLevel> = next_allowlist
            .iter()
            .map(|entry| (entry.peer, entry.tier))
            .collect();
        let mut mutated = false;

        for (peer, new_tier) in &next_map {
            match previous_map.get(peer) {
                None => {
                    mutated = true;
                    self.append_policy_change(
                        actor,
                        audit.reason(),
                        audit.approvals(),
                        AdmissionPolicyChange::Allowlist {
                            previous: None,
                            current: Some(PolicyAllowlistState::new(peer.clone(), *new_tier)),
                        },
                    )?;
                    info!(
                        target: "telemetry.admission",
                        actor = %actor,
                        reason,
                        peer = %peer.to_base58(),
                        tier = ?new_tier,
                        "admission_allowlist_added"
                    );
                }
                Some(old_tier) if old_tier != new_tier => {
                    mutated = true;
                    self.append_policy_change(
                        actor,
                        audit.reason(),
                        audit.approvals(),
                        AdmissionPolicyChange::Allowlist {
                            previous: Some(PolicyAllowlistState::new(peer.clone(), *old_tier)),
                            current: Some(PolicyAllowlistState::new(peer.clone(), *new_tier)),
                        },
                    )?;
                    info!(
                        target: "telemetry.admission",
                        actor = %actor,
                        reason,
                        peer = %peer.to_base58(),
                        previous_tier = ?old_tier,
                        tier = ?new_tier,
                        "admission_allowlist_updated"
                    );
                }
                _ => {}
            }
        }

        for (peer, old_tier) in &previous_map {
            if !next_map.contains_key(peer) {
                mutated = true;
                self.append_policy_change(
                    actor,
                    audit.reason(),
                    audit.approvals(),
                    AdmissionPolicyChange::Allowlist {
                        previous: Some(PolicyAllowlistState::new(peer.clone(), *old_tier)),
                        current: None,
                    },
                )?;
                info!(
                    target: "telemetry.admission",
                    actor = %actor,
                    reason,
                    peer = %peer.to_base58(),
                    previous_tier = ?old_tier,
                    "admission_allowlist_removed"
                );
            }
        }

        for peer in next_blocklisted {
            if !previous_blocklisted.contains(peer) {
                mutated = true;
                self.append_policy_change(
                    actor,
                    audit.reason(),
                    audit.approvals(),
                    AdmissionPolicyChange::Blocklist {
                        peer_id: peer.to_base58(),
                        previous: false,
                        current: true,
                    },
                )?;
                info!(
                    target: "telemetry.admission",
                    actor = %actor,
                    reason,
                    peer = %peer.to_base58(),
                    "admission_blocklist_added"
                );
            }
        }

        for peer in previous_blocklisted {
            if !next_blocklisted.contains(peer) {
                mutated = true;
                self.append_policy_change(
                    actor,
                    audit.reason(),
                    audit.approvals(),
                    AdmissionPolicyChange::Blocklist {
                        peer_id: peer.to_base58(),
                        previous: true,
                        current: false,
                    },
                )?;
                info!(
                    target: "telemetry.admission",
                    actor = %actor,
                    reason,
                    peer = %peer.to_base58(),
                    "admission_blocklist_removed"
                );
            }
        }

        if !mutated {
            self.append_policy_change(
                actor,
                audit.reason(),
                audit.approvals(),
                AdmissionPolicyChange::Noop,
            )?;
            info!(
                target: "telemetry.admission",
                actor = %actor,
                reason,
                "admission_policies_unchanged"
            );
        }
        Ok(())
    }

    fn policies_differ(
        previous_allowlist: &[AllowlistedPeer],
        next_allowlist: &[AllowlistedPeer],
        previous_blocklisted: &HashSet<PeerId>,
        next_blocklisted: &HashSet<PeerId>,
    ) -> bool {
        if previous_blocklisted != next_blocklisted {
            return true;
        }
        Self::allowlist_map(previous_allowlist) != Self::allowlist_map(next_allowlist)
    }

    fn allowlist_map(entries: &[AllowlistedPeer]) -> BTreeMap<PeerId, TierLevel> {
        let mut map = BTreeMap::new();
        for entry in entries {
            map.insert(entry.peer, entry.tier);
        }
        map
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
    use crate::policy_log::{AdmissionPolicyChange, AdmissionPolicyLogEntry, PolicyAllowlistState};
    use crate::vendor::identity;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn build_policy_signer(dir: &Path, key_id: &str) -> PolicySigner {
        let key_path = dir.join(format!("{key_id}.toml"));
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        let secret_hex = hex::encode(signing_key.to_bytes());
        let public_hex = hex::encode(verifying_key.to_bytes());
        let key_toml = format!("secret_key = \"{secret_hex}\"\npublic_key = \"{public_hex}\"\n");
        fs::write(&key_path, key_toml).expect("write signing key");

        let mut trust_map = HashMap::new();
        trust_map.insert(key_id.to_string(), public_hex);
        let trust_store = PolicyTrustStore::from_hex(trust_map).expect("trust store");
        PolicySigner::with_filesystem_key(key_id.to_string(), key_path, trust_store)
            .expect("policy signer")
    }

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
    fn persists_signed_snapshot_when_signer_configured() {
        let dir = tempdir().expect("tmp");
        let peerstore_path = dir.path().join("peerstore.json");
        let access_path = dir.path().join("access.json");
        let signer = build_policy_signer(dir.path(), "test-key");
        let verifier = signer.verifier().clone();

        let store = Peerstore::open(
            PeerstoreConfig::persistent(&peerstore_path)
                .with_access_path(&access_path)
                .with_policy_signer(signer),
        )
        .expect("open peerstore");

        store
            .update_admission_policies(Vec::new(), Vec::new(), AdmissionAuditTrail::system("test"))
            .expect("update policies");

        let raw = fs::read_to_string(&access_path).expect("read snapshot");
        let stored: StoredAccessLists = serde_json::from_str(&raw).expect("decode snapshot");
        let signature = stored.signature.clone().expect("missing signature");
        let canonical = stored.canonical_bytes().expect("canonical snapshot");
        verifier
            .verify(&signature, &canonical)
            .expect("verify signature");
    }

    #[test]
    fn verifies_audit_log_signatures_when_signer_configured() {
        let dir = tempdir().expect("tmp");
        let peerstore_path = dir.path().join("peerstore.json");
        let access_path = dir.path().join("access.json");
        let audit_path = dir.path().join("audit.jsonl");
        let signer = build_policy_signer(dir.path(), "audit-key");

        let store = Peerstore::open(
            PeerstoreConfig::persistent(&peerstore_path)
                .with_access_path(&access_path)
                .with_audit_log_path(&audit_path)
                .with_policy_signer(signer),
        )
        .expect("open peerstore");

        let log = store.audit_log.as_ref().expect("audit log");
        let entry = log
            .append(
                "actor",
                Some("reason"),
                &[AdmissionApprovalRecord::new("role", "approver")],
                AdmissionPolicyChange::Noop,
                store.policy_signer.as_ref(),
            )
            .expect("append audit");

        store
            .verify_log_entries(&[entry])
            .expect("verify audit signatures");
    }

    #[test]
    fn rejects_audit_log_entries_without_signature() {
        let dir = tempdir().expect("tmp");
        let peerstore_path = dir.path().join("peerstore.json");
        let access_path = dir.path().join("access.json");
        let audit_path = dir.path().join("audit.jsonl");
        let signer = build_policy_signer(dir.path(), "missing-sig-key");

        let store = Peerstore::open(
            PeerstoreConfig::persistent(&peerstore_path)
                .with_access_path(&access_path)
                .with_audit_log_path(&audit_path)
                .with_policy_signer(signer),
        )
        .expect("open peerstore");

        let entry = AdmissionPolicyLogEntry {
            id: 42,
            timestamp_ms: 1,
            actor: "actor".into(),
            reason: None,
            change: AdmissionPolicyChange::Allowlist {
                previous: None,
                current: Some(PolicyAllowlistState::new(PeerId::random(), TierLevel::Tl2)),
            },
            approvals: vec![],
            signature: None,
        };

        let result = store.verify_log_entries(&[entry]);
        assert!(matches!(
            result,
            Err(PeerstoreError::MissingLogSignature { id }) if id == 42
        ));
    }

    #[test]
    fn rejects_audit_log_entries_with_tampered_signature() {
        let dir = tempdir().expect("tmp");
        let peerstore_path = dir.path().join("peerstore.json");
        let access_path = dir.path().join("access.json");
        let audit_path = dir.path().join("audit.jsonl");
        let signer = build_policy_signer(dir.path(), "invalid-sig-key");

        let store = Peerstore::open(
            PeerstoreConfig::persistent(&peerstore_path)
                .with_access_path(&access_path)
                .with_audit_log_path(&audit_path)
                .with_policy_signer(signer.clone()),
        )
        .expect("open peerstore");

        let log = store.audit_log.as_ref().expect("audit log");
        let mut entry = log
            .append(
                "actor",
                None,
                &[],
                AdmissionPolicyChange::Blocklist {
                    peer_id: "peer".into(),
                    previous: false,
                    current: true,
                },
                store.policy_signer.as_ref(),
            )
            .expect("append audit");
        let signature = entry.signature.as_mut().expect("signature");
        signature.value = "00".repeat(64);

        let result = store.verify_log_entries(&[entry]);
        assert!(matches!(result, Err(PeerstoreError::PolicySigning(_))));
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

    #[test]
    fn audit_log_records_allowlist_changes() {
        let dir = tempdir().expect("tmp");
        let path = dir.path().join("peerstore.json");
        let store = Peerstore::open(PeerstoreConfig::persistent(&path)).expect("open");
        let peer = PeerId::random();
        let allowlist = vec![AllowlistedPeer {
            peer: peer.clone(),
            tier: TierLevel::Tl3,
        }];

        store
            .update_admission_policies(
                allowlist,
                Vec::new(),
                AdmissionAuditTrail::new("operator", Some("initial rollout")).with_approvals(vec![
                    AdmissionApproval::new("operations", "operator"),
                    AdmissionApproval::new("security", "operator"),
                ]),
            )
            .expect("policy update");

        let (entries, total) = store.admission_audit_entries(0, 32).expect("audit log");
        assert!(total >= 1);
        let last = entries.last().expect("entry");
        assert_eq!(last.actor, "operator");
        assert_eq!(
            last.approvals,
            vec![
                AdmissionApprovalRecord::new("operations", "operator"),
                AdmissionApprovalRecord::new("security", "operator"),
            ]
        );
        match &last.change {
            AdmissionPolicyChange::Allowlist { current, .. } => {
                let current = current.as_ref().expect("current state");
                assert_eq!(current.peer_id, peer.to_base58());
                assert_eq!(current.tier, TierLevel::Tl3);
            }
            change => panic!("unexpected audit change: {change:?}"),
        }
    }

    #[test]
    fn audit_trail_reports_missing_roles() {
        let audit = AdmissionAuditTrail::new("operator", Some("test"))
            .with_approvals(vec![AdmissionApproval::new("operations", "ops.oncall")]);
        let missing = audit.missing_roles(["operations", "security"]);
        assert_eq!(missing, vec!["security".to_string()]);
        assert!(audit.has_role("operations"));
        assert!(!audit.has_role("security"));
    }

    #[test]
    fn peerstore_requires_dual_approvals_for_high_impact_changes() {
        let store = Peerstore::open(PeerstoreConfig::memory()).expect("open");
        let peer = PeerId::random();
        let allowlist = vec![AllowlistedPeer {
            peer: peer.clone(),
            tier: TierLevel::Tl3,
        }];

        let audit = AdmissionAuditTrail::new("operator", Some("ops rotation"))
            .with_approvals(vec![AdmissionApproval::new("operations", "ops.oncall")]);
        let err = store
            .update_admission_policies(allowlist.clone(), Vec::new(), audit)
            .expect_err("missing approvals should reject update");
        match err {
            PeerstoreError::MissingApprovals { missing } => {
                assert_eq!(missing, vec!["security".to_string()]);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let audit =
            AdmissionAuditTrail::new("operator", Some("ops rotation")).with_approvals(vec![
                AdmissionApproval::new("operations", "ops.oncall"),
                AdmissionApproval::new("security", "sec.oncall"),
            ]);
        store
            .update_admission_policies(allowlist.clone(), Vec::new(), audit)
            .expect("dual approvals should succeed");

        let snapshot = store.admission_policies();
        assert_eq!(snapshot.allowlist, allowlist);
        assert!(snapshot.blocklist.is_empty());
    }

    #[test]
    fn writes_policy_backups_when_configured() {
        let dir = tempdir().expect("tmp");
        let peerstore_path = dir.path().join("peerstore.json");
        let policy_path = dir.path().join("admission.json");
        let backup_dir = dir.path().join("backups");
        let config = PeerstoreConfig::persistent(&peerstore_path)
            .with_access_path(&policy_path)
            .with_policy_backups(&backup_dir, Duration::from_secs(86_400));
        let store = Peerstore::open(config).expect("open");

        let keypair = identity::Keypair::generate_ed25519();
        let peer = PeerId::from(keypair.public());
        let allowlist = vec![AllowlistedPeer {
            peer,
            tier: TierLevel::Tl3,
        }];
        store
            .update_admission_policies(
                allowlist,
                Vec::new(),
                AdmissionAuditTrail::system("test.backup"),
            )
            .expect("update policies");

        let entries: Vec<_> = fs::read_dir(&backup_dir)
            .expect("backups dir")
            .map(|entry| entry.expect("entry").path())
            .collect();
        assert_eq!(entries.len(), 1, "expected a single backup");
        let backup_path = &entries[0];
        let policy_bytes = fs::read(&policy_path).expect("policy file");
        let backup_bytes = fs::read(backup_path).expect("backup file");
        assert_eq!(
            policy_bytes, backup_bytes,
            "backup should mirror policy file"
        );

        let backups = store.admission_policy_backups().expect("backups list");
        assert_eq!(backups.len(), 1);
        let name = backup_path
            .file_name()
            .expect("backup name")
            .to_string_lossy();
        assert_eq!(backups[0].name, name);
    }

    #[test]
    fn prunes_policy_backups_after_retention() {
        let dir = tempdir().expect("tmp");
        let peerstore_path = dir.path().join("peerstore.json");
        let policy_path = dir.path().join("admission.json");
        let backup_dir = dir.path().join("backups");
        let retention = Duration::from_secs(1);
        let config = PeerstoreConfig::persistent(&peerstore_path)
            .with_access_path(&policy_path)
            .with_policy_backups(&backup_dir, retention);
        let store = Peerstore::open(config).expect("open");

        fs::create_dir_all(&backup_dir).expect("backup dir");
        let prefix = policy_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or(DEFAULT_POLICY_BACKUP_PREFIX);
        let old_backup = backup_dir.join(format!("{prefix}-1.json"));
        fs::write(&old_backup, b"{}").expect("seed backup");

        let keypair = identity::Keypair::generate_ed25519();
        let peer = PeerId::from(keypair.public());
        let allowlist = vec![AllowlistedPeer {
            peer,
            tier: TierLevel::Tl2,
        }];
        store
            .update_admission_policies(
                allowlist,
                Vec::new(),
                AdmissionAuditTrail::system("test.prune"),
            )
            .expect("update policies");

        let backups: Vec<_> = fs::read_dir(&backup_dir)
            .expect("backups dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(backups.len(), 1, "expected old backups to be pruned");
        assert_ne!(
            backups[0],
            old_backup.file_name().unwrap().to_string_lossy()
        );
    }
}
