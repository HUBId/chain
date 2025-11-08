use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::policy_signing::{PolicySignature, PolicySigner, PolicySigningError};
use crate::tier::TierLevel;
use crate::vendor::PeerId;
use crate::worm_export::{WormEntryMetadata, WormExportError, WormExportSettings};

#[derive(Debug, Error)]
pub enum AdmissionPolicyLogError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("signing error: {0}")]
    Signing(#[from] PolicySigningError),
    #[error("worm export error: {0}")]
    Export(String),
    #[error("worm export requires signature for entry {id}")]
    MissingExportSignature { id: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAllowlistState {
    pub peer_id: String,
    pub tier: TierLevel,
}

impl PolicyAllowlistState {
    pub fn new(peer: PeerId, tier: TierLevel) -> Self {
        Self {
            peer_id: peer.to_base58(),
            tier,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdmissionPolicyChange {
    Allowlist {
        previous: Option<PolicyAllowlistState>,
        current: Option<PolicyAllowlistState>,
    },
    Blocklist {
        peer_id: String,
        previous: bool,
        current: bool,
    },
    Noop,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionApprovalRecord {
    pub role: String,
    pub approver: String,
}

impl AdmissionApprovalRecord {
    pub fn new(role: impl Into<String>, approver: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            approver: approver.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionPolicyLogEntry {
    pub id: u64,
    pub timestamp_ms: u64,
    pub actor: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub change: AdmissionPolicyChange,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<AdmissionApprovalRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<PolicySignature>,
}

impl AdmissionPolicyLogEntry {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AdmissionPolicyLogError> {
        let mut clone = self.clone();
        clone.signature = None;
        serde_json::to_vec(&clone).map_err(|err| AdmissionPolicyLogError::Encoding(err.to_string()))
    }
}

#[derive(Debug)]
pub struct AdmissionPolicyLog {
    path: PathBuf,
    next_id: AtomicU64,
    lock: Mutex<()>,
    worm_export: Option<WormExportSettings>,
}

impl AdmissionPolicyLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AdmissionPolicyLogError> {
        Self::open_with_options(path, AdmissionPolicyLogOptions::default())
    }

    pub fn open_with_options(
        path: impl Into<PathBuf>,
        options: AdmissionPolicyLogOptions,
    ) -> Result<Self, AdmissionPolicyLogError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let next_id = if path.exists() {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            let mut next = 0u64;
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let entry: AdmissionPolicyLogEntry = serde_json::from_str(&line)
                    .map_err(|err| AdmissionPolicyLogError::Encoding(err.to_string()))?;
                next = next.max(entry.id + 1);
            }
            next
        } else {
            0
        };

        Ok(Self {
            path,
            next_id: AtomicU64::new(next_id),
            lock: Mutex::new(()),
            worm_export: options.worm_export,
        })
    }

    pub fn append(
        &self,
        actor: &str,
        reason: Option<&str>,
        approvals: &[AdmissionApprovalRecord],
        change: AdmissionPolicyChange,
        signer: Option<&PolicySigner>,
    ) -> Result<AdmissionPolicyLogEntry, AdmissionPolicyLogError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        let mut entry = AdmissionPolicyLogEntry {
            id,
            timestamp_ms,
            actor: actor.to_string(),
            reason: reason.map(|value| value.to_string()),
            change,
            approvals: approvals.to_vec(),
            signature: None,
        };
        if let Some(signer) = signer {
            let message = entry.canonical_bytes()?;
            let signature = signer.sign(&message)?;
            entry.signature = Some(signature);
        }
        let encoded = serde_json::to_string(&entry)
            .map_err(|err| AdmissionPolicyLogError::Encoding(err.to_string()))?;
        {
            let _guard = self.lock.lock();
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            file.write_all(encoded.as_bytes())?;
            file.write_all(b"\n")?;
        }
        if let Some(settings) = &self.worm_export {
            if settings.require_signature() && entry.signature.is_none() {
                return Err(AdmissionPolicyLogError::MissingExportSignature { id });
            }
            let metadata = WormEntryMetadata { id, timestamp_ms };
            settings
                .exporter()
                .append(encoded.as_bytes(), &metadata, settings.retention())
                .map_err(map_worm_error)?;
        }
        Ok(entry)
    }

    pub fn read(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<(Vec<AdmissionPolicyLogEntry>, usize), AdmissionPolicyLogError> {
        let _guard = self.lock.lock();
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok((Vec::new(), 0));
            }
            Err(err) => return Err(err.into()),
        };
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AdmissionPolicyLogEntry = serde_json::from_str(&line)
                .map_err(|err| AdmissionPolicyLogError::Encoding(err.to_string()))?;
            entries.push(entry);
        }
        let total = entries.len();
        if limit == 0 || offset >= total {
            return Ok((Vec::new(), total));
        }
        let end = (offset + limit).min(total);
        let slice = entries[offset..end].to_vec();
        Ok((slice, total))
    }
}

fn map_worm_error(err: WormExportError) -> AdmissionPolicyLogError {
    match err {
        WormExportError::Io(source) => AdmissionPolicyLogError::Io(source),
        WormExportError::Encoding(message)
        | WormExportError::InvalidRetention(message)
        | WormExportError::Command(message)
        | WormExportError::S3(message) => AdmissionPolicyLogError::Export(message),
    }
}

#[derive(Default, Clone)]
pub struct AdmissionPolicyLogOptions {
    pub worm_export: Option<WormExportSettings>,
}
