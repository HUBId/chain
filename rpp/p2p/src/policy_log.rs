use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::tier::TierLevel;
use crate::vendor::PeerId;

#[derive(Debug, Error)]
pub enum AdmissionPolicyLogError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding error: {0}")]
    Encoding(String),
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
}

#[derive(Debug)]
pub struct AdmissionPolicyLog {
    path: PathBuf,
    next_id: AtomicU64,
    lock: Mutex<()>,
}

impl AdmissionPolicyLog {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AdmissionPolicyLogError> {
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
        })
    }

    pub fn append(
        &self,
        actor: &str,
        reason: Option<&str>,
        approvals: &[AdmissionApprovalRecord],
        change: AdmissionPolicyChange,
    ) -> Result<AdmissionPolicyLogEntry, AdmissionPolicyLogError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0);
        let entry = AdmissionPolicyLogEntry {
            id,
            timestamp_ms,
            actor: actor.to_string(),
            reason: reason.map(|value| value.to_string()),
            change,
            approvals: approvals.to_vec(),
        };
        let encoded = serde_json::to_string(&entry)
            .map_err(|err| AdmissionPolicyLogError::Encoding(err.to_string()))?;
        let _guard = self.lock.lock();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(encoded.as_bytes())?;
        file.write_all(b"\n")?;
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
