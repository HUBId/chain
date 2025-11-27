use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use hex::encode as hex_encode;
use serde::{Deserialize, Serialize};

const ZERO_HASH: [u8; 32] = [0u8; 32];

/// Logical role of the actor that produced an audit event.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuditRole {
    Prover,
    Verifier,
}

/// Immutable audit record persisted as JSONL with hash chaining.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub index: u64,
    pub timestamp_ms: u128,
    pub role: AuditRole,
    pub backend: String,
    pub operation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_fingerprint: Option<String>,
    pub result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_bytes: Option<usize>,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Serialize)]
struct AuditRecordDigest<'a> {
    index: u64,
    timestamp_ms: u128,
    role: &'a AuditRole,
    backend: &'a str,
    operation: &'a str,
    circuit: Option<&'a str>,
    proof_fingerprint: Option<&'a str>,
    result: &'a str,
    message: Option<&'a str>,
    witness_bytes: Option<usize>,
    proof_bytes: Option<usize>,
    prev_hash: &'a str,
}

struct AuditState {
    next_index: u64,
    prev_hash: [u8; 32],
}

/// Append-only audit log that hash-chains prover and verifier events.
#[derive(Clone)]
pub struct AuditLog {
    path: Arc<PathBuf>,
    state: Arc<Mutex<AuditState>>,
}

impl AuditLog {
    /// Environment variable used to discover a custom audit log path.
    pub const ENV_VAR: &'static str = "RPP_ZK_AUDIT_LOG";
    /// Default verifier audit log path.
    pub const DEFAULT_VERIFIER_PATH: &'static str = "logs/zk-verifier-audit.jsonl";
    /// Default prover audit log path.
    pub const DEFAULT_PROVER_PATH: &'static str = "logs/zk-prover-audit.jsonl";

    /// Open (or create) an audit log at the provided path, verifying the existing chain.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let state = Self::load_state(&path)?;
        Ok(Self {
            path: Arc::new(path),
            state: Arc::new(Mutex::new(state)),
        })
    }

    /// Attempt to open a log from `env_var`, falling back to `default_path`.
    ///
    /// Setting the environment variable to an empty string or "off" disables auditing.
    pub fn from_env(env_var: &str, default_path: &str) -> std::io::Result<Option<Self>> {
        match env::var(env_var) {
            Ok(value) => {
                if value.trim().is_empty() || value.eq_ignore_ascii_case("off") {
                    return Ok(None);
                }
                Self::open(value).map(Some)
            }
            Err(_) => Self::open(default_path).map(Some),
        }
    }

    /// Append a new audit record, extending the hash chain.
    pub fn append(&self, record: AuditRecord) -> std::io::Result<AuditRecord> {
        let mut guard = self.state.lock().expect("audit log mutex poisoned");
        let index = guard.next_index;
        let prev_hash_hex = hex_encode(guard.prev_hash);
        let timestamp_ms = record.timestamp_ms;
        let digest = AuditRecordDigest {
            index,
            timestamp_ms,
            role: &record.role,
            backend: &record.backend,
            operation: &record.operation,
            circuit: record.circuit.as_deref(),
            proof_fingerprint: record.proof_fingerprint.as_deref(),
            result: &record.result,
            message: record.message.as_deref(),
            witness_bytes: record.witness_bytes,
            proof_bytes: record.proof_bytes,
            prev_hash: &prev_hash_hex,
        };

        let entry_hash = hash_record(&digest)?;
        let entry = AuditRecord {
            index,
            timestamp_ms,
            role: record.role,
            backend: record.backend,
            operation: record.operation,
            circuit: record.circuit,
            proof_fingerprint: record.proof_fingerprint,
            result: record.result,
            message: record.message,
            witness_bytes: record.witness_bytes,
            proof_bytes: record.proof_bytes,
            prev_hash: prev_hash_hex,
            entry_hash: hex_encode(entry_hash),
        };

        persist(&self.path, &entry)?;

        guard.prev_hash = entry_hash;
        guard.next_index = guard.next_index.saturating_add(1);
        Ok(entry)
    }

    /// Validate the full chain for the log at the provided path.
    pub fn verify_chain(path: impl AsRef<Path>) -> std::io::Result<()> {
        let mut prev_hash = ZERO_HASH;
        let reader = match File::open(path.as_ref()) {
            Ok(file) => BufReader::new(file),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        };

        for line in reader.lines() {
            let line = line?;
            let entry: AuditRecord = serde_json::from_str(&line)?;
            let expected_prev = hex_encode(prev_hash);
            if entry.prev_hash != expected_prev {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "audit chain mismatch at {}: expected prev_hash {} but found {}",
                        entry.index, expected_prev, entry.prev_hash
                    ),
                ));
            }

            let digest = AuditRecordDigest {
                index: entry.index,
                timestamp_ms: entry.timestamp_ms,
                role: &entry.role,
                backend: &entry.backend,
                operation: &entry.operation,
                circuit: entry.circuit.as_deref(),
                proof_fingerprint: entry.proof_fingerprint.as_deref(),
                result: &entry.result,
                message: entry.message.as_deref(),
                witness_bytes: entry.witness_bytes,
                proof_bytes: entry.proof_bytes,
                prev_hash: &entry.prev_hash,
            };
            let hash = hash_record(&digest)?;
            let hash_hex = hex_encode(hash);
            if entry.entry_hash != hash_hex {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "audit chain mismatch at {}: expected entry_hash {} but found {}",
                        entry.index, hash_hex, entry.entry_hash
                    ),
                ));
            }
            prev_hash = hash;
        }

        Ok(())
    }

    fn load_state(path: &Path) -> std::io::Result<AuditState> {
        if !path.exists() {
            return Ok(AuditState {
                next_index: 0,
                prev_hash: ZERO_HASH,
            });
        }

        Self::verify_chain(path)?;

        let reader = BufReader::new(File::open(path)?);
        let mut last_hash = ZERO_HASH;
        let mut last_index = 0;
        for line in reader.lines() {
            let line = line?;
            let entry: AuditRecord = serde_json::from_str(&line)?;
            last_hash = hex::decode(entry.entry_hash)
                .ok()
                .and_then(|bytes| bytes.try_into().ok())
                .unwrap_or(ZERO_HASH);
            last_index = entry.index;
        }

        Ok(AuditState {
            next_index: last_index.saturating_add(1),
            prev_hash: last_hash,
        })
    }
}

fn persist(path: &Path, record: &AuditRecord) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_vec(record)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .write(true)
        .open(path)?;
    file.write_all(&json)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn hash_record(digest: &AuditRecordDigest<'_>) -> std::io::Result<[u8; 32]> {
    let bytes = serde_json::to_vec(digest)?;
    let mut hasher = Hasher::new();
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

/// Build a timestamp suitable for audit entries.
pub fn now_timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn record(role: AuditRole, backend: &str, result: &str, prev_hash: [u8; 32]) -> AuditRecord {
        AuditRecord {
            index: 0,
            timestamp_ms: now_timestamp_ms(),
            role,
            backend: backend.to_string(),
            operation: "prove".to_string(),
            circuit: Some("tx".to_string()),
            proof_fingerprint: Some("abc123".to_string()),
            result: result.to_string(),
            message: None,
            witness_bytes: Some(32),
            proof_bytes: Some(64),
            prev_hash: hex_encode(prev_hash),
            entry_hash: String::new(),
        }
    }

    #[test]
    fn chain_rejects_tampering() {
        let temp = TempDir::new().expect("tempdir");
        let log_path = temp.path().join("audit.jsonl");
        let log = AuditLog::open(&log_path).expect("open log");

        let entry_one = log
            .append(record(AuditRole::Prover, "stwo", "ok", ZERO_HASH))
            .expect("first entry");
        assert!(AuditLog::verify_chain(&log_path).is_ok());

        let mut tampered = entry_one.clone();
        tampered.result = "err".to_string();
        persist(&log_path, &tampered).expect("append tampered entry");

        let error = AuditLog::verify_chain(&log_path).expect_err("tampering detected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn chain_survives_rotation() {
        let temp = TempDir::new().expect("tempdir");
        let log_path = temp.path().join("audit.jsonl");
        let log = AuditLog::open(&log_path).expect("open log");

        let first = log
            .append(record(AuditRole::Verifier, "plonky3", "ok", ZERO_HASH))
            .expect("first entry");
        assert_eq!(first.index, 0);

        let rotated = temp.path().join("audit-rotated.jsonl");
        fs::rename(&log_path, &rotated).expect("rotate file");
        AuditLog::verify_chain(&rotated).expect("verify rotated chain");

        let log = AuditLog::open(&log_path).expect("reopen log");
        let second = log
            .append(record(AuditRole::Verifier, "plonky3", "ok", ZERO_HASH))
            .expect("second entry");
        assert_eq!(second.index, 0);
    }
}
