use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hex::FromHex;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::errors::{ChainError, ChainResult};
use crate::runtime::wallet::runtime::WalletAuditRuntimeConfig;

use super::{WalletIdentity, WalletRole, WalletRoleSet};

const SEGMENT_PREFIX: &str = "wallet-audit";
const SEGMENT_EXTENSION: &str = ".jsonl";
const ANCHOR_FILE: &str = "wallet-audit.anchor";
const ZERO_HASH: [u8; 32] = [0; 32];

#[derive(Debug)]
struct ActiveSegment {
    opened_at: SystemTime,
    writer: BufWriter<File>,
    path: PathBuf,
    size: u64,
}

#[derive(Debug)]
struct AuditState {
    active: Option<ActiveSegment>,
    next_index: u64,
    prev_hash: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
struct AnchorState {
    prev_hash: String,
}

#[derive(Deserialize, Serialize)]
struct WalletAuditRecord {
    index: u64,
    timestamp: u64,
    method: String,
    identities: Vec<WalletIdentity>,
    roles: Vec<WalletRole>,
    result_code: i32,
    prev_hash: String,
    entry_hash: String,
}

#[derive(Serialize)]
struct WalletAuditDigest<'a> {
    index: u64,
    timestamp: u64,
    method: &'a str,
    identities: &'a [WalletIdentity],
    roles: &'a [WalletRole],
    result_code: i32,
    prev_hash: &'a str,
}

/// Rotating append-only audit logger for wallet RPC invocations.
#[derive(Debug)]
pub struct WalletAuditLogger {
    enabled: bool,
    directory: PathBuf,
    rotation: Duration,
    retention: Duration,
    retention_bytes: Option<u64>,
    max_segment_bytes: u64,
    state: Mutex<AuditState>,
}

impl WalletAuditLogger {
    /// Construct an audit logger from the runtime configuration.
    pub fn from_config(config: &WalletAuditRuntimeConfig) -> ChainResult<Self> {
        if !config.enabled() {
            return Ok(Self::disabled());
        }

        let directory = config.directory().ok_or_else(|| {
            ChainError::Config(
                "wallet audit logging enabled but no audit directory configured".to_string(),
            )
        })?;
        Self::with_settings(
            directory.to_path_buf(),
            config.rotation_interval(),
            config.max_segment_bytes(),
            config.retention_duration(),
            config.retention_bytes(),
            true,
        )
    }

    /// Construct a logger with custom rotation and retention settings.
    #[cfg(test)]
    pub(crate) fn with_settings(
        directory: PathBuf,
        rotation: Duration,
        max_segment_bytes: u64,
        retention: Duration,
        retention_bytes: Option<u64>,
        enabled: bool,
    ) -> ChainResult<Self> {
        Self::new_inner(
            directory,
            rotation,
            max_segment_bytes,
            retention,
            retention_bytes,
            enabled,
        )
    }

    /// Construct a disabled logger that performs no operations.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            directory: PathBuf::new(),
            rotation: Duration::from_secs(0),
            retention: Duration::from_secs(0),
            retention_bytes: None,
            max_segment_bytes: 0,
            state: Mutex::new(AuditState {
                active: None,
                next_index: 0,
                prev_hash: ZERO_HASH,
            }),
        }
    }

    /// Append an audit record capturing the provided metadata.
    pub fn log(
        &self,
        method: &str,
        identities: &[WalletIdentity],
        roles: &WalletRoleSet,
        result_code: i32,
    ) {
        if !self.enabled {
            return;
        }

        if let Err(err) =
            self.append_with_time(SystemTime::now(), method, identities, roles, result_code)
        {
            warn!(?err, method, "failed to append wallet audit record");
        }
    }

    fn new_inner(
        directory: PathBuf,
        rotation: Duration,
        max_segment_bytes: u64,
        retention: Duration,
        retention_bytes: Option<u64>,
        enabled: bool,
    ) -> ChainResult<Self> {
        if enabled {
            fs::create_dir_all(&directory)?;
        }
        let state = if enabled {
            Self::load_state(&directory)?
        } else {
            AuditState {
                active: None,
                next_index: 0,
                prev_hash: ZERO_HASH,
            }
        };
        Ok(Self {
            enabled,
            directory,
            rotation,
            retention,
            retention_bytes,
            max_segment_bytes,
            state: Mutex::new(state),
        })
    }

    fn append_with_time(
        &self,
        now: SystemTime,
        method: &str,
        identities: &[WalletIdentity],
        roles: &WalletRoleSet,
        result_code: i32,
    ) -> ChainResult<()> {
        if !self.enabled {
            return Ok(());
        }

        let mut state = self.state.lock();
        self.ensure_segment(now, &mut state)?;

        let mut identities = identities.to_vec();
        let mut roles = roles.iter().copied().collect::<Vec<_>>();
        identities.shrink_to_fit();
        roles.shrink_to_fit();

        let prev_hash_hex = hex::encode(state.prev_hash);
        let digest = WalletAuditDigest {
            index: state.next_index,
            timestamp: now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            method,
            identities: &identities,
            roles: &roles,
            result_code,
            prev_hash: &prev_hash_hex,
        };

        let entry_hash = Self::hash_record(&digest)?;
        let record = WalletAuditRecord {
            index: state.next_index,
            timestamp: digest.timestamp,
            method: method.to_string(),
            identities,
            roles,
            result_code,
            prev_hash: prev_hash_hex,
            entry_hash: hex::encode(entry_hash),
        };

        let encoded = serde_json::to_vec(&record).map_err(|err| {
            ChainError::Config(format!("failed to encode wallet audit record: {err}"))
        })?;
        let record_size = encoded.len() as u64 + 1; // newline
        self.enforce_segment_size(now, &mut state, record_size)?;
        let segment = state.active.as_mut().expect("audit segment initialised");
        segment.writer.write_all(&encoded)?;
        segment.writer.write_all(b"\n")?;
        segment.writer.flush()?;
        segment.size = segment.size.saturating_add(record_size);
        state.prev_hash = entry_hash;
        state.next_index = state.next_index.saturating_add(1);
        Ok(())
    }

    fn ensure_segment(&self, now: SystemTime, state: &mut AuditState) -> ChainResult<()> {
        if !self.enabled {
            return Err(ChainError::Config(
                "wallet audit logger accessed while disabled".to_string(),
            ));
        }

        let rotate = match &state.active {
            Some(active) => {
                self.rotation != Duration::from_secs(0)
                    && now.duration_since(active.opened_at).unwrap_or_default() >= self.rotation
            }
            None => true,
        };
        if rotate {
            state.active = Some(self.open_segment(now)?);
            self.prune_segments(now)?;
        }
        Ok(())
    }

    fn open_segment(&self, now: SystemTime) -> ChainResult<ActiveSegment> {
        let timestamp = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let name = format!("{SEGMENT_PREFIX}-{timestamp}{SEGMENT_EXTENSION}");
        let path = self.directory.join(name);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .write(true)
            .open(&path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(ActiveSegment {
            opened_at: now,
            writer: BufWriter::new(file),
            path,
            size,
        })
    }

    fn prune_segments(&self, now: SystemTime) -> ChainResult<()> {
        if self.retention.is_zero() && self.retention_bytes.is_none() {
            return Ok(());
        }

        let cutoff = if self.retention.is_zero() {
            SystemTime::UNIX_EPOCH
        } else {
            now.checked_sub(self.retention)
                .unwrap_or(SystemTime::UNIX_EPOCH)
        };

        let mut segments: Vec<_> = fs::read_dir(&self.directory)?
            .filter_map(|entry| match entry {
                Ok(entry) => {
                    let path = entry.path();
                    let timestamp = segment_timestamp(&path)?;
                    let size = fs::metadata(&path).ok()?.len();
                    Some((timestamp, path, size))
                }
                Err(err) => {
                    warn!(?err, "failed to iterate wallet audit directory");
                    None
                }
            })
            .collect();
        segments.sort_by_key(|(ts, _, _)| *ts);

        let mut retained: Vec<(SystemTime, PathBuf, u64)> = Vec::new();
        for (timestamp, path, size) in segments {
            if timestamp < cutoff {
                if let Err(err) = fs::remove_file(&path) {
                    warn!(?err, ?path, "failed to prune wallet audit segment");
                }
            } else {
                retained.push((timestamp, path, size));
            }
        }

        if let Some(limit) = self.retention_bytes {
            let mut total_size: u64 = retained.iter().map(|(_, _, size)| *size).sum();
            let mut drop_prefix = 0;
            while total_size > limit && drop_prefix < retained.len().saturating_sub(1) {
                total_size = total_size.saturating_sub(retained[drop_prefix].2);
                let path = retained[drop_prefix].1.clone();
                if let Err(err) = fs::remove_file(&path) {
                    warn!(?err, ?path, "failed to prune wallet audit segment");
                }
                drop_prefix += 1;
            }
            retained.drain(0..drop_prefix);
        }

        self.write_anchor(&retained)?;
        Ok(())
    }

    fn enforce_segment_size(
        &self,
        now: SystemTime,
        state: &mut AuditState,
        record_size: u64,
    ) -> ChainResult<()> {
        if self.max_segment_bytes == 0 {
            return Ok(());
        }

        if let Some(active) = &state.active {
            if active.size.saturating_add(record_size) > self.max_segment_bytes {
                state.active = Some(self.open_segment(now)?);
                self.prune_segments(now)?;
            }
        }
        Ok(())
    }

    fn load_state(directory: &Path) -> ChainResult<AuditState> {
        let mut prev_hash = Self::read_anchor(directory);
        let mut next_index = 0;

        let mut segments: Vec<_> = fs::read_dir(directory)?
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let path = entry.path();
                let timestamp = segment_timestamp(&path)?;
                Some((timestamp, path))
            })
            .collect();
        segments.sort_by_key(|(ts, _)| *ts);

        for (_, path) in segments {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let record: WalletAuditRecord = serde_json::from_str(&line).map_err(|err| {
                    ChainError::Config(format!(
                        "failed to decode wallet audit record in {}: {err}",
                        path.display()
                    ))
                })?;

                if record.index != next_index {
                    return Err(ChainError::Config(format!(
                        "wallet audit log contains out-of-order index {} expected {} in {}",
                        record.index,
                        next_index,
                        path.display()
                    )));
                }

                let expected_prev = hex::encode(prev_hash);
                if record.prev_hash != expected_prev {
                    return Err(ChainError::Config(format!(
                        "wallet audit chain mismatch at {} in {}: expected prev_hash {} but found {}",
                        record.index,
                        path.display(),
                        expected_prev,
                        record.prev_hash
                    )));
                }

                let digest = WalletAuditDigest {
                    index: record.index,
                    timestamp: record.timestamp,
                    method: &record.method,
                    identities: &record.identities,
                    roles: &record.roles,
                    result_code: record.result_code,
                    prev_hash: &record.prev_hash,
                };
                let hash = Self::hash_record(&digest)?;
                let hash_hex = hex::encode(hash);
                if record.entry_hash != hash_hex {
                    return Err(ChainError::Config(format!(
                        "wallet audit chain mismatch at {} in {}: expected entry_hash {} but found {}",
                        record.index,
                        path.display(),
                        hash_hex,
                        record.entry_hash
                    )));
                }

                prev_hash = hash;
                next_index = next_index.saturating_add(1);
            }
        }

        Ok(AuditState {
            active: None,
            next_index,
            prev_hash,
        })
    }

    fn read_anchor(directory: &Path) -> [u8; 32] {
        let path = directory.join(ANCHOR_FILE);
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(_) => return ZERO_HASH,
        };
        let state: AnchorState = match serde_json::from_str(&contents) {
            Ok(state) => state,
            Err(_) => return ZERO_HASH,
        };
        <[u8; 32]>::from_hex(state.prev_hash).unwrap_or(ZERO_HASH)
    }

    fn write_anchor(&self, retained: &[(SystemTime, PathBuf, u64)]) -> ChainResult<()> {
        let path = self.directory.join(ANCHOR_FILE);
        if retained.is_empty() {
            let _ = fs::remove_file(path);
            return Ok(());
        }

        let first_path = &retained[0].1;
        let mut reader = BufReader::new(File::open(first_path)?);
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            let _ = fs::remove_file(path);
            return Ok(());
        }

        let record: WalletAuditRecord = serde_json::from_str(line.trim_end()).map_err(|err| {
            ChainError::Config(format!(
                "failed to decode wallet audit record in {}: {err}",
                first_path.display()
            ))
        })?;
        let anchor = AnchorState {
            prev_hash: record.prev_hash.clone(),
        };
        let encoded = serde_json::to_vec(&anchor).map_err(|err| {
            ChainError::Config(format!("failed to encode wallet audit anchor: {err}"))
        })?;
        fs::write(path, encoded)?;
        Ok(())
    }

    fn hash_record(digest: &WalletAuditDigest<'_>) -> ChainResult<[u8; 32]> {
        let bytes = serde_json::to_vec(digest).map_err(|err| {
            ChainError::Config(format!("failed to encode wallet audit digest: {err}"))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    #[cfg(test)]
    pub(crate) fn append_at(
        &self,
        now: SystemTime,
        method: &str,
        identities: &[WalletIdentity],
        roles: &WalletRoleSet,
        result_code: i32,
    ) -> ChainResult<()> {
        self.append_with_time(now, method, identities, roles, result_code)
    }
}

fn segment_timestamp(path: &Path) -> Option<SystemTime> {
    let name = path.file_name()?.to_str()?;
    if !name.starts_with(SEGMENT_PREFIX) || !name.ends_with(SEGMENT_EXTENSION) {
        return None;
    }
    let start = SEGMENT_PREFIX.len() + 1; // include dash
    let end = name.len() - SEGMENT_EXTENSION.len();
    let value = name.get(start..end)?;
    let seconds = value.parse::<u64>().ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::wallet::rpc::WalletRole;
    use serde_json::Value;
    use tempfile::tempdir;

    #[test]
    fn appends_redacted_records_to_segment() {
        let temp = tempdir().expect("tempdir");
        let logger = WalletAuditLogger::with_settings(
            temp.path().to_path_buf(),
            Duration::from_secs(60),
            1024,
            Duration::from_secs(600),
            None,
            true,
        )
        .expect("logger");

        let identities = vec![WalletIdentity::from_bearer_token("super-secret-token")];
        let mut roles = WalletRoleSet::new();
        roles.insert(WalletRole::Operator);

        logger
            .append_at(
                UNIX_EPOCH + Duration::from_secs(123),
                "wallet.advanced",
                &identities,
                &roles,
                17,
            )
            .expect("append");

        let records = read_records(temp.path());
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["method"], Value::from("wallet.advanced"));
        assert_eq!(record["result_code"], Value::from(17));
        assert_eq!(record["timestamp"], Value::from(123));

        let identity = record["identities"][0].clone();
        assert_eq!(identity["kind"], Value::from("token"));
        let id = identity["id"].as_str().expect("token id");
        assert_eq!(id.len(), 64);
        assert_ne!(id, "super-secret-token");

        let roles = record["roles"].as_array().expect("roles array");
        assert_eq!(roles, &vec![Value::from("operator")]);
    }

    #[test]
    fn rotates_segments_when_interval_elapsed() {
        let temp = tempdir().expect("tempdir");
        let logger = WalletAuditLogger::with_settings(
            temp.path().to_path_buf(),
            Duration::from_secs(1),
            1024,
            Duration::from_secs(10),
            None,
            true,
        )
        .expect("logger");

        let identities = vec![WalletIdentity::Token("test".into())];
        let mut roles = WalletRoleSet::new();
        roles.insert(WalletRole::Operator);

        logger
            .append_at(
                UNIX_EPOCH + Duration::from_secs(0),
                "test.method",
                &identities,
                &roles,
                0,
            )
            .expect("append");

        logger
            .append_at(
                UNIX_EPOCH + Duration::from_secs(2),
                "test.method",
                &identities,
                &roles,
                0,
            )
            .expect("append");

        let files = read_segment_names(temp.path());
        assert_eq!(files.len(), 2, "rotation should create two segments");
    }

    #[test]
    fn prunes_segments_past_retention_window() {
        let temp = tempdir().expect("tempdir");
        let logger = WalletAuditLogger::with_settings(
            temp.path().to_path_buf(),
            Duration::from_secs(1),
            1024,
            Duration::from_secs(3),
            None,
            true,
        )
        .expect("logger");

        let identities = vec![WalletIdentity::Token("test".into())];
        let mut roles = WalletRoleSet::new();
        roles.insert(WalletRole::Admin);

        logger
            .append_at(
                UNIX_EPOCH + Duration::from_secs(0),
                "test.method",
                &identities,
                &roles,
                0,
            )
            .expect("append");
        logger
            .append_at(
                UNIX_EPOCH + Duration::from_secs(2),
                "test.method",
                &identities,
                &roles,
                0,
            )
            .expect("append");
        logger
            .append_at(
                UNIX_EPOCH + Duration::from_secs(4),
                "test.method",
                &identities,
                &roles,
                0,
            )
            .expect("append");

        let files = read_segment_names(temp.path());
        assert_eq!(files.len(), 2, "old segments should be pruned");
        assert!(files
            .iter()
            .all(|name| name.contains("-2") || name.contains("-4")));
    }

    #[test]
    fn hash_chain_survives_rotation() {
        let temp = tempdir().expect("tempdir");
        let logger = WalletAuditLogger::with_settings(
            temp.path().to_path_buf(),
            Duration::from_secs(1),
            2048,
            Duration::from_secs(15),
            None,
            true,
        )
        .expect("logger");

        let identities = vec![WalletIdentity::Token("test".into())];
        let mut roles = WalletRoleSet::new();
        roles.insert(WalletRole::Operator);

        logger
            .append_at(
                UNIX_EPOCH + Duration::from_secs(0),
                "test.method",
                &identities,
                &roles,
                0,
            )
            .expect("append first");
        logger
            .append_at(
                UNIX_EPOCH + Duration::from_secs(2),
                "test.method",
                &identities,
                &roles,
                1,
            )
            .expect("append second");

        let records = read_record_structs(temp.path());
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].index, 0);
        assert_eq!(records[1].index, 1);
        assert_eq!(records[1].prev_hash, records[0].entry_hash);

        let reloaded = WalletAuditLogger::with_settings(
            temp.path().to_path_buf(),
            Duration::from_secs(60),
            2048,
            Duration::from_secs(15),
            None,
            true,
        )
        .expect("reload");

        reloaded
            .append_at(
                UNIX_EPOCH + Duration::from_secs(4),
                "test.method",
                &identities,
                &roles,
                2,
            )
            .expect("append third");

        let records = read_record_structs(temp.path());
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].index, 2);
        assert_eq!(records[2].prev_hash, records[1].entry_hash);
    }

    #[test]
    fn rotates_when_segment_exceeds_size_limit() {
        let temp = tempdir().expect("tempdir");
        let logger = WalletAuditLogger::with_settings(
            temp.path().to_path_buf(),
            Duration::from_secs(60),
            180,
            Duration::from_secs(30),
            None,
            true,
        )
        .expect("logger");

        let identities = vec![WalletIdentity::Token("tiny".into())];
        let mut roles = WalletRoleSet::new();
        roles.insert(WalletRole::Operator);

        for offset in 0..4 {
            logger
                .append_at(
                    UNIX_EPOCH + Duration::from_secs(offset),
                    "audit.size",
                    &identities,
                    &roles,
                    offset as i32,
                )
                .expect("append");
        }

        let files = read_segment_names(temp.path());
        assert!(files.len() >= 2, "size limit should trigger rotation");
    }

    #[test]
    fn retention_bytes_drop_old_segments_and_write_anchor() {
        let temp = tempdir().expect("tempdir");
        let logger = WalletAuditLogger::with_settings(
            temp.path().to_path_buf(),
            Duration::from_secs(1),
            256,
            Duration::from_secs(60),
            Some(350),
            true,
        )
        .expect("logger");

        let identities = vec![WalletIdentity::Token("tiny".into())];
        let mut roles = WalletRoleSet::new();
        roles.insert(WalletRole::Admin);

        logger
            .append_at(
                UNIX_EPOCH + Duration::from_secs(0),
                "audit.retention",
                &identities,
                &roles,
                0,
            )
            .expect("append first");
        logger
            .append_at(
                UNIX_EPOCH + Duration::from_secs(2),
                "audit.retention",
                &identities,
                &roles,
                1,
            )
            .expect("append second");

        let files = read_segment_names(temp.path());
        assert_eq!(
            files.len(),
            1,
            "retention bytes should prune oldest segment"
        );

        let anchor = read_anchor(temp.path());
        let records = read_record_structs(temp.path());
        assert_eq!(records.first().unwrap().prev_hash, anchor.prev_hash);

        WalletAuditLogger::with_settings(
            temp.path().to_path_buf(),
            Duration::from_secs(10),
            512,
            Duration::from_secs(60),
            Some(350),
            true,
        )
        .expect("reload with anchor");
    }

    fn read_records(dir: &std::path::Path) -> Vec<Value> {
        let mut records = Vec::new();
        for name in read_segment_names(dir) {
            let path = dir.join(name);
            let contents = fs::read_to_string(path).expect("segment contents");
            for line in contents.lines().filter(|line| !line.is_empty()) {
                let parsed = serde_json::from_str::<Value>(line).expect("record");
                records.push(parsed);
            }
        }
        records
    }

    fn read_record_structs(dir: &std::path::Path) -> Vec<WalletAuditRecord> {
        let mut records = Vec::new();
        for name in read_segment_names(dir) {
            let path = dir.join(name);
            let contents = fs::read_to_string(path).expect("segment contents");
            for line in contents.lines().filter(|line| !line.is_empty()) {
                let parsed = serde_json::from_str::<WalletAuditRecord>(line).expect("record");
                records.push(parsed);
            }
        }
        records
    }

    fn read_anchor(dir: &std::path::Path) -> AnchorState {
        let contents = fs::read_to_string(dir.join(ANCHOR_FILE)).expect("anchor file");
        serde_json::from_str(&contents).expect("anchor state")
    }

    fn read_segment_names(dir: &std::path::Path) -> Vec<String> {
        let mut entries: Vec<String> = fs::read_dir(dir)
            .expect("read dir")
            .filter_map(|entry| {
                entry.ok().and_then(|e| {
                    let name = e.file_name().into_string().ok()?;
                    if name.starts_with(SEGMENT_PREFIX) && name.ends_with(SEGMENT_EXTENSION) {
                        Some(name)
                    } else {
                        None
                    }
                })
            })
            .collect();
        entries.sort();
        entries
    }
}
