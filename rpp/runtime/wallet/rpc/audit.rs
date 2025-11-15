use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::Serialize;
use tracing::warn;

use crate::errors::{ChainError, ChainResult};
use crate::runtime::wallet::runtime::WalletAuditRuntimeConfig;

use super::{WalletIdentity, WalletRole, WalletRoleSet};

const SEGMENT_PREFIX: &str = "wallet-audit";
const SEGMENT_EXTENSION: &str = ".jsonl";
const DEFAULT_ROTATION: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug)]
struct ActiveSegment {
    opened_at: SystemTime,
    writer: BufWriter<File>,
    path: PathBuf,
}

#[derive(Serialize)]
struct WalletAuditRecord {
    timestamp: u64,
    method: String,
    identities: Vec<WalletIdentity>,
    roles: Vec<WalletRole>,
    result_code: i32,
}

/// Rotating append-only audit logger for wallet RPC invocations.
#[derive(Debug)]
pub struct WalletAuditLogger {
    enabled: bool,
    directory: PathBuf,
    rotation: Duration,
    retention: Duration,
    state: Mutex<Option<ActiveSegment>>,
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
        let retention = config.retention_duration();
        Self::with_settings(directory.to_path_buf(), DEFAULT_ROTATION, retention, true)
    }

    /// Construct a logger with custom rotation and retention settings.
    #[cfg(test)]
    pub(crate) fn with_settings(
        directory: PathBuf,
        rotation: Duration,
        retention: Duration,
        enabled: bool,
    ) -> ChainResult<Self> {
        Self::new_inner(directory, rotation, retention, enabled)
    }

    /// Construct a disabled logger that performs no operations.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            directory: PathBuf::new(),
            rotation: DEFAULT_ROTATION,
            retention: Duration::from_secs(0),
            state: Mutex::new(None),
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
        retention: Duration,
        enabled: bool,
    ) -> ChainResult<Self> {
        if enabled {
            fs::create_dir_all(&directory)?;
        }
        Ok(Self {
            enabled,
            directory,
            rotation,
            retention,
            state: Mutex::new(None),
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
        let segment = self.ensure_segment(now, &mut state)?;
        let record = WalletAuditRecord {
            timestamp: now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            method: method.to_string(),
            identities: identities.to_vec(),
            roles: roles.iter().copied().collect(),
            result_code,
        };
        serde_json::to_writer(&mut segment.writer, &record).map_err(|err| {
            ChainError::Config(format!("failed to encode wallet audit record: {err}"))
        })?;
        segment.writer.write_all(b"\n")?;
        segment.writer.flush()?;
        Ok(())
    }

    fn ensure_segment<'a>(
        &self,
        now: SystemTime,
        state: &'a mut Option<ActiveSegment>,
    ) -> ChainResult<&'a mut ActiveSegment> {
        if !self.enabled {
            return Err(ChainError::Config(
                "wallet audit logger accessed while disabled".to_string(),
            ));
        }

        let rotate = match state {
            Some(active) => {
                now.duration_since(active.opened_at).unwrap_or_default() >= self.rotation
            }
            None => true,
        };
        if rotate {
            *state = Some(self.open_segment(now)?);
            self.prune_segments(now)?;
        }
        Ok(state.as_mut().expect("audit segment initialised"))
    }

    fn open_segment(&self, now: SystemTime) -> ChainResult<ActiveSegment> {
        let timestamp = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let name = format!("{SEGMENT_PREFIX}-{timestamp}{SEGMENT_EXTENSION}");
        let path = self.directory.join(name);
        let file = File::create(&path)?;
        Ok(ActiveSegment {
            opened_at: now,
            writer: BufWriter::new(file),
            path,
        })
    }

    fn prune_segments(&self, now: SystemTime) -> ChainResult<()> {
        if self.retention.is_zero() {
            return Ok(());
        }

        let cutoff = now
            .checked_sub(self.retention)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        for entry in fs::read_dir(&self.directory)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    warn!(?err, "failed to iterate wallet audit directory");
                    continue;
                }
            };
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(opened_at) = segment_timestamp(&path) {
                if opened_at < cutoff {
                    if let Err(err) = fs::remove_file(&path) {
                        warn!(?err, ?path, "failed to prune wallet audit segment");
                    }
                }
            }
        }
        Ok(())
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

fn segment_timestamp(path: &PathBuf) -> Option<SystemTime> {
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
            Duration::from_secs(600),
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
            Duration::from_secs(10),
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
            Duration::from_secs(3),
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

    fn read_segment_names(dir: &std::path::Path) -> Vec<String> {
        let mut entries: Vec<String> = fs::read_dir(dir)
            .expect("read dir")
            .filter_map(|entry| entry.ok().and_then(|e| e.file_name().into_string().ok()))
            .collect();
        entries.sort();
        entries
    }
}
