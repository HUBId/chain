use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use reqwest::blocking::Client;
use serde::Serialize;

const MAX_SPOOL_BYTES: u64 = 512 * 1024; // 512 KiB
const MAX_IN_MEMORY_BATCH: usize = 64;

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TelemetryEventKind {
    Session {
        phase: &'static str,
    },
    Rpc {
        method: String,
        latency_ms: u64,
        outcome: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<String>,
    },
    SendStage {
        stage: &'static str,
        outcome: &'static str,
    },
    Rescan {
        stage: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        latency_ms: Option<u64>,
        outcome: &'static str,
    },
    Error {
        code: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct TelemetryEvent {
    #[serde(rename = "ts_ms")]
    pub timestamp_ms: u64,
    #[serde(flatten)]
    pub kind: TelemetryEventKind,
}

impl TelemetryEvent {
    pub fn now(kind: TelemetryEventKind) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self { timestamp_ms, kind }
    }
}

#[derive(Debug, Serialize)]
struct TelemetryEnvelope<'a> {
    schema: &'static str,
    build_id: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    commit: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    machine_id: &'a Option<String>,
    events: &'a [TelemetryEvent],
}

#[derive(Debug)]
pub struct TelemetryExporter {
    endpoint: String,
    spool_dir: PathBuf,
    client: Client,
    machine_id: Option<String>,
    max_batch: usize,
}

impl TelemetryExporter {
    pub fn new(
        endpoint: String,
        spool_dir: PathBuf,
        machine_id: Option<String>,
    ) -> io::Result<Self> {
        if !spool_dir.exists() {
            fs::create_dir_all(&spool_dir)?;
        }
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        Ok(Self {
            endpoint,
            spool_dir,
            client,
            machine_id,
            max_batch: MAX_IN_MEMORY_BATCH,
        })
    }

    pub fn max_batch(&self) -> usize {
        self.max_batch
    }

    pub fn flush_spool(&self) {
        if let Ok(entries) = collect_spool_entries(&self.spool_dir) {
            for entry in entries {
                if self.try_send_bytes(&entry).is_ok() {
                    let _ = fs::remove_file(entry);
                } else {
                    break;
                }
            }
        }
    }

    pub fn publish(&self, events: Vec<TelemetryEvent>) {
        if events.is_empty() {
            return;
        }
        let serialized = match self.encode(&events) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("wallet telemetry exporter failed to encode events: {err}");
                return;
            }
        };
        if self.try_send_bytes_raw(&serialized).is_err() {
            if let Err(err) = self.persist(&serialized) {
                eprintln!("wallet telemetry exporter failed to persist batch: {err}");
            }
        } else {
            self.flush_spool();
        }
    }

    fn encode(&self, events: &[TelemetryEvent]) -> io::Result<Vec<u8>> {
        let envelope = TelemetryEnvelope {
            schema: "wallet.telemetry.v1",
            build_id: env!("CARGO_PKG_VERSION"),
            commit: option_env!("GIT_COMMIT_SHA"),
            machine_id: &self.machine_id,
            events,
        };
        serde_json::to_vec(&envelope).map_err(|err| io::Error::new(io::ErrorKind::Other, err))
    }

    fn persist(&self, payload: &[u8]) -> io::Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let path = self.spool_dir.join(format!("{timestamp}.json"));
        fs::write(&path, payload)?;
        enforce_spool_limit(&self.spool_dir, MAX_SPOOL_BYTES)?;
        Ok(())
    }

    fn try_send_bytes_raw(&self, payload: &[u8]) -> io::Result<()> {
        let response = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .body(payload.to_vec())
            .send()
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("telemetry upload failed: {}", response.status()),
            ));
        }
        Ok(())
    }

    fn try_send_bytes(&self, path: &Path) -> io::Result<()> {
        let payload = fs::read(path)?;
        self.try_send_bytes_raw(&payload)
    }
}

fn collect_spool_entries(spool_dir: &Path) -> io::Result<Vec<PathBuf>> {
    if !spool_dir.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(spool_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            entries.push(entry.path());
        }
    }
    entries.sort();
    Ok(entries)
}

fn enforce_spool_limit(spool_dir: &Path, limit: u64) -> io::Result<()> {
    if !spool_dir.exists() {
        return Ok(());
    }
    let mut entries: Vec<_> = fs::read_dir(spool_dir)?
        .filter_map(|entry| entry.ok())
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    let mut total = 0u64;
    for entry in &entries {
        total = total.saturating_add(entry.metadata()?.len());
    }
    if total <= limit {
        return Ok(());
    }
    for entry in entries {
        if total <= limit {
            break;
        }
        let len = entry.metadata()?.len();
        total = total.saturating_sub(len);
        let _ = fs::remove_file(entry.path());
    }
    Ok(())
}

pub fn events_per_batch(exporter: Option<&TelemetryExporter>) -> usize {
    exporter
        .map(|inner| inner.max_batch())
        .unwrap_or(MAX_IN_MEMORY_BATCH)
}
