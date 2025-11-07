use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, info, warn};

use rpp_chain::config::NodeConfig;

use crate::telemetry::snapshots::SnapshotValidatorMetrics;

#[derive(Clone, Debug)]
pub struct SnapshotValidatorSettings {
    pub cadence: Duration,
    pub manifest_path: PathBuf,
    pub chunk_dir: PathBuf,
}

impl SnapshotValidatorSettings {
    pub fn from_config(config: &NodeConfig) -> Self {
        let cadence = Duration::from_secs(config.snapshot_validator.cadence_secs);
        let manifest_path = config.snapshot_dir.join("manifest/chunks.json");
        let chunk_dir = config.snapshot_dir.join("chunks");
        Self {
            cadence,
            manifest_path,
            chunk_dir,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FailureKind {
    Missing,
    SizeMismatch,
    ChecksumMismatch,
}

impl FailureKind {
    fn as_str(&self) -> &'static str {
        match self {
            FailureKind::Missing => "missing",
            FailureKind::SizeMismatch => "size_mismatch",
            FailureKind::ChecksumMismatch => "checksum_mismatch",
        }
    }
}

#[derive(Debug)]
struct ChunkFailure {
    segment: String,
    expected_size: u64,
    expected_checksum: String,
    kind: FailureKind,
}

#[derive(Debug, Deserialize)]
struct SnapshotChunkManifest {
    #[serde(default)]
    segments: Vec<ManifestSegment>,
}

#[derive(Debug, Deserialize)]
struct ManifestSegment {
    #[serde(rename = "segment_name")]
    name: Option<String>,
    #[serde(default)]
    size_bytes: Option<u64>,
    #[serde(default)]
    sha256: Option<String>,
}

pub struct SnapshotValidator {
    shutdown: watch::Sender<bool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl SnapshotValidator {
    pub fn start(config: &NodeConfig) -> Self {
        let settings = SnapshotValidatorSettings::from_config(config);
        let metrics = SnapshotValidatorMetrics::global().clone();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let settings_arc = Arc::new(settings);

        info!(
            target = "snapshot_validator",
            cadence_secs = settings_arc.cadence.as_secs(),
            manifest = %settings_arc.manifest_path.display(),
            chunk_dir = %settings_arc.chunk_dir.display(),
            "snapshot validator started"
        );

        let worker_settings = Arc::clone(&settings_arc);
        let worker = tokio::spawn(async move {
            let mut ticker = time::interval(worker_settings.cadence);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let settings = Arc::clone(&worker_settings);
                        match tokio::task::spawn_blocking(move || scan_once(&settings)).await {
                            Ok(Ok(failures)) => {
                                for failure in failures {
                                    metrics.record_failure(failure.kind.as_str());
                                    warn!(
                                        target = "snapshot_validator",
                                        segment = failure.segment,
                                        expected_size = failure.expected_size,
                                        expected_checksum = %failure.expected_checksum,
                                        kind = failure.kind.as_str(),
                                        "snapshot chunk validation failed"
                                    );
                                }
                            }
                            Ok(Err(ScanError::ManifestMissing)) => {
                                debug!(
                                    target = "snapshot_validator",
                                    manifest = %worker_settings.manifest_path.display(),
                                    "snapshot manifest not present; skipping validation"
                                );
                            }
                            Ok(Err(ScanError::ChunkDirectoryMissing)) => {
                                debug!(
                                    target = "snapshot_validator",
                                    chunk_dir = %worker_settings.chunk_dir.display(),
                                    "snapshot chunk directory not present; skipping validation"
                                );
                            }
                            Ok(Err(ScanError::Decode(err))) => {
                                warn!(
                                    target = "snapshot_validator",
                                    manifest = %worker_settings.manifest_path.display(),
                                    error = %err,
                                    "snapshot manifest decode failed"
                                );
                            }
                            Ok(Err(ScanError::Io(err))) => {
                                warn!(
                                    target = "snapshot_validator",
                                    manifest = %worker_settings.manifest_path.display(),
                                    error = %err,
                                    "snapshot validation I/O failure"
                                );
                            }
                            Err(err) => {
                                warn!(
                                    target = "snapshot_validator",
                                    error = %err,
                                    "snapshot validator worker task failed"
                                );
                            }
                        }
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        Self {
            shutdown: shutdown_tx,
            worker: Mutex::new(Some(worker)),
        }
    }

    pub async fn shutdown(&self) {
        if self.shutdown.send(true).is_err() {
            return;
        }
        if let Some(handle) = self.worker.lock().await.take() {
            if let Err(err) = handle.await {
                debug!(?err, "snapshot validator worker exited with error");
            }
        }
    }
}

#[derive(Debug)]
enum ScanError {
    ManifestMissing,
    ChunkDirectoryMissing,
    Decode(serde_json::Error),
    Io(io::Error),
}

fn scan_once(settings: &SnapshotValidatorSettings) -> Result<Vec<ChunkFailure>, ScanError> {
    if !settings.manifest_path.exists() {
        return Err(ScanError::ManifestMissing);
    }
    if !settings.chunk_dir.exists() {
        return Err(ScanError::ChunkDirectoryMissing);
    }

    let data = fs::read(&settings.manifest_path).map_err(ScanError::Io)?;
    let manifest: SnapshotChunkManifest =
        serde_json::from_slice(&data).map_err(ScanError::Decode)?;

    let mut failures = Vec::new();
    for segment in manifest.segments {
        let Some(name) = segment.name.as_ref() else {
            continue;
        };
        let Some(expected_size) = segment.size_bytes else {
            continue;
        };
        let Some(expected_checksum) = segment.sha256.as_ref() else {
            continue;
        };

        let path = settings.chunk_dir.join(name);
        match validate_chunk(&path, expected_size, expected_checksum) {
            Ok(Some(kind)) => failures.push(ChunkFailure {
                segment: name.clone(),
                expected_size,
                expected_checksum: expected_checksum.clone(),
                kind,
            }),
            Ok(None) => {}
            Err(err) => {
                return Err(ScanError::Io(err));
            }
        }
    }

    Ok(failures)
}

fn validate_chunk(
    path: &Path,
    expected_size: u64,
    expected_checksum: &str,
) -> Result<Option<FailureKind>, io::Error> {
    if !path.exists() {
        return Ok(Some(FailureKind::Missing));
    }

    let metadata = path.metadata()?;
    if metadata.len() != expected_size {
        return Ok(Some(FailureKind::SizeMismatch));
    }

    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hex::encode(hasher.finalize());
    if digest != expected_checksum {
        return Ok(Some(FailureKind::ChecksumMismatch));
    }

    Ok(None)
}

impl From<io::Error> for ScanError {
    fn from(err: io::Error) -> Self {
        ScanError::Io(err)
    }
}
