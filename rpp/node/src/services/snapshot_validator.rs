use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use blake2::{
    digest::{consts::U32, Digest},
    Blake2b,
};
use hex;
use serde::Deserialize;
use sha2::Sha256;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, info, warn};

use rpp_chain::config::{NodeConfig, SnapshotChecksumAlgorithm};

use crate::telemetry::snapshots::{ScanResult, SnapshotValidatorMetrics};

#[derive(Clone, Debug)]
pub struct SnapshotValidatorSettings {
    pub cadence: Duration,
    pub manifest_path: PathBuf,
    pub chunk_dir: PathBuf,
    pub checksum_algorithm: SnapshotChecksumAlgorithm,
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
            checksum_algorithm: config.snapshot_checksum_algorithm,
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

const SNAPSHOT_MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Deserialize)]
struct SnapshotChunkManifest {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    checksum_algorithm: Option<SnapshotChecksumAlgorithm>,
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
    checksum: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
}

type Blake2b256 = Blake2b<U32>;

fn resolve_manifest_algorithm(
    manifest_algorithm: Option<SnapshotChecksumAlgorithm>,
    configured_algorithm: SnapshotChecksumAlgorithm,
) -> Result<SnapshotChecksumAlgorithm, ScanError> {
    match manifest_algorithm {
        Some(actual) if actual != configured_algorithm => {
            Err(ScanError::ChecksumAlgorithmMismatch {
                expected: configured_algorithm,
                actual,
            })
        }
        Some(actual) => Ok(actual),
        None => Ok(configured_algorithm),
    }
}

enum SnapshotChecksumHasher {
    Sha256(Sha256),
    Blake2b(Blake2b256),
}

impl SnapshotChecksumHasher {
    fn new(algorithm: SnapshotChecksumAlgorithm) -> Self {
        match algorithm {
            SnapshotChecksumAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            SnapshotChecksumAlgorithm::Blake2b => Self::Blake2b(Blake2b256::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            SnapshotChecksumHasher::Sha256(hasher) => hasher.update(bytes),
            SnapshotChecksumHasher::Blake2b(hasher) => hasher.update(bytes),
        }
    }

    fn finalize(self) -> String {
        match self {
            SnapshotChecksumHasher::Sha256(hasher) => hex::encode(hasher.finalize()),
            SnapshotChecksumHasher::Blake2b(hasher) => hex::encode(hasher.finalize()),
        }
    }
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
                        let started_at = Instant::now();
                        metrics.record_scan_start();

                        let settings = Arc::clone(&worker_settings);
                        let scan_result = match tokio::task::spawn_blocking(move || scan_once(&settings)).await {
                            Ok(Ok(failures)) => {
                                for failure in failures {
                                    metrics.record_failure(failure.kind.as_str());
                                    warn!(
                                        target = "snapshot_validator",
                                        segment = failure.segment,
                                        expected_size = failure.expected_size,
                                        expected_checksum = %failure.expected_checksum,
                                        kind = failure.kind.as_str(),
                                        "snapshot chunk validation failed",
                                    );
                                }
                                ScanResult::Success
                            }
                            Ok(Err(ScanError::ManifestMissing)) => {
                                debug!(
                                    target = "snapshot_validator",
                                    manifest = %worker_settings.manifest_path.display(),
                                    "snapshot manifest not present; skipping validation",
                                );
                                ScanResult::Skipped
                            }
                            Ok(Err(ScanError::ChunkDirectoryMissing)) => {
                                debug!(
                                    target = "snapshot_validator",
                                    chunk_dir = %worker_settings.chunk_dir.display(),
                                    "snapshot chunk directory not present; skipping validation",
                                );
                                ScanResult::Skipped
                            }
                            Ok(Err(ScanError::VersionMismatch { expected, actual })) => {
                                warn!(
                                    target = "snapshot_validator",
                                    manifest = %worker_settings.manifest_path.display(),
                                    expected_version = expected,
                                    actual_version = actual,
                                    "snapshot manifest version mismatch",
                                );
                                ScanResult::Failure
                            }
                            Ok(Err(ScanError::ChecksumAlgorithmMismatch { expected, actual })) => {
                                warn!(
                                    target = "snapshot_validator",
                                    manifest = %worker_settings.manifest_path.display(),
                                    expected_algorithm = %expected.as_str(),
                                    actual_algorithm = %actual.as_str(),
                                    "snapshot manifest checksum algorithm mismatch",
                                );
                                ScanResult::Failure
                            }
                            Ok(Err(ScanError::Decode(err))) => {
                                warn!(
                                    target = "snapshot_validator",
                                    manifest = %worker_settings.manifest_path.display(),
                                    error = %err,
                                    "snapshot manifest decode failed",
                                );
                                ScanResult::Failure
                            }
                            Ok(Err(ScanError::Io(err))) => {
                                warn!(
                                    target = "snapshot_validator",
                                    manifest = %worker_settings.manifest_path.display(),
                                    error = %err,
                                    "snapshot validation I/O failure",
                                );
                                ScanResult::Failure
                            }
                            Err(err) => {
                                warn!(
                                    target = "snapshot_validator",
                                    error = %err,
                                    "snapshot validator worker task failed",
                                );
                                ScanResult::Failure
                            }
                        };

                        metrics.record_scan_end(scan_result, started_at.elapsed());
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
    VersionMismatch {
        expected: u32,
        actual: u32,
    },
    ChecksumAlgorithmMismatch {
        expected: SnapshotChecksumAlgorithm,
        actual: SnapshotChecksumAlgorithm,
    },
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

    if manifest.version != SNAPSHOT_MANIFEST_VERSION {
        return Err(ScanError::VersionMismatch {
            expected: SNAPSHOT_MANIFEST_VERSION,
            actual: manifest.version,
        });
    }

    let checksum_algorithm =
        resolve_manifest_algorithm(manifest.checksum_algorithm, settings.checksum_algorithm)?;

    let mut failures = Vec::new();
    for segment in manifest.segments {
        let Some(name) = segment.name.as_ref() else {
            continue;
        };
        let Some(expected_size) = segment.size_bytes else {
            continue;
        };
        let Some(expected_checksum) = segment.checksum.as_ref().or(segment.sha256.as_ref()) else {
            continue;
        };
        let expected_checksum = expected_checksum.to_lowercase();

        let path = settings.chunk_dir.join(name);
        match validate_chunk(&path, expected_size, &expected_checksum, checksum_algorithm) {
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
    algorithm: SnapshotChecksumAlgorithm,
) -> Result<Option<FailureKind>, io::Error> {
    if !path.exists() {
        return Ok(Some(FailureKind::Missing));
    }

    let metadata = path.metadata()?;
    if metadata.len() != expected_size {
        return Ok(Some(FailureKind::SizeMismatch));
    }

    let mut file = File::open(path)?;
    let mut hasher = SnapshotChecksumHasher::new(algorithm);
    let mut buffer = [0u8; 8 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    if !digest.eq_ignore_ascii_case(expected_checksum) {
        return Ok(Some(FailureKind::ChecksumMismatch));
    }

    Ok(None)
}

impl From<io::Error> for ScanError {
    fn from(err: io::Error) -> Self {
        ScanError::Io(err)
    }
}
