#![deny(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Duration, Instant};

use anyhow::Context;
use base64::Engine;
use blake2::{
    digest::{consts::U32, Digest},
    Blake2b,
};
use clap::ValueEnum;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use hex::FromHexError;
use metrics::counter;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use thiserror::Error;

const SNAPSHOT_VERIFY_RESULTS_METRIC: &str = "snapshot_verify_results_total";
const SNAPSHOT_VERIFY_FAILURE_METRIC: &str = "snapshot_verify_failures_total";
static SNAPSHOT_METRIC_REGISTER: Once = Once::new();

#[derive(Clone, Debug)]
pub enum DataSource {
    Path(PathBuf),
    Inline { label: String, data: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumAlgorithm {
    Sha256,
    Blake2b,
}

type Blake2b256 = Blake2b<U32>;

impl ChecksumAlgorithm {
    fn description(self) -> &'static str {
        match self {
            ChecksumAlgorithm::Sha256 => "sha256",
            ChecksumAlgorithm::Blake2b => "blake2b",
        }
    }
}

enum EitherHasher {
    Sha256(Sha256),
    Blake2b(Blake2b256),
}

impl EitherHasher {
    fn new(algorithm: ChecksumAlgorithm) -> Self {
        match algorithm {
            ChecksumAlgorithm::Sha256 => Self::Sha256(Sha256::new()),
            ChecksumAlgorithm::Blake2b => Self::Blake2b(Blake2b256::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            EitherHasher::Sha256(hasher) => hasher.update(data),
            EitherHasher::Blake2b(hasher) => hasher.update(data),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            EitherHasher::Sha256(hasher) => hasher.finalize().to_vec(),
            EitherHasher::Blake2b(hasher) => hasher.finalize().to_vec(),
        }
    }
}

impl DataSource {
    pub fn display(&self) -> String {
        match self {
            DataSource::Path(path) => path.display().to_string(),
            DataSource::Inline { label, .. } => label.clone(),
        }
    }

    fn read_to_string(&self) -> Result<String, String> {
        match self {
            DataSource::Path(path) => fs::read_to_string(path)
                .map_err(|err| format!("failed to read {}: {err}", path.display())),
            DataSource::Inline { data, .. } => Ok(data.clone()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifyArgs {
    pub manifest: PathBuf,
    pub signature: PathBuf,
    pub public_key: DataSource,
    pub chunk_root: Option<PathBuf>,
    pub verbose_progress: bool,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
}

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub manifest_path: String,
    pub signature_path: String,
    pub public_key_path: String,
    pub chunk_root: Option<String>,
    pub manifest_sha256: Option<String>,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    pub signature: Option<SignatureReport>,
    pub segments: Vec<SegmentReport>,
    pub summary: Option<SegmentSummary>,
    pub errors: Vec<String>,
}

impl VerificationReport {
    pub fn new(args: &VerifyArgs) -> Self {
        Self {
            manifest_path: args.manifest.display().to_string(),
            signature_path: args.signature.display().to_string(),
            public_key_path: args.public_key.display(),
            chunk_root: args
                .chunk_root
                .as_ref()
                .map(|path| path.display().to_string()),
            manifest_sha256: None,
            checksum_algorithm: None,
            signature: None,
            segments: Vec::new(),
            summary: None,
            errors: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct SignatureReport {
    pub algorithm: &'static str,
    pub manifest_digest: String,
    pub public_key_fingerprint: Option<String>,
    pub signature_valid: bool,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SegmentSummary {
    pub segments_total: usize,
    pub checksum_algorithm: ChecksumAlgorithm,
    pub metadata_incomplete: usize,
    pub verified: usize,
    pub missing_files: usize,
    pub size_mismatches: usize,
    pub checksum_mismatches: usize,
    pub io_errors: usize,
}

#[derive(Debug, Serialize)]
pub struct SegmentReport {
    pub segment: String,
    pub path: String,
    pub checksum_algorithm: ChecksumAlgorithm,
    pub status: SegmentStatus,
    pub expected_size: Option<u64>,
    pub actual_size: Option<u64>,
    pub expected_checksum: Option<String>,
    pub actual_checksum: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SegmentStatus {
    Verified,
    MissingMetadata,
    MissingFile,
    SizeMismatch,
    ChecksumMismatch,
    IoError,
}

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("hex decode failed: {0}")]
    Hex(#[from] FromHexError),
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
}

const SNAPSHOT_MANIFEST_VERSION: u32 = 1;
const DEFAULT_CHECKSUM_ALGORITHM: ChecksumAlgorithm = ChecksumAlgorithm::Sha256;

#[derive(Debug, Deserialize)]
struct SnapshotManifest {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    checksum_algorithm: Option<ChecksumAlgorithm>,
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

fn resolve_checksum_algorithm(
    manifest: &SnapshotManifest,
    override_algorithm: Option<ChecksumAlgorithm>,
) -> Result<ChecksumAlgorithm, String> {
    match (manifest.checksum_algorithm, override_algorithm) {
        (Some(manifest_alg), Some(requested)) if manifest_alg != requested => Err(format!(
            "snapshot manifest checksum algorithm mismatch (manifest={}, requested={})",
            manifest_alg.description(),
            requested.description(),
        )),
        (Some(manifest_alg), _) => Ok(manifest_alg),
        (None, Some(requested)) => Ok(requested),
        (None, None) => Ok(DEFAULT_CHECKSUM_ALGORITHM),
    }
}

#[derive(Debug)]
pub enum Execution {
    Completed { exit_code: ExitCode },
    Fatal { exit_code: ExitCode, error: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Success,
    SignatureInvalid,
    ChunkMismatch,
    Fatal,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        match self {
            ExitCode::Success => 0,
            ExitCode::SignatureInvalid => 2,
            ExitCode::ChunkMismatch => 3,
            ExitCode::Fatal => 1,
        }
    }
}

pub fn record_verification_outcome(exit_code: ExitCode, manifest: &Path) {
    SNAPSHOT_METRIC_REGISTER.call_once(|| {
        metrics::describe_counter!(
            SNAPSHOT_VERIFY_RESULTS_METRIC,
            "Total number of snapshot verification outcomes grouped by result"
        );
        metrics::describe_counter!(
            SNAPSHOT_VERIFY_FAILURE_METRIC,
            "Total number of snapshot verification failures observed while packaging release snapshots",
        );
    });

    let manifest_label = manifest.display().to_string();
    let (result_label, error_label) = match exit_code {
        ExitCode::Success => ("success", "none"),
        ExitCode::SignatureInvalid => ("failure", "signature_invalid"),
        ExitCode::ChunkMismatch => ("failure", "chunk_mismatch"),
        ExitCode::Fatal => ("failure", "fatal"),
    };

    counter!(
        SNAPSHOT_VERIFY_RESULTS_METRIC,
        "manifest" => manifest_label.clone(),
        "result" => result_label,
        "error" => error_label,
    )
    .increment(1);

    if result_label == "failure" {
        counter!(
            SNAPSHOT_VERIFY_FAILURE_METRIC,
            "manifest" => manifest_label,
            "exit_code" => error_label,
        )
        .increment(1);
    }
}

pub fn run_verification(args: &VerifyArgs, report: &mut VerificationReport) -> Execution {
    let manifest_bytes = match fs::read(&args.manifest) {
        Ok(bytes) => bytes,
        Err(err) => {
            return Execution::Fatal {
                exit_code: ExitCode::Fatal,
                error: format!("failed to read manifest {}: {err}", args.manifest.display()),
            }
        }
    };

    let manifest_sha256 = Sha256::digest(&manifest_bytes);
    report.manifest_sha256 = Some(hex::encode(manifest_sha256));

    let manifest: SnapshotManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(err) => {
            return Execution::Fatal {
                exit_code: ExitCode::Fatal,
                error: format!(
                    "failed to decode manifest {}: {err}",
                    args.manifest.display()
                ),
            }
        }
    };

    if manifest.version != SNAPSHOT_MANIFEST_VERSION {
        return Execution::Fatal {
            exit_code: ExitCode::Fatal,
            error: format!(
                "snapshot manifest version mismatch (expected {}, found {})",
                SNAPSHOT_MANIFEST_VERSION, manifest.version
            ),
        };
    }

    let checksum_algorithm = match resolve_checksum_algorithm(&manifest, args.checksum_algorithm) {
        Ok(algorithm) => algorithm,
        Err(err) => {
            return Execution::Fatal {
                exit_code: ExitCode::Fatal,
                error: err,
            };
        }
    };
    report.checksum_algorithm = Some(checksum_algorithm);

    let chunk_root = match determine_chunk_root(args) {
        Ok(root) => root,
        Err(err) => {
            return Execution::Fatal {
                exit_code: ExitCode::Fatal,
                error: err,
            }
        }
    };
    report.chunk_root = Some(chunk_root.display().to_string());

    let mut exit_code = ExitCode::Success;

    match verify_signature(&manifest_bytes, &args.signature, &args.public_key) {
        Ok(signature_report) => {
            if !signature_report.signature_valid {
                exit_code = ExitCode::SignatureInvalid;
            }
            report.signature = Some(signature_report);
        }
        Err(err) => {
            report.signature = Some(SignatureReport {
                algorithm: "ed25519",
                manifest_digest: report.manifest_sha256.clone().unwrap_or_default(),
                public_key_fingerprint: None,
                signature_valid: false,
                error: Some(err.clone()),
            });
            return Execution::Fatal {
                exit_code: ExitCode::Fatal,
                error: err,
            };
        }
    }

    let (segments, summary) = verify_segments(
        &manifest,
        &chunk_root,
        checksum_algorithm,
        args.verbose_progress,
    );
    if summary.metadata_incomplete > 0
        || summary.missing_files > 0
        || summary.size_mismatches > 0
        || summary.checksum_mismatches > 0
        || summary.io_errors > 0
    {
        exit_code = ExitCode::ChunkMismatch;
    }
    report.segments = segments;
    report.summary = Some(summary);

    Execution::Completed { exit_code }
}

fn determine_chunk_root(args: &VerifyArgs) -> Result<PathBuf, String> {
    if let Some(root) = args.chunk_root.as_ref() {
        return Ok(root.clone());
    }
    let parent = args.manifest.parent().ok_or_else(|| {
        format!(
            "manifest {} has no parent directory",
            args.manifest.display()
        )
    })?;
    let grand_parent = parent.parent().unwrap_or(parent);
    Ok(grand_parent.join("chunks"))
}

fn verify_signature(
    manifest_bytes: &[u8],
    signature_path: &Path,
    public_key: &DataSource,
) -> Result<SignatureReport, String> {
    let signature_raw = fs::read_to_string(signature_path).map_err(|err| {
        format!(
            "failed to read signature {}: {err}",
            signature_path.display()
        )
    })?;
    let public_key_raw = public_key.read_to_string()?;

    let signature_bytes = decode_data(&signature_raw).map_err(|err| {
        format!(
            "failed to decode signature {}: {err}",
            signature_path.display()
        )
    })?;
    let public_key_bytes = decode_data(&public_key_raw).map_err(|err| {
        let label = public_key.display();
        format!("failed to decode public key {label}: {err}")
    })?;

    let signature_array: [u8; Signature::BYTE_SIZE] =
        signature_bytes.as_slice().try_into().map_err(|_| {
            format!(
                "signature {} has invalid length {}; expected {} bytes",
                signature_path.display(),
                signature_bytes.len(),
                Signature::BYTE_SIZE
            )
        })?;
    let public_key_array: [u8; PUBLIC_KEY_LENGTH] =
        public_key_bytes.as_slice().try_into().map_err(|_| {
            let label = public_key.display();
            format!(
                "public key {label} has invalid length {}; expected {} bytes",
                public_key_bytes.len(),
                PUBLIC_KEY_LENGTH
            )
        })?;

    let verifying_key = VerifyingKey::from_bytes(&public_key_array).map_err(|err| {
        let label = public_key.display();
        format!("invalid public key {label}: {err}")
    })?;
    let signature = Signature::from_bytes(&signature_array);

    let manifest_digest = hex::encode(Sha256::digest(manifest_bytes));
    let mut fingerprint_hasher = Sha256::new();
    fingerprint_hasher.update(public_key_array);
    let fingerprint = hex::encode(fingerprint_hasher.finalize());

    let verification_error = verifying_key
        .verify(manifest_bytes, &signature)
        .err()
        .map(|err| err.to_string());
    let signature_valid = verification_error.is_none();

    Ok(SignatureReport {
        algorithm: "ed25519",
        manifest_digest,
        public_key_fingerprint: Some(fingerprint),
        signature_valid,
        error: verification_error,
    })
}

fn verify_segments(
    manifest: &SnapshotManifest,
    chunk_root: &Path,
    checksum_algorithm: ChecksumAlgorithm,
    verbose_progress: bool,
) -> (Vec<SegmentReport>, SegmentSummary) {
    let mut reports = Vec::new();
    let mut metadata_incomplete = 0;
    let mut verified = 0;
    let mut missing_files = 0;
    let mut size_mismatches = 0;
    let mut checksum_mismatches = 0;
    let mut io_errors = 0;

    for (index, segment) in manifest.segments.iter().enumerate() {
        let name = segment
            .name
            .as_ref()
            .cloned()
            .unwrap_or_else(|| format!("segment_{index}"));
        let expected_size = match segment.size_bytes {
            Some(size) => size,
            None => {
                metadata_incomplete += 1;
                reports.push(SegmentReport {
                    segment: name.clone(),
                    path: chunk_root.join(&name).display().to_string(),
                    checksum_algorithm,
                    status: SegmentStatus::MissingMetadata,
                    expected_size: None,
                    actual_size: None,
                    expected_checksum: None,
                    actual_checksum: None,
                    error: Some("segment missing required metadata".to_string()),
                });
                continue;
            }
        };
        let expected_checksum = match segment
            .checksum
            .as_ref()
            .or(segment.sha256.as_ref())
            .map(|s| s.to_lowercase())
        {
            Some(checksum) => checksum,
            None => {
                metadata_incomplete += 1;
                reports.push(SegmentReport {
                    segment: name.clone(),
                    path: chunk_root.join(&name).display().to_string(),
                    checksum_algorithm,
                    status: SegmentStatus::MissingMetadata,
                    expected_size: Some(expected_size),
                    actual_size: None,
                    expected_checksum: None,
                    actual_checksum: None,
                    error: Some("segment missing required metadata".to_string()),
                });
                continue;
            }
        };
        let path = chunk_root.join(&name);

        let (status, actual_size, actual_checksum, error) = match fs::metadata(&path) {
            Ok(metadata) => {
                let size = metadata.len();
                if size != expected_size {
                    (SegmentStatus::SizeMismatch, Some(size), None, None)
                } else {
                    match compute_checksum(
                        &path,
                        Some(expected_size),
                        checksum_algorithm,
                        verbose_progress,
                    ) {
                        Ok(actual_hash) => {
                            if actual_hash == expected_checksum {
                                (SegmentStatus::Verified, Some(size), Some(actual_hash), None)
                            } else {
                                (
                                    SegmentStatus::ChecksumMismatch,
                                    Some(size),
                                    Some(actual_hash),
                                    None,
                                )
                            }
                        }
                        Err(err) => (SegmentStatus::IoError, Some(size), None, Some(err)),
                    }
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => (
                SegmentStatus::MissingFile,
                None,
                None,
                Some("file not found".to_string()),
            ),
            Err(err) => (SegmentStatus::IoError, None, None, Some(err.to_string())),
        };

        match status {
            SegmentStatus::Verified => verified += 1,
            SegmentStatus::MissingMetadata => {}
            SegmentStatus::MissingFile => missing_files += 1,
            SegmentStatus::SizeMismatch => size_mismatches += 1,
            SegmentStatus::ChecksumMismatch => checksum_mismatches += 1,
            SegmentStatus::IoError => io_errors += 1,
        }

        reports.push(SegmentReport {
            segment: name,
            path: path.display().to_string(),
            checksum_algorithm,
            status,
            expected_size: Some(expected_size),
            actual_size,
            expected_checksum: Some(expected_checksum),
            actual_checksum,
            error,
        });
    }

    let summary = SegmentSummary {
        segments_total: manifest.segments.len(),
        checksum_algorithm,
        metadata_incomplete,
        verified,
        missing_files,
        size_mismatches,
        checksum_mismatches,
        io_errors,
    };

    (reports, summary)
}

fn compute_checksum(
    path: &Path,
    expected_size: Option<u64>,
    algorithm: ChecksumAlgorithm,
    verbose_progress: bool,
) -> Result<String, String> {
    let progress: Option<ProgressReporter<io::StderrLock<'static>>> = if verbose_progress {
        Some(ProgressReporter::stderr(
            expected_size,
            PROGRESS_LOG_INTERVAL,
        ))
    } else {
        None
    };

    compute_checksum_from_reader(
        fs::File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?,
        path,
        algorithm,
        progress,
    )
}

fn compute_checksum_from_reader<R: Read, W: Write>(
    mut reader: R,
    path: &Path,
    algorithm: ChecksumAlgorithm,
    mut progress: Option<ProgressReporter<W>>,
) -> Result<String, String> {
    let mut buffer = [0u8; 8192];
    let mut hasher = EitherHasher::new(algorithm);

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(len) => {
                hasher.update(&buffer[..len]);
                counter!(SNAPSHOT_CHECKSUM_BYTES_METRIC, "file" => path.display().to_string())
                    .increment(len as u64);
                if let Some(reporter) = progress.as_mut() {
                    reporter
                        .record(len as u64)
                        .map_err(|err| format!("failed to log progress: {err}"))?;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
        }
    }

    if let Some(reporter) = progress.as_mut() {
        reporter
            .finish()
            .map_err(|err| format!("failed to log progress: {err}"))?;
    }

    Ok(hex::encode(hasher.finalize()))
}

const SNAPSHOT_CHECKSUM_BYTES_METRIC: &str = "snapshot_client_checksum_bytes_total";

#[cfg(test)]
const PROGRESS_LOG_INTERVAL: u64 = 1024;

#[cfg(not(test))]
const PROGRESS_LOG_INTERVAL: u64 = 8 * 1024 * 1024;

struct ProgressReporter<W: Write> {
    writer: W,
    expected_size: Option<u64>,
    interval: u64,
    bytes_read: u64,
    next_log: u64,
    started_at: Instant,
}

impl ProgressReporter<io::StderrLock<'static>> {
    fn stderr(
        expected_size: Option<u64>,
        interval: u64,
    ) -> ProgressReporter<io::StderrLock<'static>> {
        ProgressReporter::new(io::stderr().lock(), expected_size, interval)
    }
}

impl<W: Write> ProgressReporter<W> {
    fn new(writer: W, expected_size: Option<u64>, interval: u64) -> Self {
        Self {
            writer,
            expected_size,
            interval: interval.max(1),
            bytes_read: 0,
            next_log: interval.max(1),
            started_at: Instant::now(),
        }
    }

    fn record(&mut self, delta: u64) -> io::Result<()> {
        self.bytes_read = self.bytes_read.saturating_add(delta);
        while self.bytes_read >= self.next_log {
            self.log_progress()?;
            self.next_log = self.next_log.saturating_add(self.interval);
        }
        Ok(())
    }

    fn finish(&mut self) -> io::Result<()> {
        if self.bytes_read > 0 {
            self.log_progress()?;
        }
        Ok(())
    }

    fn log_progress(&mut self) -> io::Result<()> {
        let total_bytes = self.expected_size;
        let bytes_per_second = rate_bytes_per_second(self.bytes_read, self.started_at.elapsed());
        let checksum_progress = total_bytes.map(|total| progress_ratio(self.bytes_read, total));

        let entry = json!({
            "event": "checksum_progress",
            "bytes_downloaded": self.bytes_read,
            "total_bytes": total_bytes,
            "bytes_per_second": bytes_per_second,
            "checksum_progress": checksum_progress,
        });

        serde_json::to_writer(&mut self.writer, &entry)?;
        self.writer.write_all(b"\n")
    }
}

fn rate_bytes_per_second(bytes_read: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds <= f64::EPSILON {
        0.0
    } else {
        bytes_read as f64 / seconds
    }
}

fn progress_ratio(bytes_read: u64, total_bytes: u64) -> f64 {
    if total_bytes == 0 {
        0.0
    } else {
        (bytes_read as f64 / total_bytes as f64).min(1.0)
    }
}

fn decode_data(value: &str) -> Result<Vec<u8>, DecodeError> {
    let filtered: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    match hex::decode(&filtered) {
        Ok(bytes) => Ok(bytes),
        Err(_) => {
            let bytes = base64::engine::general_purpose::STANDARD.decode(&filtered)?;
            Ok(bytes)
        }
    }
}

pub fn write_report(report: &VerificationReport, output: Option<&Path>) -> anyhow::Result<()> {
    let json = serde_json::to_vec_pretty(report)?;
    if let Some(path) = output {
        fs::write(path, &json).with_context(|| format!("write report to {}", path.display()))?;
    } else {
        io::stdout()
            .write_all(&json)
            .context("write report to stdout")?;
        println!();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use ed25519_dalek::{Signer, SigningKey};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use serde_json::{json, Value};
    use std::convert::TryFrom;
    use std::error::Error;
    use std::io::Cursor;
    use std::sync::OnceLock;
    use tempfile::TempDir;

    static PROMETHEUS: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();

    fn prometheus_handle() -> &'static metrics_exporter_prometheus::PrometheusHandle {
        PROMETHEUS.get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("install prometheus recorder")
        })
    }

    fn deterministic_signing_key(seed: u8) -> SigningKey {
        let secret_bytes = [seed; 32];
        SigningKey::try_from(&secret_bytes).expect("valid seed")
    }

    fn write_manifest(
        dir: &TempDir,
        segments: &[(&str, &[u8])],
        algorithm: ChecksumAlgorithm,
    ) -> (PathBuf, PathBuf) {
        let manifest_dir = dir.path().join("manifest");
        let chunk_dir = dir.path().join("chunks");
        fs::create_dir_all(&manifest_dir).unwrap();
        fs::create_dir_all(&chunk_dir).unwrap();

        let mut manifest_segments = Vec::new();
        for (index, (name, data)) in segments.iter().enumerate() {
            let path = chunk_dir.join(name);
            fs::write(&path, data).unwrap();
            let checksum = match algorithm {
                ChecksumAlgorithm::Sha256 => hex::encode(Sha256::digest(data)),
                ChecksumAlgorithm::Blake2b => hex::encode(Blake2b256::digest(data)),
            };
            let mut segment = json!({
                "segment_name": name,
                "size_bytes": data.len(),
                "checksum": checksum,
                "index": index,
            });
            if algorithm == ChecksumAlgorithm::Sha256 {
                segment
                    .as_object_mut()
                    .unwrap()
                    .insert("sha256".to_string(), json!(checksum));
            }
            manifest_segments.push(segment);
        }

        let manifest = json!({
            "version": 1,
            "checksum_algorithm": algorithm,
            "generated_at": "2024-01-01T00:00:00Z",
            "segments": manifest_segments,
        });
        let manifest_path = manifest_dir.join("chunks.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        (manifest_path, chunk_dir)
    }

    #[test]
    fn surfaces_missing_segment_metadata() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let chunk_root = temp.path().join("chunks");
        fs::create_dir_all(&chunk_root)?;

        let manifest = SnapshotManifest {
            version: SNAPSHOT_MANIFEST_VERSION,
            checksum_algorithm: Some(ChecksumAlgorithm::Sha256),
            segments: vec![ManifestSegment {
                name: Some("chunk-0.bin".to_string()),
                size_bytes: None,
                checksum: None,
                sha256: None,
            }],
        };

        let (reports, summary) =
            verify_segments(&manifest, &chunk_root, ChecksumAlgorithm::Sha256, false);

        assert_eq!(summary.metadata_incomplete, 1);
        assert_eq!(summary.verified, 0);
        assert_matches!(
            reports.first().map(|r| &r.status),
            Some(SegmentStatus::MissingMetadata)
        );
        assert_eq!(
            reports.first().and_then(|report| report.error.as_deref()),
            Some("segment missing required metadata"),
        );

        Ok(())
    }

    #[test]
    fn surfaces_checksum_mismatches() -> Result<(), Box<dyn Error>> {
        let temp = TempDir::new()?;
        let chunk_root = temp.path().join("chunks");
        fs::create_dir_all(&chunk_root)?;

        let path = chunk_root.join("chunk-0.bin");
        fs::write(&path, b"hello world")?;
        let incorrect_checksum = hex::encode(Sha256::digest(b"different"));

        let manifest = SnapshotManifest {
            version: SNAPSHOT_MANIFEST_VERSION,
            checksum_algorithm: Some(ChecksumAlgorithm::Sha256),
            segments: vec![ManifestSegment {
                name: Some("chunk-0.bin".to_string()),
                size_bytes: Some(11),
                checksum: Some(incorrect_checksum.clone()),
                sha256: None,
            }],
        };

        let (reports, summary) =
            verify_segments(&manifest, &chunk_root, ChecksumAlgorithm::Sha256, false);

        assert_eq!(summary.checksum_mismatches, 1);
        assert_eq!(summary.verified, 0);
        assert_matches!(
            reports.first().map(|r| &r.status),
            Some(SegmentStatus::ChecksumMismatch)
        );
        assert_eq!(
            reports.first().and_then(|r| r.expected_checksum.as_deref()),
            Some(incorrect_checksum.as_str())
        );
        assert_ne!(
            reports.first().and_then(|r| r.actual_checksum.as_deref()),
            Some(incorrect_checksum.as_str())
        );

        Ok(())
    }

    #[test]
    fn verify_valid_manifest() {
        let temp = TempDir::new().unwrap();
        let (manifest_path, chunk_dir) = write_manifest(
            &temp,
            &[("chunk-0.bin", b"hello"), ("chunk-1.bin", b"world")],
            ChecksumAlgorithm::Sha256,
        );

        let signing_key = deterministic_signing_key(1);
        let verifying_key = signing_key.verifying_key();
        let manifest_bytes = fs::read(&manifest_path).unwrap();
        let signature = signing_key.sign(&manifest_bytes);

        let signature_path = temp.path().join("chunks.json.sig");
        fs::write(&signature_path, hex::encode(signature.to_bytes())).unwrap();

        let args = VerifyArgs {
            manifest: manifest_path.clone(),
            signature: signature_path.clone(),
            public_key: DataSource::Inline {
                label: "inline".to_string(),
                data: hex::encode(verifying_key.to_bytes()),
            },
            chunk_root: Some(chunk_dir.clone()),
            verbose_progress: false,
            checksum_algorithm: None,
        };
        let mut report = VerificationReport::new(&args);
        let result = run_verification(&args, &mut report);
        assert_matches!(
            result,
            Execution::Completed {
                exit_code: ExitCode::Success
            }
        );
        assert_eq!(report.summary.as_ref().unwrap().verified, 2);
        assert!(report.signature.as_ref().unwrap().signature_valid);
    }

    #[test]
    fn detect_checksum_mismatch() {
        let temp = TempDir::new().unwrap();
        let (manifest_path, chunk_dir) = write_manifest(
            &temp,
            &[("chunk-0.bin", b"hello")],
            ChecksumAlgorithm::Sha256,
        );

        fs::write(chunk_dir.join("chunk-0.bin"), b"xxxxx").unwrap();

        let signing_key = deterministic_signing_key(2);
        let verifying_key = signing_key.verifying_key();
        let manifest_bytes = fs::read(&manifest_path).unwrap();
        let signature = signing_key.sign(&manifest_bytes);

        let signature_path = temp.path().join("chunks.json.sig");
        fs::write(&signature_path, hex::encode(signature.to_bytes())).unwrap();

        let args = VerifyArgs {
            manifest: manifest_path.clone(),
            signature: signature_path.clone(),
            public_key: DataSource::Inline {
                label: "inline".to_string(),
                data: hex::encode(verifying_key.to_bytes()),
            },
            chunk_root: Some(chunk_dir.clone()),
            verbose_progress: false,
            checksum_algorithm: None,
        };
        let mut report = VerificationReport::new(&args);
        let result = run_verification(&args, &mut report);
        assert_matches!(
            result,
            Execution::Completed {
                exit_code: ExitCode::ChunkMismatch
            }
        );
        let summary = report.summary.unwrap();
        assert_eq!(summary.checksum_mismatches, 1);
        assert!(report.signature.unwrap().signature_valid);
    }

    #[test]
    fn verify_blake2b_manifest() {
        let temp = TempDir::new().unwrap();
        let (manifest_path, chunk_dir) = write_manifest(
            &temp,
            &[("chunk-0.bin", b"hello blake2b")],
            ChecksumAlgorithm::Blake2b,
        );

        let signing_key = deterministic_signing_key(4);
        let verifying_key = signing_key.verifying_key();
        let manifest_bytes = fs::read(&manifest_path).unwrap();
        let signature = signing_key.sign(&manifest_bytes);

        let signature_path = temp.path().join("chunks.json.sig");
        fs::write(&signature_path, hex::encode(signature.to_bytes())).unwrap();

        let args = VerifyArgs {
            manifest: manifest_path.clone(),
            signature: signature_path.clone(),
            public_key: DataSource::Inline {
                label: "inline".to_string(),
                data: hex::encode(verifying_key.to_bytes()),
            },
            chunk_root: Some(chunk_dir.clone()),
            verbose_progress: false,
            checksum_algorithm: None,
        };

        let mut report = VerificationReport::new(&args);
        let result = run_verification(&args, &mut report);
        assert_matches!(
            result,
            Execution::Completed {
                exit_code: ExitCode::Success
            }
        );
        let summary = report.summary.unwrap();
        assert_eq!(summary.verified, 1);
        assert_eq!(summary.checksum_algorithm, ChecksumAlgorithm::Blake2b);
    }

    #[test]
    fn checksum_algorithm_mismatch_is_fatal() {
        let temp = TempDir::new().unwrap();
        let (manifest_path, chunk_dir) = write_manifest(
            &temp,
            &[("chunk-0.bin", b"hello blake2b")],
            ChecksumAlgorithm::Blake2b,
        );

        let signing_key = deterministic_signing_key(5);
        let verifying_key = signing_key.verifying_key();
        let manifest_bytes = fs::read(&manifest_path).unwrap();
        let signature = signing_key.sign(&manifest_bytes);

        let signature_path = temp.path().join("chunks.json.sig");
        fs::write(&signature_path, hex::encode(signature.to_bytes())).unwrap();

        let args = VerifyArgs {
            manifest: manifest_path.clone(),
            signature: signature_path.clone(),
            public_key: DataSource::Inline {
                label: "inline".to_string(),
                data: hex::encode(verifying_key.to_bytes()),
            },
            chunk_root: Some(chunk_dir.clone()),
            verbose_progress: false,
            checksum_algorithm: Some(ChecksumAlgorithm::Sha256),
        };

        let mut report = VerificationReport::new(&args);
        let result = run_verification(&args, &mut report);
        match result {
            Execution::Fatal { exit_code, error } => {
                assert_eq!(exit_code, ExitCode::Fatal);
                assert!(error.contains("checksum algorithm mismatch"));
            }
            other => panic!("expected fatal checksum mismatch, got {other:?}"),
        }
    }

    fn counter_value(metrics: &str, name: &str, key: &str, value: &str) -> f64 {
        metrics
            .lines()
            .find_map(|line| {
                if !line.starts_with(name) {
                    return None;
                }

                let matcher = format!("{key}=\"{value}\"");
                if !line.contains(&matcher) {
                    return None;
                }

                line.split_whitespace()
                    .last()
                    .and_then(|v| v.parse::<f64>().ok())
            })
            .unwrap_or_default()
    }

    fn execution_exit_code(execution: Execution) -> ExitCode {
        match execution {
            Execution::Completed { exit_code } => exit_code,
            Execution::Fatal { exit_code, .. } => exit_code,
        }
    }

    #[test]
    fn tampered_signature_increments_failure_metrics() {
        let handle = prometheus_handle();
        let baseline = handle.render();

        let temp = TempDir::new().unwrap();
        let (manifest_path, chunk_dir) = write_manifest(
            &temp,
            &[("chunk-0.bin", b"hello")],
            ChecksumAlgorithm::Sha256,
        );

        let signing_key = deterministic_signing_key(3);
        let verifying_key = signing_key.verifying_key();
        let manifest_bytes = fs::read(&manifest_path).unwrap();
        let signature_path = temp.path().join("chunks.json.sig");
        fs::write(
            &signature_path,
            hex::encode(signing_key.sign(&manifest_bytes).to_bytes()),
        )
        .unwrap();

        let args = VerifyArgs {
            manifest: manifest_path.clone(),
            signature: signature_path.clone(),
            public_key: DataSource::Inline {
                label: "inline".to_string(),
                data: hex::encode(verifying_key.to_bytes()),
            },
            chunk_root: Some(chunk_dir.clone()),
            verbose_progress: false,
            checksum_algorithm: None,
        };

        let mut success_report = VerificationReport::new(&args);
        let success_code = execution_exit_code(run_verification(&args, &mut success_report));
        assert_eq!(success_code, ExitCode::Success);
        record_verification_outcome(success_code, &manifest_path);

        let tampered_signature = deterministic_signing_key(7).sign(&manifest_bytes);
        fs::write(&signature_path, hex::encode(tampered_signature.to_bytes())).unwrap();

        for _ in 0..2 {
            let mut report = VerificationReport::new(&args);
            let exit_code = execution_exit_code(run_verification(&args, &mut report));
            assert_eq!(exit_code, ExitCode::SignatureInvalid);
            record_verification_outcome(exit_code, &manifest_path);
        }

        let metrics = handle.render();
        let success_delta = counter_value(
            &metrics,
            SNAPSHOT_VERIFY_RESULTS_METRIC,
            "result",
            "success",
        ) - counter_value(
            &baseline,
            SNAPSHOT_VERIFY_RESULTS_METRIC,
            "result",
            "success",
        );
        let failure_delta = counter_value(
            &metrics,
            SNAPSHOT_VERIFY_RESULTS_METRIC,
            "result",
            "failure",
        ) - counter_value(
            &baseline,
            SNAPSHOT_VERIFY_RESULTS_METRIC,
            "result",
            "failure",
        );
        let signature_delta = counter_value(
            &metrics,
            SNAPSHOT_VERIFY_FAILURE_METRIC,
            "exit_code",
            "signature_invalid",
        ) - counter_value(
            &baseline,
            SNAPSHOT_VERIFY_FAILURE_METRIC,
            "exit_code",
            "signature_invalid",
        );

        assert!(success_delta >= 1.0, "success outcomes should be counted");
        assert!(
            failure_delta >= 2.0,
            "two tampered runs should count as failures: {metrics}"
        );
        assert!(
            signature_delta >= 2.0,
            "signature failures should flow to the dedicated counter"
        );

        let total_runs = success_delta + failure_delta;
        assert!(
            total_runs >= 3.0,
            "expected at least three verification attempts recorded"
        );

        let failure_rate = failure_delta / total_runs;
        assert!(
            failure_rate > 0.5,
            "tampered signatures should push the failure ratio above alert thresholds"
        );
    }

    #[test]
    fn failure_rate_alerts_reference_results_metric() {
        let alerts_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/observability/alerts/compliance_controls.yaml");
        let contents =
            fs::read_to_string(&alerts_path).expect("read compliance controls alert file");
        let document: serde_yaml::Value =
            serde_yaml::from_str(&contents).expect("parse alert yaml");

        let mut expressions = Vec::new();
        if let Some(groups) = document
            .get("spec")
            .and_then(|spec| spec.get("groups"))
            .and_then(|groups| groups.as_sequence())
        {
            for group in groups {
                if let Some(rules) = group.get("rules").and_then(|rules| rules.as_sequence()) {
                    for rule in rules {
                        if let Some(alert_name) = rule.get("alert").and_then(|alert| alert.as_str())
                        {
                            if alert_name.starts_with("SnapshotVerifierFailureRate") {
                                if let Some(expr) = rule.get("expr").and_then(|expr| expr.as_str())
                                {
                                    expressions.push(expr.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        assert!(
            !expressions.is_empty(),
            "expected snapshot verifier failure rate alerts to be defined"
        );

        for expr in expressions {
            assert!(
                expr.contains("snapshot_verify_results_total{result=\"failure\"}"),
                "alert should track failure-labelled outcomes: {expr}"
            );
            assert!(
                expr.contains("snapshot_verify_results_total"),
                "alert should compute rates using the aggregated results counter: {expr}"
            );
        }
    }

    #[test]
    fn streams_progress_with_expected_size() {
        let data = vec![0u8; (3 * PROGRESS_LOG_INTERVAL as usize) + 512];
        let mut log_buffer = Vec::new();
        let expected = Sha256::digest(&data);

        let reporter = ProgressReporter::new(
            &mut log_buffer,
            Some(data.len() as u64),
            PROGRESS_LOG_INTERVAL,
        );

        let digest = compute_checksum_from_reader(
            Cursor::new(&data),
            Path::new("mock.bin"),
            ChecksumAlgorithm::Sha256,
            Some(reporter),
        )
        .expect("checksum succeeds");

        assert_eq!(digest, hex::encode(expected));

        let output = String::from_utf8(log_buffer).expect("utf8 log");
        let lines: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).expect("json line"))
            .collect();

        assert!(lines.len() >= 3);

        let mut last_bytes = 0;
        for entry in &lines {
            assert_eq!(entry["event"], "checksum_progress");
            assert_eq!(entry["total_bytes"], Value::from(data.len() as u64));
            let bytes_downloaded = entry["bytes_downloaded"]
                .as_u64()
                .expect("bytes_downloaded");
            assert!(bytes_downloaded >= last_bytes);
            last_bytes = bytes_downloaded;
            assert!(entry["bytes_per_second"].as_f64().expect("rate") >= 0.0);
            let progress = entry["checksum_progress"].as_f64().expect("progress");
            assert!(progress >= 0.0 && progress <= 1.0);
        }

        let final_entry = lines.last().expect("final progress entry");
        assert_eq!(
            final_entry["bytes_downloaded"],
            Value::from(data.len() as u64)
        );
        assert_eq!(final_entry["checksum_progress"], Value::from(1.0));
    }

    #[test]
    fn streams_progress_without_known_size() {
        let data = vec![1u8; (2 * PROGRESS_LOG_INTERVAL as usize) + 128];
        let mut log_buffer = Vec::new();

        let reporter = ProgressReporter::new(&mut log_buffer, None, PROGRESS_LOG_INTERVAL);

        let digest = compute_checksum_from_reader(
            Cursor::new(&data),
            Path::new("mock.bin"),
            ChecksumAlgorithm::Sha256,
            Some(reporter),
        )
        .expect("checksum succeeds");

        assert_eq!(digest, hex::encode(Sha256::digest(&data)));

        let output = String::from_utf8(log_buffer).expect("utf8 log");
        let lines: Vec<Value> = output
            .lines()
            .map(|line| serde_json::from_str(line).expect("json line"))
            .collect();

        assert!(!lines.is_empty());

        let mut last_bytes = 0;
        for entry in &lines {
            assert_eq!(entry["event"], "checksum_progress");
            assert!(entry["total_bytes"].is_null());
            let bytes_downloaded = entry["bytes_downloaded"]
                .as_u64()
                .expect("bytes_downloaded");
            assert!(bytes_downloaded >= last_bytes);
            last_bytes = bytes_downloaded;
            assert!(entry["bytes_per_second"].as_f64().expect("rate") >= 0.0);
            assert!(entry["checksum_progress"].is_null());
        }

        assert_eq!(
            lines
                .last()
                .expect("final entry")
                .get("bytes_downloaded")
                .and_then(|v| v.as_u64()),
            Some(data.len() as u64)
        );
    }
}
