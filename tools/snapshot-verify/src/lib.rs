use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};
use hex::FromHexError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Debug)]
pub enum DataSource {
    Path(PathBuf),
    Inline { label: String, data: String },
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
}

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub manifest_path: String,
    pub signature_path: String,
    pub public_key_path: String,
    pub chunk_root: Option<String>,
    pub manifest_sha256: Option<String>,
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

#[derive(Debug, Deserialize)]
struct SnapshotManifest {
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

    let (segments, summary) = verify_segments(&manifest, &chunk_root);
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
        let expected_size = segment.size_bytes;
        let expected_checksum = segment.sha256.as_ref().map(|s| s.to_lowercase());
        let path = chunk_root.join(&name);

        if segment.name.is_none() || expected_size.is_none() || expected_checksum.is_none() {
            metadata_incomplete += 1;
            reports.push(SegmentReport {
                segment: name,
                path: path.display().to_string(),
                status: SegmentStatus::MissingMetadata,
                expected_size,
                actual_size: None,
                expected_checksum: segment.sha256.clone(),
                actual_checksum: None,
                error: Some("segment missing required metadata".to_string()),
            });
            continue;
        }

        let (status, actual_size, actual_checksum, error) = match fs::metadata(&path) {
            Ok(metadata) => {
                let size = metadata.len();
                if size != expected_size.unwrap() {
                    (SegmentStatus::SizeMismatch, Some(size), None, None)
                } else {
                    match compute_sha256(&path) {
                        Ok(actual_hash) => {
                            if actual_hash == expected_checksum.as_deref().unwrap() {
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
            status,
            expected_size,
            actual_size,
            expected_checksum: segment.sha256.clone(),
            actual_checksum,
            error,
        });
    }

    let summary = SegmentSummary {
        segments_total: manifest.segments.len(),
        metadata_incomplete,
        verified,
        missing_files,
        size_mismatches,
        checksum_mismatches,
        io_errors,
    };

    (reports, summary)
}

fn compute_sha256(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|err| format!("failed to open {}: {err}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(len) => {
                hasher.update(&buffer[..len]);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(format!("failed to read {}: {err}", path.display())),
        }
    }
    Ok(hex::encode(hasher.finalize()))
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
    use serde_json::json;
    use std::convert::TryFrom;
    use tempfile::TempDir;

    fn deterministic_signing_key(seed: u8) -> SigningKey {
        let secret_bytes = [seed; 32];
        SigningKey::try_from(&secret_bytes).expect("valid seed")
    }

    fn write_manifest(dir: &TempDir, segments: &[(&str, &[u8])]) -> (PathBuf, PathBuf) {
        let manifest_dir = dir.path().join("manifest");
        let chunk_dir = dir.path().join("chunks");
        fs::create_dir_all(&manifest_dir).unwrap();
        fs::create_dir_all(&chunk_dir).unwrap();

        let mut manifest_segments = Vec::new();
        for (index, (name, data)) in segments.iter().enumerate() {
            let path = chunk_dir.join(name);
            fs::write(&path, data).unwrap();
            let mut hasher = Sha256::new();
            hasher.update(data);
            let checksum = hex::encode(hasher.finalize());
            manifest_segments.push(json!({
                "segment_name": name,
                "size_bytes": data.len(),
                "sha256": checksum,
                "index": index,
            }));
        }

        let manifest = json!({
            "version": 1,
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
    fn verify_valid_manifest() {
        let temp = TempDir::new().unwrap();
        let (manifest_path, chunk_dir) = write_manifest(
            &temp,
            &[("chunk-0.bin", b"hello"), ("chunk-1.bin", b"world")],
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
        let (manifest_path, chunk_dir) = write_manifest(&temp, &[("chunk-0.bin", b"hello")]);

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
}
