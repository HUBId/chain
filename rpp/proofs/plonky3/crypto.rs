use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use blake3::hash as blake3_hash;
use flate2::read::GzDecoder;
use once_cell::sync::{Lazy, OnceCell};
use parking_lot::RwLock;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::error;

use crate::errors::{ChainError, ChainResult};
pub use plonky3_backend::COMMITMENT_LEN;
use plonky3_backend::{self as backend, validate_consensus_public_inputs, AirMetadata};

use super::params::Plonky3Parameters;

pub use super::public_inputs::compute_commitment;
pub(crate) use super::public_inputs::compute_commitment_and_inputs;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum BackendErrorCategory {
    Key,
    Input,
    Runtime,
}

impl BackendErrorCategory {
    fn as_str(&self) -> &'static str {
        match self {
            BackendErrorCategory::Key => "key",
            BackendErrorCategory::Input => "input",
            BackendErrorCategory::Runtime => "runtime",
        }
    }
}

fn categorize_backend_error(err: &backend::BackendError) -> BackendErrorCategory {
    use backend::BackendError as Error;

    match err {
        Error::EmptyCircuit
        | Error::MissingVerifyingKey(_)
        | Error::MissingProvingKey(_)
        | Error::VerifyingKeyMismatch(_)
        | Error::InvalidKeyEncoding { .. }
        | Error::UnsupportedProvingAir { .. }
        | Error::SetupManifest(_)
        | Error::SetupManifestMissing(_)
        | Error::SetupArtifactMismatch { .. }
        | Error::InvalidAirMetadata(_)
        | Error::InsufficientSecurity { .. } => BackendErrorCategory::Key,
        Error::InvalidProofLength { .. }
        | Error::PublicInputDigestMismatch(_)
        | Error::CanonicalPublicInputMismatch(_)
        | Error::FriDigestMismatch(_)
        | Error::TranscriptMismatch(_)
        | Error::InvalidProofShape { .. }
        | Error::OpeningArgumentMismatch { .. }
        | Error::ConstraintMismatch { .. }
        | Error::RandomizationInconsistency { .. }
        | Error::SecurityParameterMismatch(_)
        | Error::GpuModeMismatch(_)
        | Error::InvalidWitness { .. }
        | Error::InvalidPublicInputs { .. }
        | Error::StarkVerificationError { .. } => BackendErrorCategory::Input,
        Error::StarkProvingError { .. }
        | Error::GpuInitialization { .. }
        | Error::ProverFailure { .. } => BackendErrorCategory::Runtime,
    }
}

pub(crate) fn map_backend_error(
    err: backend::BackendError,
    context: impl FnOnce(&str) -> String,
) -> ChainError {
    let category = categorize_backend_error(&err);
    let detail = err.to_string();
    let message = context(&detail);
    match category {
        BackendErrorCategory::Key => ChainError::Config(message),
        BackendErrorCategory::Input => ChainError::InvalidProof(message),
        BackendErrorCategory::Runtime => ChainError::Crypto(message),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Plonky3VerifierError {
    pub message: String,
    pub category: String,
    pub at_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Plonky3VerifierHealth {
    pub proofs_verified: u64,
    pub key_failures: u64,
    pub input_failures: u64,
    pub runtime_failures: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<Plonky3VerifierError>,
}

#[derive(Default)]
struct VerifierTelemetry {
    proofs_verified: AtomicU64,
    key_failures: AtomicU64,
    input_failures: AtomicU64,
    runtime_failures: AtomicU64,
    last_success_ms: AtomicU64,
    last_error: RwLock<Option<Plonky3VerifierError>>,
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl VerifierTelemetry {
    fn record_success(&self) {
        self.proofs_verified.fetch_add(1, Ordering::SeqCst);
        self.last_success_ms.store(now_ms(), Ordering::SeqCst);
        self.last_error.write().take();
    }

    fn record_failure(&self, category: BackendErrorCategory, message: String) {
        let counter = match category {
            BackendErrorCategory::Key => &self.key_failures,
            BackendErrorCategory::Input => &self.input_failures,
            BackendErrorCategory::Runtime => &self.runtime_failures,
        };
        counter.fetch_add(1, Ordering::SeqCst);
        *self.last_error.write() = Some(Plonky3VerifierError {
            message,
            category: category.as_str().to_string(),
            at_ms: now_ms(),
        });
    }

    fn snapshot(&self) -> Plonky3VerifierHealth {
        let proofs_verified = self.proofs_verified.load(Ordering::SeqCst);
        let key_failures = self.key_failures.load(Ordering::SeqCst);
        let input_failures = self.input_failures.load(Ordering::SeqCst);
        let runtime_failures = self.runtime_failures.load(Ordering::SeqCst);
        let last_success_raw = self.last_success_ms.load(Ordering::SeqCst);
        let last_success_ms = if last_success_raw == 0 {
            None
        } else {
            Some(last_success_raw)
        };
        let last_error = self.last_error.read().clone();
        Plonky3VerifierHealth {
            proofs_verified,
            key_failures,
            input_failures,
            runtime_failures,
            last_success_ms,
            last_error,
        }
    }
}

static PLONKY3_VERIFIER_TELEMETRY: Lazy<VerifierTelemetry> = Lazy::new(VerifierTelemetry::default);

pub fn verifier_telemetry_snapshot() -> Plonky3VerifierHealth {
    PLONKY3_VERIFIER_TELEMETRY.snapshot()
}

#[derive(Clone)]
struct CircuitArtifact {
    verifying_key: backend::VerifyingKey,
    proving_key: backend::ProvingKey,
    air_metadata: Option<Arc<AirMetadata>>,
}

#[derive(Deserialize)]
struct CircuitArtifactConfig {
    circuit: String,
    #[serde(default)]
    _constraints: Option<String>,
    verifying_key: ArtifactLocation,
    proving_key: ArtifactLocation,
    #[serde(default)]
    metadata: Option<AirMetadata>,
    #[serde(default)]
    hash_manifest: Option<ArtifactHashManifest>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ArtifactLocation {
    Inline(String),
    Descriptor(ArtifactDescriptor),
}

#[derive(Deserialize, Default)]
struct ArtifactDescriptor {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    base64: Option<String>,
    #[serde(default)]
    hex: Option<String>,
    #[serde(default)]
    compression: Option<String>,
    #[serde(default)]
    byte_length: Option<u64>,
    #[serde(default)]
    hash_blake3: Option<String>,
}

#[derive(Deserialize, Default)]
struct ArtifactHashEntry {
    #[serde(default)]
    byte_length: Option<u64>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    blake3: Option<String>,
}

#[derive(Deserialize, Default)]
struct ArtifactHashManifest {
    #[serde(default)]
    verifying_key: Option<ArtifactHashEntry>,
    #[serde(default)]
    proving_key: Option<ArtifactHashEntry>,
}

struct DecodedArtifact {
    bytes: Vec<u8>,
    compression: Option<String>,
    declared_length: Option<u64>,
}

const REQUIRED_CIRCUITS: &[&str] = &[
    "identity",
    "transaction",
    "state",
    "pruning",
    "recursive",
    "uptime",
    "consensus",
];

static CIRCUIT_ARTIFACTS: OnceCell<HashMap<String, CircuitArtifact>> = OnceCell::new();

fn candidate_paths(base: &Path, value: &str) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let stripped = value.trim_start_matches('@');
    if stripped.is_empty() {
        return candidates;
    }
    let path = Path::new(stripped);
    if path.is_absolute() {
        candidates.push(path.to_path_buf());
    } else {
        candidates.push(base.join(path));
    }
    candidates
}

fn normalize_encoding<'a>(encoding: Option<&'a str>) -> Option<&'a str> {
    encoding
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

fn normalize_compression(compression: Option<&str>) -> Option<String> {
    compression
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn decode_blob(value: &str, encoding: Option<&str>) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut attempts = Vec::new();
    if let Some(explicit) = encoding {
        attempts.push(explicit.to_ascii_lowercase());
    }
    attempts.push(String::new());

    for attempt in attempts {
        match attempt.as_str() {
            "" => {
                let hex_candidate = trimmed
                    .strip_prefix("hex:")
                    .or_else(|| trimmed.strip_prefix("0x"))
                    .unwrap_or(trimmed);
                if hex_candidate.chars().all(|char| char.is_ascii_hexdigit())
                    && hex_candidate.len() % 2 == 0
                {
                    if let Ok(bytes) = hex::decode(hex_candidate) {
                        if !bytes.is_empty() {
                            return Some(bytes);
                        }
                    }
                }

                let base64_candidate = trimmed
                    .strip_prefix("base64:")
                    .or_else(|| trimmed.strip_prefix("b64:"))
                    .unwrap_or(trimmed);
                if let Ok(bytes) = BASE64_STANDARD.decode(base64_candidate.as_bytes()) {
                    if !bytes.is_empty() {
                        return Some(bytes);
                    }
                }
            }
            "base64" | "b64" => {
                if let Ok(bytes) = BASE64_STANDARD.decode(trimmed.as_bytes()) {
                    if !bytes.is_empty() {
                        return Some(bytes);
                    }
                }
            }
            "hex" | "base16" => {
                if let Ok(bytes) = hex::decode(trimmed) {
                    if !bytes.is_empty() {
                        return Some(bytes);
                    }
                }
            }
            other => {
                let prefix = format!("{other}:");
                if let Some(stripped) = trimmed.strip_prefix(&prefix) {
                    if let Ok(bytes) = BASE64_STANDARD.decode(stripped.as_bytes()) {
                        if !bytes.is_empty() {
                            return Some(bytes);
                        }
                    }
                    if let Ok(bytes) = hex::decode(stripped) {
                        if !bytes.is_empty() {
                            return Some(bytes);
                        }
                    }
                }
            }
        }
    }

    None
}

fn decode_from_path(
    base: &Path,
    value: &str,
    circuit: &str,
    kind: &str,
) -> ChainResult<Option<Vec<u8>>> {
    for path in candidate_paths(base, value) {
        if path.exists() {
            let data = fs::read(&path).map_err(|err| {
                ChainError::Config(format!(
                    "unable to read {kind} for {circuit} circuit from {}: {err}",
                    path.display()
                ))
            })?;
            if data.is_empty() {
                return Err(ChainError::Config(format!(
                    "{kind} for {circuit} circuit at {} is empty",
                    path.display()
                )));
            }
            return Ok(Some(data));
        }
    }
    Ok(None)
}

fn decode_artifact_bytes(
    base: &Path,
    location: &ArtifactLocation,
    circuit: &str,
    kind: &str,
) -> ChainResult<DecodedArtifact> {
    match location {
        ArtifactLocation::Inline(value) => decode_artifact_string(base, value, circuit, kind),
        ArtifactLocation::Descriptor(descriptor) => {
            decode_artifact_descriptor(base, descriptor, circuit, kind)
        }
    }
}

fn decode_artifact_string(
    base: &Path,
    value: &str,
    circuit: &str,
    kind: &str,
) -> ChainResult<DecodedArtifact> {
    if value.trim().is_empty() {
        return Err(ChainError::Config(format!(
            "{kind} for {circuit} circuit is empty"
        )));
    }
    if let Some(bytes) = decode_from_path(base, value, circuit, kind)? {
        return Ok(DecodedArtifact {
            bytes,
            compression: None,
            declared_length: None,
        });
    }
    if let Some(bytes) = decode_blob(value, None) {
        return Ok(DecodedArtifact {
            bytes,
            compression: None,
            declared_length: None,
        });
    }
    Err(ChainError::Config(format!(
        "{kind} for {circuit} circuit must reference a file or contain hex/base64 data",
    )))
}

fn decode_artifact_descriptor(
    base: &Path,
    descriptor: &ArtifactDescriptor,
    circuit: &str,
    kind: &str,
) -> ChainResult<DecodedArtifact> {
    let mut candidate: Option<Vec<u8>> = None;

    if let Some(path) = descriptor
        .path
        .as_ref()
        .or(descriptor.file.as_ref())
        .map(|path| path.as_str())
    {
        if let Some(bytes) = decode_from_path(base, path, circuit, kind)? {
            candidate = Some(bytes);
        }
    }

    if candidate.is_none() {
        if let Some(value) = descriptor.base64.as_ref() {
            if let Some(bytes) = decode_blob(value, Some("base64")) {
                candidate = Some(bytes);
            }
        }
    }

    if candidate.is_none() {
        if let Some(value) = descriptor.hex.as_ref() {
            if let Some(bytes) = decode_blob(value, Some("hex")) {
                candidate = Some(bytes);
            }
        }
    }

    if candidate.is_none() {
        if let Some(value) = descriptor.value.as_ref() {
            if let Some(bytes) = decode_blob(
                value,
                normalize_encoding(
                    descriptor
                        .encoding
                        .as_deref()
                        .or(descriptor.format.as_deref()),
                ),
            ) {
                candidate = Some(bytes);
            }
        }
    }

    let bytes = candidate.ok_or_else(|| {
        ChainError::Config(format!(
            "{kind} for {circuit} circuit must provide a file path or an encoded value",
        ))
    })?;

    let mut compression = normalize_compression(descriptor.compression.as_deref());
    if let Some(normalized) = compression.as_deref() {
        match normalized {
            "gzip" | "gz" | "none" => {}
            other => {
                return Err(ChainError::Config(format!(
                    "unsupported compression '{other}' for {kind} in {circuit} circuit",
                )))
            }
        }
    }

    if compression.as_deref() == Some("none") {
        compression = None;
    }
    if compression.is_none() {
        if let Some(expected) = descriptor.byte_length {
            if bytes.len() as u64 != expected {
                return Err(ChainError::Config(format!(
                    "{kind} for {circuit} circuit declares {expected} bytes but decoded payload has length {}",
                    bytes.len(),
                )));
            }
        }
    }

    Ok(DecodedArtifact {
        bytes,
        compression,
        declared_length: descriptor.byte_length,
    })
}

fn decompress_artifact_bytes(
    bytes: &[u8],
    compression: Option<&str>,
    circuit: &str,
    kind: &str,
) -> ChainResult<Vec<u8>> {
    match compression {
        None => Ok(bytes.to_vec()),
        Some("gzip") | Some("gz") => {
            let mut decoder = GzDecoder::new(bytes);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed).map_err(|err| {
                ChainError::Config(format!(
                    "failed to decompress {kind} for {circuit} circuit: {err}",
                ))
            })?;
            if decompressed.is_empty() {
                return Err(ChainError::Config(format!(
                    "{kind} for {circuit} circuit decompressed to zero bytes",
                )));
            }
            Ok(decompressed)
        }
        Some("none") => Ok(bytes.to_vec()),
        Some(other) => Err(ChainError::Config(format!(
            "unsupported compression '{other}' for {kind} in {circuit} circuit",
        ))),
    }
}

fn digests_match(expected: &str, actual: &str) -> bool {
    expected.trim().eq_ignore_ascii_case(actual.trim())
}

fn validate_hash_manifest_entry(
    entry: Option<&ArtifactHashEntry>,
    artifact: &DecodedArtifact,
    circuit: &str,
    kind: &str,
) -> ChainResult<()> {
    let entry = entry.ok_or_else(|| {
        ChainError::Config(format!(
            "Plonky3 setup artifact for {circuit} circuit is missing hash manifest metadata for {kind}",
        ))
    })?;

    let decompressed = decompress_artifact_bytes(
        &artifact.bytes,
        artifact.compression.as_deref(),
        circuit,
        kind,
    )?;

    if let Some(expected) = entry.byte_length {
        if decompressed.len() as u64 != expected {
            return Err(ChainError::Config(format!(
                "{kind} for {circuit} circuit expected {expected} bytes after decompression, found {}",
                decompressed.len(),
            )));
        }
    }

    if let Some(declared) = artifact.declared_length {
        if decompressed.len() as u64 != declared {
            return Err(ChainError::Config(format!(
                "{kind} for {circuit} circuit decoded length mismatch: descriptor declared {declared} bytes, found {}",
                decompressed.len(),
            )));
        }
    }

    if let Some(expected_sha) = entry.sha256.as_deref() {
        let actual_sha = hex::encode(Sha256::digest(&decompressed));
        if !digests_match(expected_sha, &actual_sha) {
            return Err(ChainError::Config(format!(
                "{kind} for {circuit} circuit SHA-256 mismatch: expected {expected_sha}, found {actual_sha}",
            )));
        }
    } else {
        return Err(ChainError::Config(format!(
            "{kind} for {circuit} circuit is missing a SHA-256 digest in the hash manifest",
        )));
    }

    if let Some(expected_blake3) = entry.blake3.as_deref() {
        let actual_blake3 = hex::encode(blake3_hash(&decompressed));
        if !digests_match(expected_blake3, &actual_blake3) {
            return Err(ChainError::Config(format!(
                "{kind} for {circuit} circuit BLAKE3 mismatch: expected {expected_blake3}, found {actual_blake3}",
            )));
        }
    }

    Ok(())
}
fn load_circuit_artifacts() -> ChainResult<HashMap<String, CircuitArtifact>> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("config/plonky3/setup");
    let entries = fs::read_dir(&path).map_err(|err| {
        ChainError::Config(format!(
            "unable to read Plonky3 setup artifacts from {}: {err}",
            path.display()
        ))
    })?;
    let mut artifacts = HashMap::new();
    for entry in entries {
        let entry = entry
            .map_err(|err| ChainError::Config(format!("invalid Plonky3 setup entry: {err}")))?;
        let file_path = entry.path();
        if file_path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let contents = fs::read_to_string(&file_path).map_err(|err| {
            ChainError::Config(format!(
                "unable to read Plonky3 setup artifact {}: {err}",
                file_path.display()
            ))
        })?;
        let config: CircuitArtifactConfig = serde_json::from_str(&contents).map_err(|err| {
            ChainError::Config(format!(
                "invalid Plonky3 setup artifact {}: {err}",
                file_path.display()
            ))
        })?;
        if config.circuit.is_empty() {
            return Err(ChainError::Config(format!(
                "Plonky3 setup artifact {} missing circuit name",
                file_path.display()
            )));
        }
        let verifying_artifact = decode_artifact_bytes(
            &path,
            &config.verifying_key,
            &config.circuit,
            "verifying key",
        )?;
        let proving_artifact =
            decode_artifact_bytes(&path, &config.proving_key, &config.circuit, "proving key")?;

        let hash_manifest = config.hash_manifest.as_ref();
        validate_hash_manifest_entry(
            hash_manifest.and_then(|manifest| manifest.verifying_key.as_ref()),
            &verifying_artifact,
            &config.circuit,
            "verifying key",
        )?;
        validate_hash_manifest_entry(
            hash_manifest.and_then(|manifest| manifest.proving_key.as_ref()),
            &proving_artifact,
            &config.circuit,
            "proving key",
        )?;

        let DecodedArtifact {
            bytes: verifying_key_bytes,
            ..
        } = verifying_artifact;
        let DecodedArtifact {
            bytes: proving_key_bytes,
            ..
        } = proving_artifact;
        let mut verifying_key =
            backend::VerifyingKey::from_bytes(verifying_key_bytes, &config.circuit).map_err(
                |err| {
                    ChainError::Config(format!(
                        "failed to decode Plonky3 verifying key for {} circuit: {err}",
                        config.circuit
                    ))
                },
            )?;
        let mut air_metadata = config
            .metadata
            .as_ref()
            .map(|value| Arc::new(value.clone()));
        let verifying_metadata = Arc::clone(verifying_key.air_metadata());
        if let Some(expected) = &air_metadata {
            if verifying_metadata.as_ref() != expected.as_ref() {
                return Err(ChainError::Config(format!(
                    "Plonky3 verifying key metadata for {} circuit does not match fixture metadata",
                    config.circuit
                )));
            }
            verifying_key = verifying_key.with_metadata(Arc::clone(expected));
        } else if !verifying_metadata.is_empty() {
            air_metadata = Some(Arc::clone(&verifying_metadata));
        }
        let proving_key = backend::ProvingKey::from_bytes(
            proving_key_bytes,
            &config.circuit,
            air_metadata.as_ref(),
        )
        .map_err(|err| {
            ChainError::Config(format!(
                "failed to decode Plonky3 proving key for {} circuit: {err}",
                config.circuit
            ))
        })?;
        if artifacts
            .insert(
                config.circuit.clone(),
                CircuitArtifact {
                    verifying_key,
                    proving_key,
                    air_metadata,
                },
            )
            .is_some()
        {
            return Err(ChainError::Config(format!(
                "duplicate Plonky3 setup artifact for {} circuit",
                config.circuit
            )));
        }
    }
    if artifacts.is_empty() {
        return Err(ChainError::Config(
            "no Plonky3 setup artifacts were found; expected at least one circuit".into(),
        ));
    }
    for required in REQUIRED_CIRCUITS {
        if !artifacts.contains_key(*required) {
            return Err(ChainError::Config(format!(
                "missing Plonky3 setup artifact for required {required} circuit"
            )));
        }
    }
    Ok(artifacts)
}

fn circuit_artifacts() -> ChainResult<&'static HashMap<String, CircuitArtifact>> {
    match CIRCUIT_ARTIFACTS.get_or_try_init(load_circuit_artifacts) {
        Ok(artifacts) => Ok(artifacts),
        Err(err) => {
            error!("failed to load Plonky3 setup artifacts: {err}");
            Err(err)
        }
    }
}

fn circuit_artifact(circuit: &str) -> ChainResult<&'static CircuitArtifact> {
    let artifacts = circuit_artifacts()?;
    artifacts.get(circuit).ok_or_else(|| {
        let message = format!("no Plonky3 setup artifact registered for {circuit} circuit");
        error!("{message}");
        ChainError::Config(message)
    })
}

pub fn verifying_key(circuit: &str) -> ChainResult<backend::VerifyingKey> {
    circuit_artifact(circuit).map(|artifact| artifact.verifying_key.clone())
}

pub fn circuit_air_metadata(circuit: &str) -> ChainResult<Option<Arc<AirMetadata>>> {
    circuit_artifact(circuit).map(|artifact| artifact.air_metadata.as_ref().map(Arc::clone))
}

pub fn circuit_keys(circuit: &str) -> ChainResult<(backend::VerifyingKey, backend::ProvingKey)> {
    circuit_artifact(circuit)
        .map(|artifact| (artifact.verifying_key.clone(), artifact.proving_key.clone()))
}

pub fn finalize(circuit: String, public_inputs: Value) -> ChainResult<super::proof::Plonky3Proof> {
    let artifact = circuit_artifact(&circuit)?;
    let params = Plonky3Parameters::default();
    let context = backend::ProverContext::new(
        circuit.clone(),
        artifact.verifying_key.clone(),
        artifact.proving_key.clone(),
        params.security_bits,
        params.use_gpu_acceleration,
    )
    .map_err(|err| {
        map_backend_error(err, |detail| {
            format!("failed to prepare Plonky3 {circuit} circuit for proving: {detail}")
        })
    })?;
    let (expected_commitment, _, canonical_bytes) =
        super::public_inputs::compute_commitment_and_inputs(&public_inputs)?;
    let canonical_public_inputs: Value =
        serde_json::from_slice(&canonical_bytes).map_err(|err| {
            ChainError::Crypto(format!(
                "failed to decode canonical Plonky3 public inputs: {err}"
            ))
        })?;
    if circuit == "consensus" {
        validate_consensus_public_inputs(&canonical_public_inputs).map_err(|err| {
            map_backend_error(err, |detail| {
                format!("invalid consensus public inputs supplied to Plonky3 prover: {detail}")
            })
        })?;
    }
    let (commitment, backend_proof) = context.prove(&canonical_public_inputs).map_err(|err| {
        map_backend_error(err, |detail| {
            format!("failed to produce Plonky3 {circuit} proof: {detail}")
        })
    })?;
    if commitment != expected_commitment {
        return Err(ChainError::CommitmentMismatch(format!(
            "Plonky3 backend commitment mismatch: expected {expected_commitment}, found {commitment}"
        )));
    }
    let proof = super::proof::Plonky3Proof::from_backend(
        circuit,
        commitment,
        canonical_public_inputs,
        backend_proof,
    )?;
    if let Err(detail) = proof.payload.metadata.ensure_alignment(&params) {
        return Err(ChainError::Crypto(detail));
    }
    Ok(proof)
}

pub fn verify_proof(proof: &super::proof::Plonky3Proof) -> ChainResult<()> {
    let artifact = match circuit_artifact(&proof.circuit) {
        Ok(artifact) => artifact,
        Err(err) => {
            PLONKY3_VERIFIER_TELEMETRY.record_failure(BackendErrorCategory::Key, err.to_string());
            return Err(err);
        }
    };
    let params = Plonky3Parameters::default();
    proof.payload.validate().map_err(|err| {
        let message = format!("plonky3 {} proof payload invalid: {err}", proof.circuit);
        PLONKY3_VERIFIER_TELEMETRY.record_failure(BackendErrorCategory::Input, message.clone());
        ChainError::InvalidProof(message)
    })?;
    if let Err(detail) = proof.payload.metadata.ensure_alignment(&params) {
        PLONKY3_VERIFIER_TELEMETRY.record_failure(BackendErrorCategory::Input, detail.clone());
        return Err(ChainError::InvalidProof(detail));
    }
    let metadata = &proof.payload.metadata;

    let verifier = backend::VerifierContext::new(
        proof.circuit.clone(),
        artifact.verifying_key.clone(),
        metadata.security_bits,
        metadata.use_gpu,
    )
    .map_err(|err| {
        let message = format!(
            "failed to prepare Plonky3 {} circuit for verification: {detail}",
            proof.circuit,
            detail = err
        );
        PLONKY3_VERIFIER_TELEMETRY.record_failure(BackendErrorCategory::Key, message.clone());
        map_backend_error(err, |_| message)
    })?;
    let backend_proof = proof.payload.to_backend(&proof.circuit).map_err(|err| {
        let message = format!(
            "failed to decode Plonky3 {} proof payload: {err}",
            proof.circuit
        );
        PLONKY3_VERIFIER_TELEMETRY.record_failure(BackendErrorCategory::Input, message.clone());
        map_backend_error(err, |_| message)
    })?;
    verifier
        .verify(&proof.commitment, &proof.public_inputs, &backend_proof)
        .map_err(|err| {
            let message = format!("Plonky3 {} proof verification failed: {err}", proof.circuit);
            let category = categorize_backend_error(&err);
            PLONKY3_VERIFIER_TELEMETRY.record_failure(category, message.clone());
            map_backend_error(err, |_| message)
        })?;
    PLONKY3_VERIFIER_TELEMETRY.record_success();
    Ok(())
}
