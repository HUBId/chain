use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use once_cell::sync::OnceCell;
use serde::Deserialize;
use serde_json::Value;
use tracing::error;

use crate::errors::{ChainError, ChainResult};
pub use plonky3_backend::PROOF_BLOB_LEN;
use plonky3_backend::{self as backend, Circuit};

use super::params::Plonky3Parameters;

#[derive(Clone)]
struct CircuitArtifact {
    verifying_key: Vec<u8>,
    proving_key: Vec<u8>,
    verifying_key_hash: [u8; 32],
    proving_key_hash: [u8; 32],
}

#[derive(Deserialize)]
struct CircuitArtifactConfig {
    circuit: String,
    #[serde(default)]
    _constraints: Option<String>,
    verifying_key: ArtifactLocation,
    proving_key: ArtifactLocation,
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
                ChainError::Crypto(format!(
                    "unable to read {kind} for {circuit} circuit from {}: {err}",
                    path.display()
                ))
            })?;
            if data.is_empty() {
                return Err(ChainError::Crypto(format!(
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
) -> ChainResult<Vec<u8>> {
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
) -> ChainResult<Vec<u8>> {
    if value.trim().is_empty() {
        return Err(ChainError::Crypto(format!(
            "{kind} for {circuit} circuit is empty"
        )));
    }
    if let Some(bytes) = decode_from_path(base, value, circuit, kind)? {
        return Ok(bytes);
    }
    if let Some(bytes) = decode_blob(value, None) {
        return Ok(bytes);
    }
    Err(ChainError::Crypto(format!(
        "{kind} for {circuit} circuit must reference a file or contain hex/base64 data",
    )))
}

fn decode_artifact_descriptor(
    base: &Path,
    descriptor: &ArtifactDescriptor,
    circuit: &str,
    kind: &str,
) -> ChainResult<Vec<u8>> {
    if let Some(path) = descriptor
        .path
        .as_ref()
        .or(descriptor.file.as_ref())
        .map(|path| path.as_str())
    {
        if let Some(bytes) = decode_from_path(base, path, circuit, kind)? {
            return Ok(bytes);
        }
    }

    if let Some(value) = descriptor.base64.as_ref() {
        if let Some(bytes) = decode_blob(value, Some("base64")) {
            return Ok(bytes);
        }
    }

    if let Some(value) = descriptor.hex.as_ref() {
        if let Some(bytes) = decode_blob(value, Some("hex")) {
            return Ok(bytes);
        }
    }

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
            return Ok(bytes);
        }
    }

    Err(ChainError::Crypto(format!(
        "{kind} for {circuit} circuit must provide a file path or an encoded value",
    )))
}
fn load_circuit_artifacts() -> ChainResult<HashMap<String, CircuitArtifact>> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("config/plonky3/setup");
    let entries = fs::read_dir(&path).map_err(|err| {
        ChainError::Crypto(format!(
            "unable to read Plonky3 setup artifacts from {}: {err}",
            path.display()
        ))
    })?;
    let mut artifacts = HashMap::new();
    for entry in entries {
        let entry = entry
            .map_err(|err| ChainError::Crypto(format!("invalid Plonky3 setup entry: {err}")))?;
        let file_path = entry.path();
        if file_path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let contents = fs::read_to_string(&file_path).map_err(|err| {
            ChainError::Crypto(format!(
                "unable to read Plonky3 setup artifact {}: {err}",
                file_path.display()
            ))
        })?;
        let config: CircuitArtifactConfig = serde_json::from_str(&contents).map_err(|err| {
            ChainError::Crypto(format!(
                "invalid Plonky3 setup artifact {}: {err}",
                file_path.display()
            ))
        })?;
        if config.circuit.is_empty() {
            return Err(ChainError::Crypto(format!(
                "Plonky3 setup artifact {} missing circuit name",
                file_path.display()
            )));
        }
        let verifying_key = decode_artifact_bytes(
            &path,
            &config.verifying_key,
            &config.circuit,
            "verifying key",
        )?;
        let proving_key =
            decode_artifact_bytes(&path, &config.proving_key, &config.circuit, "proving key")?;
        let verifying_key_hash: [u8; 32] = *blake3::hash(&verifying_key).as_bytes();
        let proving_key_hash: [u8; 32] = *blake3::hash(&proving_key).as_bytes();
        if artifacts
            .insert(
                config.circuit.clone(),
                CircuitArtifact {
                    verifying_key,
                    proving_key,
                    verifying_key_hash,
                    proving_key_hash,
                },
            )
            .is_some()
        {
            return Err(ChainError::Crypto(format!(
                "duplicate Plonky3 setup artifact for {} circuit",
                config.circuit
            )));
        }
    }
    if artifacts.is_empty() {
        return Err(ChainError::Crypto(
            "no Plonky3 setup artifacts were found; expected at least one circuit".into(),
        ));
    }
    for required in REQUIRED_CIRCUITS {
        if !artifacts.contains_key(*required) {
            return Err(ChainError::Crypto(format!(
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
        ChainError::Crypto(message)
    })
}

pub fn verifying_key(circuit: &str) -> ChainResult<Vec<u8>> {
    circuit_artifact(circuit).map(|artifact| artifact.verifying_key.clone())
}

pub(crate) fn circuit_keys(circuit: &str) -> ChainResult<(Vec<u8>, Vec<u8>)> {
    circuit_artifact(circuit)
        .map(|artifact| (artifact.verifying_key.clone(), artifact.proving_key.clone()))
}

pub(crate) fn canonical_public_inputs(public_inputs: &Value) -> ChainResult<(String, Vec<u8>)> {
    backend::compute_commitment_and_inputs(public_inputs).map_err(|err| {
        ChainError::Crypto(format!(
            "failed to encode Plonky3 public inputs for commitment: {err}"
        ))
    })
}

pub fn compute_commitment(public_inputs: &Value) -> ChainResult<String> {
    canonical_public_inputs(public_inputs).map(|(commitment, _)| commitment)
}

pub fn finalize(circuit: String, public_inputs: Value) -> ChainResult<super::proof::Plonky3Proof> {
    let artifact = circuit_artifact(&circuit)?;
    let (commitment, encoded_inputs) = canonical_public_inputs(&public_inputs)?;
    let params = Plonky3Parameters::default();
    let compiled = Circuit::keygen(
        circuit.clone(),
        artifact.verifying_key.clone(),
        artifact.proving_key.clone(),
        params.security_bits,
        params.use_gpu_acceleration,
    )
    .map_err(|err| {
        ChainError::Crypto(format!(
            "failed to prepare Plonky3 {circuit} circuit for proving: {err}"
        ))
    })?;
    let proof_bundle = compiled
        .prove(&commitment, &encoded_inputs)
        .map_err(|err| {
            ChainError::Crypto(format!("failed to generate Plonky3 {circuit} proof: {err}"))
        })?;
    let (verifying_key, backend_inputs, proof_blob) = proof_bundle.into_parts();
    if verifying_key != artifact.verifying_key {
        return Err(ChainError::Crypto(format!(
            "failed to generate Plonky3 {circuit} proof: backend returned mismatched verifying key",
        )));
    }
    if backend_inputs != encoded_inputs {
        return Err(ChainError::Crypto(format!(
            "failed to generate Plonky3 {circuit} proof: backend returned mismatched public inputs",
        )));
    }
    Ok(super::proof::Plonky3Proof {
        circuit,
        commitment,
        public_inputs,
        proof: proof_blob,
        verifying_key,
    })
}

pub fn verify_proof(proof: &super::proof::Plonky3Proof) -> ChainResult<()> {
    let artifact = circuit_artifact(&proof.circuit)?;
    let (expected_commitment, encoded_inputs) = canonical_public_inputs(&proof.public_inputs)?;
    if proof.commitment != expected_commitment {
        return Err(ChainError::Crypto(format!(
            "plonky3 proof commitment mismatch: expected {expected_commitment}, found {}",
            proof.commitment
        )));
    }
    let params = Plonky3Parameters::default();
    let compiled = Circuit::keygen(
        proof.circuit.clone(),
        artifact.verifying_key.clone(),
        artifact.proving_key.clone(),
        params.security_bits,
        params.use_gpu_acceleration,
    )
    .map_err(|err| {
        ChainError::Crypto(format!(
            "failed to prepare Plonky3 {} circuit for verification: {err}",
            proof.circuit
        ))
    })?;
    compiled
        .verify(
            &expected_commitment,
            &proof.verifying_key,
            &encoded_inputs,
            &proof.proof,
        )
        .map_err(|err| {
            ChainError::Crypto(format!(
                "plonky3 proof verification failed for {} circuit: {err}",
                proof.circuit
            ))
        })
}
