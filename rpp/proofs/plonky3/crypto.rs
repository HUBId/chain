use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use blake3::Hasher;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer};
use once_cell::sync::OnceCell;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::error;

use crate::errors::{ChainError, ChainResult};

#[derive(Clone)]
struct CircuitArtifact {
    verifying_key: [u8; 32],
    proving_key: [u8; 32],
}

#[derive(Deserialize)]
struct CircuitArtifactConfig {
    circuit: String,
    #[serde(default)]
    _constraints: Option<String>,
    verifying_key: String,
    proving_key: String,
}

static CIRCUIT_ARTIFACTS: OnceCell<HashMap<String, CircuitArtifact>> = OnceCell::new();

fn decode_key(hex_value: &str, circuit: &str, kind: &str) -> ChainResult<[u8; 32]> {
    let bytes = hex::decode(hex_value).map_err(|err| {
        ChainError::Crypto(format!(
            "{kind} for {circuit} circuit is not valid hex: {err}"
        ))
    })?;
    if bytes.len() != 32 {
        return Err(ChainError::Crypto(format!(
            "{kind} for {circuit} circuit must be 32 bytes, found {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
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
        let verifying_key = decode_key(&config.verifying_key, &config.circuit, "verifying key")?;
        let proving_key = decode_key(&config.proving_key, &config.circuit, "proving key")?;
        if artifacts
            .insert(
                config.circuit.clone(),
                CircuitArtifact {
                    verifying_key,
                    proving_key,
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

pub fn verifying_key(circuit: &str) -> ChainResult<[u8; 32]> {
    circuit_artifact(circuit).map(|artifact| artifact.verifying_key)
}

pub fn compute_commitment(public_inputs: &Value) -> ChainResult<String> {
    let encoded = encode_canonical_json(public_inputs).map_err(|err| {
        ChainError::Crypto(format!(
            "failed to encode Plonky3 public inputs for commitment: {err}"
        ))
    })?;
    let mut hasher = Hasher::new();
    hasher.update(&encoded);
    Ok(hasher.finalize().to_hex().to_string())
}

fn transcript_message(
    circuit: &str,
    commitment: &str,
    public_inputs: &Value,
) -> ChainResult<Vec<u8>> {
    let encoded_inputs = encode_canonical_json(public_inputs).map_err(|err| {
        ChainError::Crypto(format!(
            "failed to encode Plonky3 public inputs for transcript: {err}"
        ))
    })?;
    let mut transcript = Vec::new();
    transcript.extend_from_slice(circuit.as_bytes());
    transcript.extend_from_slice(commitment.as_bytes());
    transcript.extend_from_slice(&encoded_inputs);
    Ok(transcript)
}

fn compute_proof(
    circuit: &str,
    commitment: &str,
    public_inputs: &Value,
    artifact: &CircuitArtifact,
) -> ChainResult<Vec<u8>> {
    let message = transcript_message(circuit, commitment, public_inputs)?;
    let secret = SecretKey::from_bytes(&artifact.proving_key).map_err(|err| {
        ChainError::Crypto(format!(
            "invalid Plonky3 proving key for {circuit} circuit: {err}"
        ))
    })?;
    let public = PublicKey::from(&secret);
    if public.to_bytes() != artifact.verifying_key {
        return Err(ChainError::Crypto(format!(
            "Plonky3 proving key for {circuit} does not match verifying key"
        )));
    }
    let keypair = Keypair { secret, public };
    let signature = keypair.sign(&message);
    Ok(signature.to_bytes().to_vec())
}

fn encode_canonical_json(value: &Value) -> serde_json::Result<Vec<u8>> {
    let canonical = CanonicalValue(value);
    let mut buffer = Vec::new();
    {
        let mut serializer = serde_json::Serializer::new(&mut buffer);
        canonical.serialize(&mut serializer)?;
    }
    Ok(buffer)
}

struct CanonicalValue<'a>(&'a Value);

impl<'a> Serialize for CanonicalValue<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self.0 {
            Value::Null => serializer.serialize_unit(),
            Value::Bool(value) => serializer.serialize_bool(*value),
            Value::Number(value) => value.serialize(serializer),
            Value::String(value) => serializer.serialize_str(value),
            Value::Array(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(&CanonicalValue(value))?;
                }
                seq.end()
            }
            Value::Object(map) => {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|(left, _), (right, _)| left.cmp(right));
                let mut object = serializer.serialize_map(Some(entries.len()))?;
                for (key, value) in entries {
                    object.serialize_entry(key, &CanonicalValue(value))?;
                }
                object.end()
            }
        }
    }
}

pub fn finalize(circuit: String, public_inputs: Value) -> ChainResult<super::proof::Plonky3Proof> {
    let artifact = circuit_artifact(&circuit)?;
    let commitment = compute_commitment(&public_inputs)?;
    let proof = compute_proof(&circuit, &commitment, &public_inputs, artifact)?;
    Ok(super::proof::Plonky3Proof {
        circuit,
        commitment,
        public_inputs,
        proof,
        verifying_key: artifact.verifying_key,
    })
}

pub fn verify_proof(proof: &super::proof::Plonky3Proof) -> ChainResult<()> {
    let artifact = circuit_artifact(&proof.circuit)?;
    if proof.verifying_key != artifact.verifying_key {
        return Err(ChainError::Crypto(format!(
            "plonky3 verifying key mismatch: expected {}, found {}",
            hex::encode(artifact.verifying_key),
            hex::encode(proof.verifying_key)
        )));
    }
    let expected_commitment = compute_commitment(&proof.public_inputs)?;
    if proof.commitment != expected_commitment {
        return Err(ChainError::Crypto(format!(
            "plonky3 proof commitment mismatch: expected {expected_commitment}, found {}",
            proof.commitment
        )));
    }
    let message = transcript_message(&proof.circuit, &expected_commitment, &proof.public_inputs)?;
    let verifying_key = PublicKey::from_bytes(&artifact.verifying_key).map_err(|err| {
        ChainError::Crypto(format!(
            "invalid Plonky3 verifying key for {} circuit: {err}",
            proof.circuit
        ))
    })?;
    if proof.proof.len() != 64 {
        return Err(ChainError::Crypto(format!(
            "plonky3 proof signature must be 64 bytes, found {}",
            proof.proof.len()
        )));
    }
    let mut signature_bytes = [0u8; 64];
    signature_bytes.copy_from_slice(&proof.proof);
    let signature = Signature::from_bytes(&signature_bytes).map_err(|err| {
        ChainError::Crypto(format!(
            "invalid Plonky3 proof signature encoding for {} circuit: {err}",
            proof.circuit
        ))
    })?;
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|err| {
            ChainError::Crypto(format!(
                "plonky3 proof verification failed for {}: {err}",
                proof.circuit
            ))
        })
}
