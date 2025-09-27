use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use blake3::Hasher;
use once_cell::sync::OnceCell;
use serde::Deserialize;
use serde_json::Value;
use tracing::error;

use crate::errors::{ChainError, ChainResult};

static VERIFYING_KEYS: OnceCell<HashMap<String, [u8; 32]>> = OnceCell::new();

#[derive(Deserialize)]
struct VerifyingKeyConfig {
    #[serde(flatten)]
    circuits: HashMap<String, String>,
}

fn load_verifying_keys() -> ChainResult<HashMap<String, [u8; 32]>> {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("config/plonky3_verifying_keys.json");
    let contents = fs::read_to_string(&path).map_err(|err| {
        ChainError::Crypto(format!(
            "unable to read Plonky3 verifying keys from {}: {err}",
            path.display()
        ))
    })?;
    let config: VerifyingKeyConfig = serde_json::from_str(&contents).map_err(|err| {
        ChainError::Crypto(format!(
            "invalid Plonky3 verifying key configuration {}: {err}",
            path.display()
        ))
    })?;
    let mut keys = HashMap::new();
    for (circuit, encoded) in config.circuits {
        let bytes = hex::decode(&encoded).map_err(|err| {
            ChainError::Crypto(format!(
                "verifying key for {circuit} is not valid hex: {err}"
            ))
        })?;
        if bytes.len() != 32 {
            return Err(ChainError::Crypto(format!(
                "verifying key for {circuit} must be 32 bytes, found {}",
                bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        keys.insert(circuit, key);
    }
    Ok(keys)
}

fn verifying_keys() -> ChainResult<&'static HashMap<String, [u8; 32]>> {
    match VERIFYING_KEYS.get_or_try_init(load_verifying_keys) {
        Ok(keys) => Ok(keys),
        Err(err) => {
            error!("failed to load Plonky3 verifying keys: {err}");
            Err(err)
        }
    }
}

pub fn verifying_key(circuit: &str) -> ChainResult<[u8; 32]> {
    let keys = verifying_keys()?;
    keys.get(circuit).copied().ok_or_else(|| {
        let message = format!("no verifying key configured for {circuit} circuit");
        error!("{message}");
        ChainError::Crypto(message)
    })
}

pub fn compute_commitment(public_inputs: &Value) -> ChainResult<String> {
    let encoded = serde_json::to_vec(public_inputs).map_err(|err| {
        ChainError::Crypto(format!(
            "failed to encode Plonky3 public inputs for commitment: {err}"
        ))
    })?;
    let mut hasher = Hasher::new();
    hasher.update(&encoded);
    Ok(hasher.finalize().to_hex().to_string())
}

pub fn compute_proof(
    circuit: &str,
    commitment: &str,
    public_inputs: &Value,
    verifying_key: &[u8; 32],
) -> ChainResult<Vec<u8>> {
    let encoded_inputs = serde_json::to_vec(public_inputs).map_err(|err| {
        ChainError::Crypto(format!(
            "failed to encode Plonky3 public inputs for proof transcript: {err}"
        ))
    })?;
    let mut transcript = Vec::new();
    transcript.extend_from_slice(circuit.as_bytes());
    transcript.extend_from_slice(commitment.as_bytes());
    transcript.extend_from_slice(&encoded_inputs);
    let digest = blake3::keyed_hash(verifying_key, &transcript);
    Ok(digest.as_bytes().to_vec())
}

pub fn finalize(circuit: String, public_inputs: Value) -> ChainResult<super::proof::Plonky3Proof> {
    let verifying_key = verifying_key(&circuit)?;
    let commitment = compute_commitment(&public_inputs)?;
    let proof = compute_proof(&circuit, &commitment, &public_inputs, &verifying_key)?;
    Ok(super::proof::Plonky3Proof {
        circuit,
        commitment,
        public_inputs,
        proof,
        verifying_key,
    })
}

pub fn verify_transcript(proof: &super::proof::Plonky3Proof) -> ChainResult<()> {
    let expected_key = verifying_key(&proof.circuit)?;
    if proof.verifying_key != expected_key {
        return Err(ChainError::Crypto(format!(
            "plonky3 verifying key mismatch: expected {}, found {}",
            hex::encode(expected_key),
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
    let expected_proof = compute_proof(
        &proof.circuit,
        &expected_commitment,
        &proof.public_inputs,
        &expected_key,
    )?;
    if proof.proof != expected_proof {
        return Err(ChainError::Crypto(
            "plonky3 proof transcript does not match verifying key".into(),
        ));
    }
    Ok(())
}
