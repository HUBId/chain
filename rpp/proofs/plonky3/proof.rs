use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::{ChainError, ChainResult};
use plonky3_backend::{self as backend, HashFormat, ProofParts};

/// Generic representation of a Plonky3 proof artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plonky3Proof {
    pub circuit: String,
    pub commitment: String,
    pub public_inputs: Value,
    pub payload: ProofPayload,
}

impl Plonky3Proof {
    pub fn new(circuit: impl Into<String>, public_inputs: Value) -> ChainResult<Self> {
        super::crypto::finalize(circuit.into(), public_inputs)
    }

    pub fn from_value(value: &Value) -> ChainResult<Self> {
        serde_json::from_value(value.clone())
            .map_err(|err| ChainError::Crypto(format!("invalid Plonky3 proof encoding: {err}")))
    }

    pub fn into_value(self) -> ChainResult<Value> {
        serde_json::to_value(self)
            .map_err(|err| ChainError::Crypto(format!("failed to encode Plonky3 proof: {err}")))
    }

    pub(crate) fn from_backend(
        circuit: String,
        commitment: String,
        public_inputs: Value,
        proof: backend::Proof,
    ) -> ChainResult<Self> {
        Ok(Self {
            circuit,
            commitment,
            public_inputs,
            payload: ProofPayload::from_backend(proof),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ProofPayload {
    #[serde(with = "serde_base64_vec")]
    pub stark_proof: Vec<u8>,
    pub metadata: ProofMetadata,
}

impl<'de> Deserialize<'de> for ProofPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct CurrentPayload {
            #[serde(with = "serde_base64_vec")]
            stark_proof: Vec<u8>,
            metadata: ProofMetadata,
        }

        let value = serde_json::Value::deserialize(deserializer)?;
        if let Ok(current) = CurrentPayload::deserialize(value.clone()) {
            return Ok(Self {
                stark_proof: current.stark_proof,
                metadata: current.metadata,
            });
        }

        if value.get("proof_blob").is_some() {
            return Err(serde::de::Error::custom(
                "legacy Plonky3 proof payload detected; re-export the proof with the updated format",
            ));
        }

        Err(serde::de::Error::custom("invalid Plonky3 proof payload"))
    }
}

impl ProofPayload {
    pub fn from_backend(proof: backend::Proof) -> Self {
        let parts = proof.into_parts();
        Self {
            stark_proof: parts.stark_proof,
            metadata: parts.metadata.into(),
        }
    }

    pub fn to_backend(&self, circuit: &str) -> backend::BackendResult<backend::Proof> {
        backend::Proof::from_parts(
            circuit,
            ProofParts::new(self.stark_proof.clone(), self.metadata.clone().into()),
        )
    }

    pub fn validate(&self) -> ChainResult<()> {
        let min_len = 3 * backend::COMMITMENT_LEN;
        if self.stark_proof.len() < min_len {
            return Err(ChainError::Crypto(format!(
                "proof payload must be at least {min_len} bytes, found {}",
                self.stark_proof.len()
            )));
        }
        self.metadata.validate()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofMetadata {
    #[serde(with = "serde_hex_32")]
    pub trace_commitment: [u8; 32],
    #[serde(with = "serde_hex_32")]
    pub quotient_commitment: [u8; 32],
    #[serde(with = "serde_hex_32")]
    pub fri_commitment: [u8; 32],
    #[serde(with = "serde_hex_32")]
    pub public_inputs_hash: [u8; 32],
    #[serde(default = "default_hash_format")]
    pub hash_format: HashFormat,
    pub security_bits: u32,
    pub use_gpu: bool,
}

impl From<backend::ProofMetadata> for ProofMetadata {
    fn from(value: backend::ProofMetadata) -> Self {
        Self {
            trace_commitment: *value.trace_commitment(),
            quotient_commitment: *value.quotient_commitment(),
            fri_commitment: *value.fri_commitment(),
            public_inputs_hash: *value.public_inputs_hash(),
            hash_format: value.hash_format(),
            security_bits: value.security_bits(),
            use_gpu: value.use_gpu(),
        }
    }
}

impl From<ProofMetadata> for backend::ProofMetadata {
    fn from(value: ProofMetadata) -> Self {
        backend::ProofMetadata::with_hash_format(
            value.trace_commitment,
            value.quotient_commitment,
            value.fri_commitment,
            value.public_inputs_hash,
            value.hash_format,
            value.security_bits,
            value.use_gpu,
        )
    }
}

impl ProofMetadata {
    pub fn validate(&self) -> ChainResult<()> {
        match self.hash_format {
            HashFormat::PoseidonMerkleCap => Ok(()),
        }
    }
}

fn default_hash_format() -> HashFormat {
    HashFormat::PoseidonMerkleCap
}

mod serde_base64_vec {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let normalized = encoded.trim();
        if normalized.is_empty() {
            return Err(serde::de::Error::custom("expected base64-encoded payload"));
        }
        BASE64_STANDARD
            .decode(normalized.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

mod serde_hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let value = encoded.trim();
        let bytes = hex::decode(value).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32-byte hex value"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
}
