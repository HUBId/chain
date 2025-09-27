use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::{ChainError, ChainResult};

/// Generic representation of a Plonky3 proof artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plonky3Proof {
    pub circuit: String,
    pub commitment: String,
    pub public_inputs: Value,
    #[serde(with = "serde_base64_vec")]
    pub proof: Vec<u8>,
    #[serde(with = "serde_hex_key")]
    pub verifying_key: [u8; 32],
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
        BASE64_STANDARD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

mod serde_hex_key {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(key: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(key))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = hex::decode(&encoded).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("verifying key must be 32 bytes"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }
}
