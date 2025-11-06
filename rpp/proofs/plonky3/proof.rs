use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::{ChainError, ChainResult};
use plonky3_backend::{self as backend, HashFormat, ProofParts};

use super::params::Plonky3Parameters;

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

/// Canonical serialization of Plonky3 proof payloads.
///
/// The JSON representation is compatible with the node and wallet APIs:
///
/// ```json
/// {
///   "circuit": "transaction",
///   "commitment": "<hex>",
///   "public_inputs": { "witness": { /* circuit dependent */ } },
///   "payload": {
///     "stark_proof": "<base64>",
///     "auxiliary_payloads": ["<base64>", "<base64>", ...],
///     "metadata": {
///       "trace_commitment": "<hex>",
///       "quotient_commitment": "<hex>",
///       "random_commitment": "<hex>",
///       "fri_commitments": ["<hex>", "<hex>", ...],
///       "canonical_public_inputs": "<base64>",
///       "transcript": { /* transcript checkpoints */ },
///       "hash_format": "poseidon_merkle_cap",
///       "security_bits": 128,
///       "derived_security_bits": 128,
///       "use_gpu": false
///     }
///   }
/// }
/// ```
///
/// Byte-oriented sections are base64 encoded while all hash digests remain
/// hex encoded to preserve backwards compatibility with existing tooling.
#[derive(Clone, Debug, Serialize)]
pub struct ProofPayload {
    #[serde(with = "serde_base64_vec")]
    pub stark_proof: Vec<u8>,
    #[serde(default, with = "serde_base64_vec_vec")]
    pub auxiliary_payloads: Vec<Vec<u8>>,
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
            #[serde(default, with = "serde_base64_vec_vec")]
            auxiliary_payloads: Vec<Vec<u8>>,
            metadata: ProofMetadata,
        }

        let value = serde_json::Value::deserialize(deserializer)?;
        if let Ok(current) = CurrentPayload::deserialize(value.clone()) {
            return Ok(Self {
                stark_proof: current.stark_proof,
                auxiliary_payloads: current.auxiliary_payloads,
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
            stark_proof: parts.serialized_proof,
            auxiliary_payloads: parts.auxiliary_payloads,
            metadata: parts.metadata.into(),
        }
    }

    pub fn to_backend(&self, circuit: &str) -> backend::BackendResult<backend::Proof> {
        self.metadata
            .validate()
            .map_err(|err| backend::BackendError::InvalidPublicInputs {
                circuit: circuit.to_string(),
                message: err.to_string(),
            })?;
        let metadata = self.metadata.clone().into_backend(circuit)?;
        backend::Proof::from_parts(
            circuit,
            ProofParts::new(
                self.stark_proof.clone(),
                metadata,
                self.auxiliary_payloads.clone(),
            ),
        )
    }

    pub fn validate(&self) -> ChainResult<()> {
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
    #[serde(default, with = "serde_hex_32_option")]
    pub random_commitment: Option<[u8; 32]>,
    #[serde(with = "serde_hex_32_vec")]
    pub fri_commitments: Vec<[u8; 32]>,
    #[serde(with = "serde_base64_vec")]
    pub canonical_public_inputs: Vec<u8>,
    pub transcript: TranscriptMetadata,
    #[serde(default = "default_hash_format")]
    pub hash_format: HashFormat,
    pub security_bits: u32,
    pub derived_security_bits: u32,
    pub use_gpu: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranscriptMetadata {
    pub degree_bits: u32,
    pub trace_length_bits: u32,
    pub alpha: Vec<u32>,
    pub zeta: Vec<u32>,
    pub pcs_alpha: Vec<u32>,
    pub fri_challenges: Vec<Vec<u32>>,
    pub query_indices: Vec<u32>,
    pub checkpoints: Vec<TranscriptCheckpointMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranscriptCheckpointMetadata {
    pub stage: TranscriptStageMetadata,
    #[serde(with = "serde_base64_vec")]
    pub state: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptStageMetadata {
    AfterPublicValues,
    AfterCommitments,
    AfterZetaSampling,
    AfterQuerySampling,
}

impl From<backend::ProofMetadata> for ProofMetadata {
    fn from(value: backend::ProofMetadata) -> Self {
        Self {
            trace_commitment: *value.trace_commitment(),
            quotient_commitment: *value.quotient_commitment(),
            random_commitment: value.random_commitment().copied(),
            fri_commitments: value.fri_commitments().to_vec(),
            canonical_public_inputs: value.canonical_public_inputs().to_vec(),
            transcript: TranscriptMetadata::from(value.transcript().clone()),
            hash_format: value.hash_format(),
            security_bits: value.security_bits(),
            derived_security_bits: value.derived_security_bits(),
            use_gpu: value.use_gpu(),
        }
    }
}

impl From<backend::TranscriptSnapshot> for TranscriptMetadata {
    fn from(snapshot: backend::TranscriptSnapshot) -> Self {
        Self {
            degree_bits: snapshot.degree_bits(),
            trace_length_bits: snapshot.trace_length_bits(),
            alpha: snapshot.alpha().limbs().to_vec(),
            zeta: snapshot.zeta().limbs().to_vec(),
            pcs_alpha: snapshot.pcs_alpha().limbs().to_vec(),
            fri_challenges: snapshot
                .fri_challenges()
                .iter()
                .map(|challenge| challenge.limbs().to_vec())
                .collect(),
            query_indices: snapshot.query_indices().to_vec(),
            checkpoints: snapshot
                .checkpoints()
                .iter()
                .cloned()
                .map(TranscriptCheckpointMetadata::from)
                .collect(),
        }
    }
}

impl From<backend::TranscriptCheckpoint> for TranscriptCheckpointMetadata {
    fn from(checkpoint: backend::TranscriptCheckpoint) -> Self {
        Self {
            stage: TranscriptStageMetadata::from(checkpoint.stage()),
            state: checkpoint.state().to_vec(),
        }
    }
}

impl From<backend::TranscriptStage> for TranscriptStageMetadata {
    fn from(stage: backend::TranscriptStage) -> Self {
        match stage {
            backend::TranscriptStage::AfterPublicValues => Self::AfterPublicValues,
            backend::TranscriptStage::AfterCommitments => Self::AfterCommitments,
            backend::TranscriptStage::AfterZetaSampling => Self::AfterZetaSampling,
            backend::TranscriptStage::AfterQuerySampling => Self::AfterQuerySampling,
        }
    }
}

impl TranscriptMetadata {
    fn into_backend(self, circuit: &str) -> backend::BackendResult<backend::TranscriptSnapshot> {
        let alpha = limbs_to_challenge(circuit, self.alpha)?;
        let zeta = limbs_to_challenge(circuit, self.zeta)?;
        let pcs_alpha = limbs_to_challenge(circuit, self.pcs_alpha)?;
        let fri_challenges: backend::BackendResult<Vec<_>> = self
            .fri_challenges
            .into_iter()
            .map(|value| limbs_to_challenge(circuit, value))
            .collect();
        let checkpoints: backend::BackendResult<Vec<_>> = self
            .checkpoints
            .into_iter()
            .map(|checkpoint| checkpoint.into_backend(circuit))
            .collect();

        Ok(backend::TranscriptSnapshot::new(
            self.degree_bits,
            self.trace_length_bits,
            alpha,
            zeta,
            pcs_alpha,
            fri_challenges?,
            self.query_indices,
            checkpoints?,
        ))
    }
}

impl TranscriptCheckpointMetadata {
    fn into_backend(self, circuit: &str) -> backend::BackendResult<backend::TranscriptCheckpoint> {
        let stage = backend::TranscriptStage::from_str(self.stage.as_str()).ok_or_else(|| {
            backend::BackendError::InvalidPublicInputs {
                circuit: circuit.to_string(),
                message: format!("unknown transcript stage {}", self.stage.as_str()),
            }
        })?;
        Ok(backend::TranscriptCheckpoint::new(stage, self.state))
    }

    fn stage(&self) -> TranscriptStageMetadata {
        self.stage
    }
}

impl TranscriptStageMetadata {
    fn as_str(self) -> &'static str {
        match self {
            TranscriptStageMetadata::AfterPublicValues => "after_public_values",
            TranscriptStageMetadata::AfterCommitments => "after_commitments",
            TranscriptStageMetadata::AfterZetaSampling => "after_zeta_sampling",
            TranscriptStageMetadata::AfterQuerySampling => "after_query_sampling",
        }
    }
}

fn limbs_to_challenge(
    circuit: &str,
    values: Vec<u32>,
) -> backend::BackendResult<backend::ChallengeValue> {
    use backend::BackendError;
    let limbs: [u32; 4] = values
        .try_into()
        .map_err(|_| BackendError::InvalidPublicInputs {
            circuit: circuit.to_string(),
            message: "challenge vector must contain exactly four limbs".into(),
        })?;
    Ok(backend::ChallengeValue::from_limbs(limbs))
}

impl ProofMetadata {
    pub fn validate(&self) -> ChainResult<()> {
        match self.hash_format {
            HashFormat::PoseidonMerkleCap => {}
        }

        if self.derived_security_bits < self.security_bits {
            return Err(ChainError::Crypto(
                "derived security cannot undershoot negotiated security".into(),
            ));
        }

        ensure_challenge_length(&self.transcript.alpha, "alpha")?;
        ensure_challenge_length(&self.transcript.zeta, "zeta")?;
        ensure_challenge_length(&self.transcript.pcs_alpha, "pcs_alpha")?;
        for (index, challenge) in self.transcript.fri_challenges.iter().enumerate() {
            ensure_challenge_length(challenge, &format!("fri_challenge[{index}]"))?;
        }

        Ok(())
    }
}

impl ProofMetadata {
    pub fn ensure_alignment(&self, params: &Plonky3Parameters) -> Result<(), String> {
        if self.security_bits != params.security_bits {
            return Err(format!(
                "plonky3 proof negotiated {} security bits but {} were requested",
                self.security_bits, params.security_bits
            ));
        }
        if self.derived_security_bits < params.security_bits {
            return Err(format!(
                "plonky3 proof derived security {} bits below requested {} bits",
                self.derived_security_bits, params.security_bits
            ));
        }
        if self.use_gpu != params.use_gpu_acceleration {
            return Err(format!(
                "plonky3 proof GPU flag {} does not match requested {}",
                self.use_gpu, params.use_gpu_acceleration
            ));
        }

        Ok(())
    }
}

fn ensure_challenge_length(values: &[u32], label: &str) -> ChainResult<()> {
    if values.len() == 4 {
        Ok(())
    } else {
        Err(ChainError::Crypto(format!(
            "{label} challenge must contain four limbs"
        )))
    }
}

impl ProofMetadata {
    fn into_backend(self, circuit: &str) -> backend::BackendResult<backend::ProofMetadata> {
        let ProofMetadata {
            trace_commitment,
            quotient_commitment,
            random_commitment,
            fri_commitments,
            canonical_public_inputs,
            transcript,
            hash_format,
            security_bits,
            derived_security_bits,
            use_gpu,
        } = self;

        let transcript = transcript.into_backend(circuit)?;
        Ok(backend::ProofMetadata::assemble(
            trace_commitment,
            quotient_commitment,
            random_commitment,
            fri_commitments,
            canonical_public_inputs,
            transcript,
            hash_format,
            security_bits,
            derived_security_bits,
            use_gpu,
        ))
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

mod serde_hex_32_option {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Option::<String>::deserialize(deserializer)?;
        match encoded {
            Some(value) => {
                let normalized = value.trim();
                let bytes = hex::decode(normalized).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32-byte hex value"));
                }
                let mut array = [0u8; 32];
                array.copy_from_slice(&bytes);
                Ok(Some(array))
            }
            None => Ok(None),
        }
    }
}

mod serde_hex_32_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(values: &Vec<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<String> = values.iter().map(|bytes| hex::encode(bytes)).collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Vec::<String>::deserialize(deserializer)?;
        encoded
            .into_iter()
            .map(|value| {
                let normalized = value.trim();
                let bytes = hex::decode(normalized).map_err(serde::de::Error::custom)?;
                if bytes.len() != 32 {
                    return Err(serde::de::Error::custom("expected 32-byte hex value"));
                }
                let mut array = [0u8; 32];
                array.copy_from_slice(&bytes);
                Ok(array)
            })
            .collect()
    }
}

mod serde_base64_vec_vec {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(payloads: &Vec<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded: Vec<String> = payloads
            .iter()
            .map(|payload| BASE64_STANDARD.encode(payload))
            .collect();
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = Option::<Vec<String>>::deserialize(deserializer)?;
        match encoded {
            Some(values) => values
                .into_iter()
                .map(|value| {
                    let trimmed = value.trim();
                    BASE64_STANDARD
                        .decode(trimmed.as_bytes())
                        .map_err(serde::de::Error::custom)
                })
                .collect(),
            None => Ok(Vec::new()),
        }
    }
}
