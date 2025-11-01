use blake3::Hasher;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

pub const PROOF_BLOB_LEN: usize = 96;

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("circuit name must not be empty")]
    EmptyCircuit,
    #[error("verifying key missing for {0} circuit")]
    MissingVerifyingKey(String),
    #[error("proving key missing for {0} circuit")]
    MissingProvingKey(String),
    #[error("proof blob must be {expected} bytes for {circuit} circuit, found {actual}")]
    InvalidProofLength {
        circuit: String,
        expected: usize,
        actual: usize,
    },
    #[error("verifying key mismatch for {0} circuit")]
    VerifyingKeyMismatch(String),
    #[error("public input digest mismatch for {0} circuit")]
    PublicInputDigestMismatch(String),
    #[error("FRI transcript digest mismatch for {0} circuit")]
    FriDigestMismatch(String),
}

pub type BackendResult<T> = Result<T, BackendError>;

#[derive(Clone, Debug)]
pub struct ProofBundle {
    verifying_key: Vec<u8>,
    public_inputs: Vec<u8>,
    proof_blob: Vec<u8>,
}

impl ProofBundle {
    pub fn verifying_key(&self) -> &[u8] {
        &self.verifying_key
    }

    pub fn public_inputs(&self) -> &[u8] {
        &self.public_inputs
    }

    pub fn proof_blob(&self) -> &[u8] {
        &self.proof_blob
    }

    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        (self.verifying_key, self.public_inputs, self.proof_blob)
    }
}

#[derive(Clone, Debug)]
pub struct Circuit {
    name: String,
    verifying_key: Vec<u8>,
    proving_key: Vec<u8>,
    verifying_key_hash: [u8; 32],
    proving_key_hash: [u8; 32],
    security_bits: u32,
    use_gpu: bool,
}

impl Circuit {
    pub fn keygen(
        name: impl Into<String>,
        verifying_key: Vec<u8>,
        proving_key: Vec<u8>,
        security_bits: u32,
        use_gpu: bool,
    ) -> BackendResult<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(BackendError::EmptyCircuit);
        }
        if verifying_key.is_empty() {
            return Err(BackendError::MissingVerifyingKey(name.clone()));
        }
        if proving_key.is_empty() {
            return Err(BackendError::MissingProvingKey(name.clone()));
        }
        let verifying_key_hash = *blake3::hash(&verifying_key).as_bytes();
        let proving_key_hash = *blake3::hash(&proving_key).as_bytes();
        Ok(Self {
            name,
            verifying_key,
            proving_key,
            verifying_key_hash,
            proving_key_hash,
            security_bits,
            use_gpu,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn verifying_key(&self) -> &[u8] {
        &self.verifying_key
    }

    pub fn proving_key(&self) -> &[u8] {
        &self.proving_key
    }

    pub fn security_bits(&self) -> u32 {
        self.security_bits
    }

    pub fn use_gpu(&self) -> bool {
        self.use_gpu
    }

    fn transcript_message(&self, commitment: &str, encoded_inputs: &[u8]) -> Vec<u8> {
        let mut transcript =
            Vec::with_capacity(self.name.len() + commitment.len() + encoded_inputs.len());
        transcript.extend_from_slice(self.name.as_bytes());
        transcript.extend_from_slice(commitment.as_bytes());
        transcript.extend_from_slice(encoded_inputs);
        transcript
    }

    pub fn prove(&self, commitment: &str, encoded_inputs: &[u8]) -> BackendResult<ProofBundle> {
        let message = self.transcript_message(commitment, encoded_inputs);
        let mut proof = Vec::with_capacity(PROOF_BLOB_LEN);
        proof.extend_from_slice(&self.verifying_key_hash);
        let inputs_digest = blake3::hash(encoded_inputs);
        proof.extend_from_slice(inputs_digest.as_bytes());
        let mut fri_hasher = Hasher::new_keyed(&self.proving_key_hash);
        fri_hasher.update(&message);
        let fri_digest = fri_hasher.finalize();
        proof.extend_from_slice(fri_digest.as_bytes());
        Ok(ProofBundle {
            verifying_key: self.verifying_key.clone(),
            public_inputs: encoded_inputs.to_vec(),
            proof_blob: proof,
        })
    }

    pub fn verify(
        &self,
        commitment: &str,
        verifying_key: &[u8],
        encoded_inputs: &[u8],
        proof: &[u8],
    ) -> BackendResult<()> {
        if verifying_key != self.verifying_key {
            return Err(BackendError::VerifyingKeyMismatch(self.name.clone()));
        }
        if proof.len() != PROOF_BLOB_LEN {
            return Err(BackendError::InvalidProofLength {
                circuit: self.name.clone(),
                expected: PROOF_BLOB_LEN,
                actual: proof.len(),
            });
        }
        let (key_hash_segment, rest) = proof.split_at(32);
        let expected_key_hash = blake3::hash(verifying_key);
        if key_hash_segment != expected_key_hash.as_bytes() {
            return Err(BackendError::VerifyingKeyMismatch(self.name.clone()));
        }
        let (inputs_segment, fri_segment) = rest.split_at(32);
        let expected_inputs = blake3::hash(encoded_inputs);
        if inputs_segment != expected_inputs.as_bytes() {
            return Err(BackendError::PublicInputDigestMismatch(self.name.clone()));
        }
        let message = self.transcript_message(commitment, encoded_inputs);
        let mut fri_hasher = Hasher::new_keyed(&self.proving_key_hash);
        fri_hasher.update(&message);
        let expected_fri = fri_hasher.finalize();
        if fri_segment != expected_fri.as_bytes() {
            return Err(BackendError::FriDigestMismatch(self.name.clone()));
        }
        Ok(())
    }
}

pub fn compute_commitment_and_inputs(
    public_inputs: &Value,
) -> serde_json::Result<(String, Vec<u8>)> {
    let encoded = encode_canonical_json(public_inputs)?;
    let mut hasher = Hasher::new();
    hasher.update(&encoded);
    let commitment = hasher.finalize().to_hex().to_string();
    Ok((commitment, encoded))
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

impl<'a> serde::Serialize for CanonicalValue<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::{SerializeMap, SerializeSeq};
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
