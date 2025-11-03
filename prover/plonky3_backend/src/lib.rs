use blake3::Hasher;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

mod circuits;

#[cfg(feature = "plonky3-gpu")]
mod gpu;

#[cfg(feature = "plonky3-gpu")]
pub use gpu::GpuResources;

pub use circuits::consensus::{
    encode_consensus_public_inputs, validate_consensus_public_inputs, ConsensusBindings,
    ConsensusCircuit, ConsensusPublicInputs, ConsensusVrfEntry, ConsensusVrfPoseidonInput,
    ConsensusVrfPublicEntry, ConsensusWitness, VotePower, VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH,
};

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
    #[error("proof metadata security bits mismatch for {0} circuit")]
    SecurityParameterMismatch(String),
    #[error("proof metadata GPU flag mismatch for {0} circuit")]
    GpuModeMismatch(String),
    #[error("invalid {circuit} witness: {message}")]
    InvalidWitness { circuit: String, message: String },
    #[error("invalid {circuit} public inputs: {message}")]
    InvalidPublicInputs { circuit: String, message: String },
}

pub type BackendResult<T> = Result<T, BackendError>;

#[derive(Clone, Debug)]
pub struct ConsensusProof {
    pub commitment: String,
    pub public_inputs: Value,
    pub proof: Proof,
}

#[derive(Clone, Debug)]
pub struct VerifyingKey {
    bytes: Vec<u8>,
    hash: [u8; 32],
}

impl VerifyingKey {
    pub fn from_bytes(bytes: Vec<u8>, circuit: &str) -> BackendResult<Self> {
        if bytes.is_empty() {
            return Err(BackendError::MissingVerifyingKey(circuit.to_string()));
        }
        Ok(Self {
            hash: *blake3::hash(&bytes).as_bytes(),
            bytes,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
}

#[derive(Clone, Debug)]
pub struct ProvingKey {
    bytes: Vec<u8>,
    hash: [u8; 32],
}

impl ProvingKey {
    pub fn from_bytes(bytes: Vec<u8>, circuit: &str) -> BackendResult<Self> {
        if bytes.is_empty() {
            return Err(BackendError::MissingProvingKey(circuit.to_string()));
        }
        Ok(Self {
            hash: *blake3::hash(&bytes).as_bytes(),
            bytes,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
}

#[derive(Clone, Debug)]
pub struct ProofMetadata {
    verifying_key_hash: [u8; 32],
    public_inputs_hash: [u8; 32],
    fri_digest: [u8; 32],
    security_bits: u32,
    use_gpu: bool,
}

impl ProofMetadata {
    pub fn new(
        verifying_key_hash: [u8; 32],
        public_inputs_hash: [u8; 32],
        fri_digest: [u8; 32],
        security_bits: u32,
        use_gpu: bool,
    ) -> Self {
        Self {
            verifying_key_hash,
            public_inputs_hash,
            fri_digest,
            security_bits,
            use_gpu,
        }
    }

    pub fn verifying_key_hash(&self) -> &[u8; 32] {
        &self.verifying_key_hash
    }

    pub fn public_inputs_hash(&self) -> &[u8; 32] {
        &self.public_inputs_hash
    }

    pub fn fri_digest(&self) -> &[u8; 32] {
        &self.fri_digest
    }

    pub fn security_bits(&self) -> u32 {
        self.security_bits
    }

    pub fn use_gpu(&self) -> bool {
        self.use_gpu
    }
}

#[derive(Clone, Debug)]
pub struct Proof {
    proof_blob: Vec<u8>,
    fri_transcript: Vec<u8>,
    openings: Vec<u8>,
    metadata: ProofMetadata,
}

impl Proof {
    pub fn from_parts(
        circuit: &str,
        proof_blob: Vec<u8>,
        fri_transcript: Vec<u8>,
        openings: Vec<u8>,
        metadata: ProofMetadata,
    ) -> BackendResult<Self> {
        if proof_blob.len() != PROOF_BLOB_LEN {
            return Err(BackendError::InvalidProofLength {
                circuit: circuit.to_string(),
                expected: PROOF_BLOB_LEN,
                actual: proof_blob.len(),
            });
        }
        let (key_segment, rest) = proof_blob.split_at(32);
        if key_segment != metadata.verifying_key_hash() {
            return Err(BackendError::VerifyingKeyMismatch(circuit.to_string()));
        }
        let (inputs_segment, fri_segment) = rest.split_at(32);
        if inputs_segment != metadata.public_inputs_hash() {
            return Err(BackendError::PublicInputDigestMismatch(circuit.to_string()));
        }
        if fri_segment != metadata.fri_digest() {
            return Err(BackendError::FriDigestMismatch(circuit.to_string()));
        }
        Ok(Self {
            proof_blob,
            fri_transcript,
            openings,
            metadata,
        })
    }

    pub fn proof_blob(&self) -> &[u8] {
        &self.proof_blob
    }

    pub fn fri_transcript(&self) -> &[u8] {
        &self.fri_transcript
    }

    pub fn openings(&self) -> &[u8] {
        &self.openings
    }

    pub fn metadata(&self) -> &ProofMetadata {
        &self.metadata
    }

    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>, Vec<u8>, ProofMetadata) {
        (
            self.proof_blob,
            self.fri_transcript,
            self.openings,
            self.metadata,
        )
    }
}

#[derive(Clone, Debug)]
pub struct ProverContext {
    name: String,
    verifying_key: VerifyingKey,
    proving_key: ProvingKey,
    security_bits: u32,
    use_gpu: bool,
}

impl ProverContext {
    pub fn new(
        name: impl Into<String>,
        verifying_key: VerifyingKey,
        proving_key: ProvingKey,
        security_bits: u32,
        use_gpu: bool,
    ) -> BackendResult<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(BackendError::EmptyCircuit);
        }
        Ok(Self {
            name,
            verifying_key,
            proving_key,
            security_bits,
            use_gpu,
        })
    }

    pub fn circuit(&self) -> &str {
        &self.name
    }

    pub fn parameters(&self) -> (u32, bool) {
        (self.security_bits, self.use_gpu)
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    fn transcript_message(&self, commitment: &str, encoded_inputs: &[u8]) -> Vec<u8> {
        let mut transcript =
            Vec::with_capacity(self.name.len() + commitment.len() + encoded_inputs.len());
        transcript.extend_from_slice(self.name.as_bytes());
        transcript.extend_from_slice(commitment.as_bytes());
        transcript.extend_from_slice(encoded_inputs);
        transcript
    }

    pub fn prove(&self, commitment: &str, encoded_inputs: &[u8]) -> BackendResult<Proof> {
        let message = self.transcript_message(commitment, encoded_inputs);
        let inputs_digest = blake3::hash(encoded_inputs);
        let mut fri_hasher = Hasher::new_keyed(&self.verifying_key.hash);
        fri_hasher.update(&message);
        let fri_digest = fri_hasher.finalize();

        let metadata = ProofMetadata::new(
            self.verifying_key.hash(),
            *inputs_digest.as_bytes(),
            *fri_digest.as_bytes(),
            self.security_bits,
            self.use_gpu,
        );

        let mut proof_blob = Vec::with_capacity(PROOF_BLOB_LEN);
        proof_blob.extend_from_slice(metadata.verifying_key_hash());
        proof_blob.extend_from_slice(metadata.public_inputs_hash());
        proof_blob.extend_from_slice(metadata.fri_digest());

        let mut fri_transcript = Vec::with_capacity(message.len() + self.proving_key.bytes().len());
        fri_transcript.extend_from_slice(&message);
        fri_transcript.extend_from_slice(self.proving_key.bytes());

        let mut openings_hasher = Hasher::new_keyed(metadata.public_inputs_hash());
        openings_hasher.update(self.proving_key.bytes());
        openings_hasher.update(&fri_transcript);
        let openings_digest = openings_hasher.finalize();
        let openings = openings_digest.as_bytes().to_vec();

        Proof::from_parts(&self.name, proof_blob, fri_transcript, openings, metadata)
    }

    pub fn verifier(&self) -> VerifierContext {
        VerifierContext {
            name: self.name.clone(),
            verifying_key: self.verifying_key.clone(),
            security_bits: self.security_bits,
            use_gpu: self.use_gpu,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VerifierContext {
    name: String,
    verifying_key: VerifyingKey,
    security_bits: u32,
    use_gpu: bool,
}

impl VerifierContext {
    pub fn new(
        name: impl Into<String>,
        verifying_key: VerifyingKey,
        security_bits: u32,
        use_gpu: bool,
    ) -> BackendResult<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(BackendError::EmptyCircuit);
        }
        Ok(Self {
            name,
            verifying_key,
            security_bits,
            use_gpu,
        })
    }

    pub fn circuit(&self) -> &str {
        &self.name
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn verify(
        &self,
        commitment: &str,
        encoded_inputs: &[u8],
        proof: &Proof,
    ) -> BackendResult<()> {
        if proof.metadata().security_bits() != self.security_bits {
            return Err(BackendError::SecurityParameterMismatch(self.name.clone()));
        }
        if proof.metadata().use_gpu() != self.use_gpu {
            return Err(BackendError::GpuModeMismatch(self.name.clone()));
        }
        if proof.metadata().verifying_key_hash() != &self.verifying_key.hash {
            return Err(BackendError::VerifyingKeyMismatch(self.name.clone()));
        }
        if proof.proof_blob().len() != PROOF_BLOB_LEN {
            return Err(BackendError::InvalidProofLength {
                circuit: self.name.clone(),
                expected: PROOF_BLOB_LEN,
                actual: proof.proof_blob().len(),
            });
        }
        let inputs_digest = blake3::hash(encoded_inputs);
        if proof.metadata().public_inputs_hash() != inputs_digest.as_bytes() {
            return Err(BackendError::PublicInputDigestMismatch(self.name.clone()));
        }
        let message = {
            let mut transcript =
                Vec::with_capacity(self.name.len() + commitment.len() + encoded_inputs.len());
            transcript.extend_from_slice(self.name.as_bytes());
            transcript.extend_from_slice(commitment.as_bytes());
            transcript.extend_from_slice(encoded_inputs);
            transcript
        };
        let mut fri_hasher = Hasher::new_keyed(&self.verifying_key.hash);
        fri_hasher.update(&message);
        let expected_fri = fri_hasher.finalize();
        if proof.metadata().fri_digest() != expected_fri.as_bytes() {
            return Err(BackendError::FriDigestMismatch(self.name.clone()));
        }
        Ok(())
    }
}

fn encode_commitment_and_inputs(
    circuit: &str,
    public_inputs: &Value,
) -> BackendResult<(String, Vec<u8>)> {
    compute_commitment_and_inputs(public_inputs).map_err(|err| BackendError::InvalidPublicInputs {
        circuit: circuit.to_string(),
        message: format!("failed to encode canonical public inputs: {err}"),
    })
}

pub fn prove_consensus(
    context: &ProverContext,
    circuit: &ConsensusCircuit,
) -> BackendResult<ConsensusProof> {
    let public_inputs = circuit.public_inputs_value()?;
    let (commitment, encoded_inputs) =
        encode_commitment_and_inputs(context.circuit(), &public_inputs)?;
    let proof = context.prove(&commitment, &encoded_inputs)?;
    Ok(ConsensusProof {
        commitment,
        public_inputs,
        proof,
    })
}

pub fn verify_consensus(context: &VerifierContext, proof: &ConsensusProof) -> BackendResult<()> {
    validate_consensus_public_inputs(&proof.public_inputs)?;
    let (commitment, encoded_inputs) =
        encode_commitment_and_inputs(context.circuit(), &proof.public_inputs)?;
    if proof.commitment != commitment {
        return Err(BackendError::PublicInputDigestMismatch(
            context.circuit().to_string(),
        ));
    }
    context.verify(&proof.commitment, &encoded_inputs, &proof.proof)
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
