use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use blake3::Hasher;
use flate2::read::GzDecoder;
use once_cell::sync::OnceLock;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use thiserror::Error;

mod circuits;
mod public_inputs;

#[cfg(feature = "plonky3-gpu")]
mod gpu;

#[cfg(feature = "plonky3-gpu")]
pub use gpu::GpuResources;

pub use circuits::consensus::{
    encode_consensus_public_inputs, validate_consensus_public_inputs, ConsensusBindings,
    ConsensusCircuit, ConsensusPublicInputs, ConsensusVrfEntry, ConsensusVrfPoseidonInput,
    ConsensusVrfPublicEntry, ConsensusWitness, VotePower, VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH,
};

/// Number of bytes that form the deterministic proof header.
///
/// The header currently stores three 32-byte digests in the following order:
///
/// * verifying key hash
/// * canonical public inputs hash
/// * FRI transcript digest
///
/// The serialized proof blob may contain additional sections after the header
/// to accommodate future commitment data without breaking backwards
/// compatibility. Consumers must therefore treat the constant as a **minimum**
/// length guarantee instead of an exact size check.
pub const PROOF_BLOB_LEN: usize = 96;

pub use public_inputs::{compute_commitment_and_inputs, encode_canonical_json};

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
    #[error("invalid {kind} encoding for {circuit} circuit: {message}")]
    InvalidKeyEncoding {
        circuit: String,
        kind: String,
        message: String,
    },
    #[error("failed to load Plonky3 setup manifest: {0}")]
    SetupManifest(String),
    #[error("Plonky3 setup manifest missing {0} circuit entry")]
    SetupManifestMissing(String),
    #[error("Plonky3 setup artifact mismatch for {circuit} circuit: {message}")]
    SetupArtifactMismatch { circuit: String, message: String },
}

pub type BackendResult<T> = Result<T, BackendError>;

#[derive(Clone)]
struct SignedFixture {
    verifying_key_hash: [u8; 32],
}

static SIGNED_FIXTURES: OnceLock<HashMap<String, SignedFixture>> = OnceLock::new();

#[derive(Deserialize)]
struct SetupManifestDoc {
    #[serde(default)]
    metadata: Option<Value>,
    artifacts: Vec<SetupManifestEntry>,
}

#[derive(Deserialize)]
struct SetupManifestEntry {
    circuit: String,
    file: String,
    sha256: String,
}

#[derive(Deserialize)]
struct SetupFixtureDoc {
    circuit: String,
    verifying_key: SetupFixtureKey,
    proving_key: SetupFixtureKey,
}

#[derive(Deserialize)]
struct SetupFixtureKey {
    value: String,
    #[serde(default)]
    encoding: Option<String>,
    #[serde(default)]
    compression: Option<String>,
    #[serde(default)]
    byte_length: Option<u64>,
}

fn setup_directory() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../config/plonky3/setup");
    path
}

fn signed_fixtures() -> BackendResult<&'static HashMap<String, SignedFixture>> {
    SIGNED_FIXTURES.get_or_try_init(load_signed_fixtures)
}

fn load_signed_fixtures() -> BackendResult<HashMap<String, SignedFixture>> {
    let dir = setup_directory();
    let manifest_path = dir.join("manifest.json");
    let manifest_contents = fs::read_to_string(&manifest_path).map_err(|err| {
        BackendError::SetupManifest(format!("{}: {err}", manifest_path.display()))
    })?;
    let manifest: SetupManifestDoc = serde_json::from_str(&manifest_contents).map_err(|err| {
        BackendError::SetupManifest(format!("{}: {err}", manifest_path.display()))
    })?;

    let mut fixtures = HashMap::new();
    for entry in manifest.artifacts {
        let file_path = dir.join(&entry.file);
        let payload = fs::read_to_string(&file_path).map_err(|err| {
            BackendError::SetupManifest(format!("{}: {err}", file_path.display()))
        })?;
        let mut hasher = Sha256::new();
        hasher.update(payload.as_bytes());
        let digest = hasher.finalize();
        let expected_bytes = hex::decode(entry.sha256.trim()).map_err(|err| {
            BackendError::SetupManifest(format!(
                "manifest entry for {} has invalid sha256: {err}",
                entry.circuit
            ))
        })?;
        let expected: [u8; 32] = expected_bytes.try_into().map_err(|_| {
            BackendError::SetupManifest(format!(
                "manifest entry for {} must encode a 32-byte sha256 digest",
                entry.circuit
            ))
        })?;
        if digest.as_slice() != expected {
            return Err(BackendError::SetupArtifactMismatch {
                circuit: entry.circuit.clone(),
                message: "artifact sha256 does not match manifest".into(),
            });
        }

        let fixture: SetupFixtureDoc =
            serde_json::from_str(&payload).map_err(|err| BackendError::SetupArtifactMismatch {
                circuit: entry.circuit.clone(),
                message: format!("invalid setup artifact JSON: {err}"),
            })?;
        if fixture.circuit != entry.circuit {
            return Err(BackendError::SetupArtifactMismatch {
                circuit: entry.circuit.clone(),
                message: format!(
                    "manifest circuit '{}' does not match fixture circuit '{}'",
                    entry.circuit, fixture.circuit
                ),
            });
        }

        let verifying_bytes =
            decode_fixture_key(&fixture, &fixture.verifying_key, "verifying key")?;
        decode_fixture_key(&fixture, &fixture.proving_key, "proving key")?;

        let verifying_hash = blake3::hash(&verifying_bytes);
        if fixtures
            .insert(
                fixture.circuit.clone(),
                SignedFixture {
                    verifying_key_hash: *verifying_hash.as_bytes(),
                },
            )
            .is_some()
        {
            return Err(BackendError::SetupManifest(format!(
                "duplicate circuit '{}' in manifest",
                fixture.circuit
            )));
        }
    }

    Ok(fixtures)
}

fn decode_fixture_key(
    doc: &SetupFixtureDoc,
    descriptor: &SetupFixtureKey,
    kind: &str,
) -> BackendResult<Vec<u8>> {
    let encoding = descriptor.encoding.as_deref().unwrap_or("base64");
    let bytes = decode_key_bytes(
        &descriptor.value,
        encoding,
        descriptor.compression.as_deref(),
        &doc.circuit,
        kind,
    )
    .map_err(|err| BackendError::SetupArtifactMismatch {
        circuit: doc.circuit.clone(),
        message: format!("failed to decode {kind}: {err}"),
    })?;
    if let Some(expected) = descriptor.byte_length {
        if bytes.len() != expected as usize {
            return Err(BackendError::SetupArtifactMismatch {
                circuit: doc.circuit.clone(),
                message: format!(
                    "{kind} length mismatch: expected {expected} bytes, found {}",
                    bytes.len()
                ),
            });
        }
    }
    Ok(bytes)
}

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

    pub fn from_encoded_parts(
        value: &str,
        encoding: &str,
        compression: Option<&str>,
        circuit: &str,
    ) -> BackendResult<Self> {
        let bytes = decode_key_bytes(value, encoding, compression, circuit, "verifying key")?;
        Self::from_bytes(bytes, circuit)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn json_schema() -> Value {
        key_schema(
            "Plonky3 Verifying Key",
            "Descriptor for a verifying key artifact",
        )
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

    pub fn from_encoded_parts(
        value: &str,
        encoding: &str,
        compression: Option<&str>,
        circuit: &str,
    ) -> BackendResult<Self> {
        let bytes = decode_key_bytes(value, encoding, compression, circuit, "proving key")?;
        Self::from_bytes(bytes, circuit)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn json_schema() -> Value {
        key_schema(
            "Plonky3 Proving Key",
            "Descriptor for a proving key artifact",
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashFormat {
    Blake3,
}

impl Default for HashFormat {
    fn default() -> Self {
        Self::Blake3
    }
}

impl HashFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Blake3 => "blake3",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProofMetadata {
    verifying_key_hash: [u8; 32],
    public_inputs_hash: [u8; 32],
    fri_digest: [u8; 32],
    hash_format: HashFormat,
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
        Self::with_hash_format(
            verifying_key_hash,
            public_inputs_hash,
            fri_digest,
            HashFormat::default(),
            security_bits,
            use_gpu,
        )
    }

    pub fn with_hash_format(
        verifying_key_hash: [u8; 32],
        public_inputs_hash: [u8; 32],
        fri_digest: [u8; 32],
        hash_format: HashFormat,
        security_bits: u32,
        use_gpu: bool,
    ) -> Self {
        Self {
            verifying_key_hash,
            public_inputs_hash,
            fri_digest,
            hash_format,
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

    pub fn hash_format(&self) -> HashFormat {
        self.hash_format
    }

    pub fn security_bits(&self) -> u32 {
        self.security_bits
    }

    pub fn use_gpu(&self) -> bool {
        self.use_gpu
    }

    pub fn json_schema() -> Value {
        let mut schema = Map::new();
        schema.insert(
            "$schema".to_string(),
            Value::String("https://json-schema.org/draft/2020-12/schema".into()),
        );
        schema.insert(
            "title".to_string(),
            Value::String("Plonky3 Proof Metadata".into()),
        );
        schema.insert("type".to_string(), Value::String("object".into()));
        schema.insert(
            "description".to_string(),
            Value::String(
                "Hex-encoded transcript and security parameters embedded in a Plonky3 proof payload.".into(),
            ),
        );

        let mut properties = Map::new();
        properties.insert(
            "verifying_key_hash".into(),
            hex32_schema("BLAKE3 digest of the verifying key referenced by the proof."),
        );
        properties.insert(
            "public_inputs_hash".into(),
            hex32_schema("BLAKE3 digest of the encoded public inputs."),
        );
        properties.insert(
            "fri_digest".into(),
            hex32_schema("BLAKE3 digest derived from the prover/verifier transcript."),
        );
        properties.insert(
            "security_bits".into(),
            integer_schema(
                "Security parameter negotiated between prover and verifier.",
                1,
            ),
        );
        properties.insert(
            "use_gpu".into(),
            boolean_schema("Indicates whether the proof was constructed with GPU acceleration."),
        );
        properties.insert(
            "hash_format".into(),
            hash_format_schema(
                "Digest algorithm used for all 32-byte metadata hashes (header order preserved).",
            ),
        );

        schema.insert("properties".into(), Value::Object(properties));
        schema.insert(
            "required".into(),
            Value::Array(
                [
                    "verifying_key_hash",
                    "public_inputs_hash",
                    "fri_digest",
                    "security_bits",
                    "use_gpu",
                    "hash_format",
                ]
                .iter()
                .map(|key| Value::String(key.to_string()))
                .collect(),
            ),
        );
        schema.insert("additionalProperties".into(), Value::Bool(false));

        Value::Object(schema)
    }
}

#[derive(Clone, Debug)]
pub struct Proof {
    proof_blob: Vec<u8>,
    fri_transcript: Vec<u8>,
    openings: Vec<u8>,
    metadata: ProofMetadata,
}

/// Discrete proof sections used to assemble and disassemble [`Proof`] values.
///
/// The `proof_blob` starts with the deterministic 96-byte header that stores
/// the verifying key hash, canonical public inputs hash and FRI transcript
/// digest. Additional sections may follow the header to capture future
/// commitment payloads. The other vectors (`fri_transcript`, `openings`) may
/// have arbitrary lengths, mirroring the dynamic payloads produced by the
/// backend.
#[derive(Clone, Debug)]
pub struct ProofParts {
    pub proof_blob: Vec<u8>,
    pub fri_transcript: Vec<u8>,
    pub openings: Vec<u8>,
    pub metadata: ProofMetadata,
}

impl ProofParts {
    pub fn new(
        proof_blob: Vec<u8>,
        fri_transcript: Vec<u8>,
        openings: Vec<u8>,
        metadata: ProofMetadata,
    ) -> Self {
        Self {
            proof_blob,
            fri_transcript,
            openings,
            metadata,
        }
    }
}

impl Proof {
    pub fn from_parts(circuit: &str, parts: ProofParts) -> BackendResult<Self> {
        let ProofParts {
            proof_blob,
            fri_transcript,
            openings,
            metadata,
        } = parts;
        if proof_blob.len() < PROOF_BLOB_LEN {
            return Err(BackendError::InvalidProofLength {
                circuit: circuit.to_string(),
                expected: PROOF_BLOB_LEN,
                actual: proof_blob.len(),
            });
        }
        let (header, _) = proof_blob.split_at(PROOF_BLOB_LEN);
        let (key_segment, rest) = header.split_at(32);
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

    pub fn into_parts(self) -> ProofParts {
        ProofParts::new(
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

    pub fn prove(&self, public_inputs: &Value) -> BackendResult<(String, Proof)> {
        let (commitment, encoded_inputs) =
            encode_commitment_and_inputs(self.circuit(), public_inputs)?;
        let proof = self.prove_with_encoded(&commitment, &encoded_inputs)?;
        Ok((commitment, proof))
    }

    fn prove_with_encoded(&self, commitment: &str, encoded_inputs: &[u8]) -> BackendResult<Proof> {
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

        Proof::from_parts(
            &self.name,
            ProofParts::new(proof_blob, fri_transcript, openings, metadata),
        )
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
        public_inputs: &Value,
        proof: &Proof,
    ) -> BackendResult<()> {
        self.ensure_signed_fixture()?;
        let (expected_commitment, encoded_inputs) =
            encode_commitment_and_inputs(self.circuit(), public_inputs)?;
        if commitment != expected_commitment {
            return Err(BackendError::PublicInputDigestMismatch(self.name.clone()));
        }
        self.verify_with_encoded(commitment, &encoded_inputs, proof)
    }

    fn ensure_signed_fixture(&self) -> BackendResult<()> {
        let fixtures = signed_fixtures()?;
        let Some(entry) = fixtures.get(self.circuit()) else {
            return Err(BackendError::SetupManifestMissing(self.name.clone()));
        };
        if entry.verifying_key_hash != self.verifying_key.hash {
            return Err(BackendError::SetupArtifactMismatch {
                circuit: self.name.clone(),
                message: "verifying key hash mismatch".into(),
            });
        }
        Ok(())
    }

    fn verify_with_encoded(
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
        if proof.proof_blob().len() < PROOF_BLOB_LEN {
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

fn decode_key_bytes(
    value: &str,
    encoding: &str,
    compression: Option<&str>,
    circuit: &str,
    kind: &str,
) -> BackendResult<Vec<u8>> {
    let payload = value.trim();
    if payload.is_empty() {
        return Err(invalid_key_error(circuit, kind, "encoded payload is empty"));
    }

    let normalized_encoding = encoding.trim().to_ascii_lowercase();
    if normalized_encoding.is_empty() {
        return Err(invalid_key_error(
            circuit,
            kind,
            "encoding must be provided",
        ));
    }

    let mut bytes = match normalized_encoding.as_str() {
        "base64" | "b64" => BASE64_STANDARD.decode(payload.as_bytes()).map_err(|err| {
            invalid_key_error(circuit, kind, format!("invalid base64 payload: {err}"))
        })?,
        other => {
            return Err(invalid_key_error(
                circuit,
                kind,
                format!("unsupported encoding '{other}'"),
            ))
        }
    };

    if bytes.is_empty() {
        return Err(invalid_key_error(circuit, kind, "decoded payload is empty"));
    }

    if let Some(compression) = compression
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
    {
        match compression.as_str() {
            "gzip" | "gz" => {
                let mut decoder = GzDecoder::new(bytes.as_slice());
                let mut decompressed = Vec::new();
                decoder.read_to_end(&mut decompressed).map_err(|err| {
                    invalid_key_error(
                        circuit,
                        kind,
                        format!("failed to decompress gzip payload: {err}"),
                    )
                })?;
                if decompressed.is_empty() {
                    return Err(invalid_key_error(
                        circuit,
                        kind,
                        "decompressed payload is empty",
                    ));
                }
                bytes = decompressed;
            }
            "none" => {}
            other => {
                return Err(invalid_key_error(
                    circuit,
                    kind,
                    format!("unsupported compression '{other}'"),
                ))
            }
        }
    }

    Ok(bytes)
}

fn key_schema(title: &str, description: &str) -> Value {
    let mut schema = Map::new();
    schema.insert(
        "$schema".to_string(),
        Value::String("https://json-schema.org/draft/2020-12/schema".into()),
    );
    schema.insert("title".into(), Value::String(title.into()));
    schema.insert("type".into(), Value::String("object".into()));
    schema.insert("description".into(), Value::String(description.into()));

    let mut properties = Map::new();

    let mut encoding = Map::new();
    encoding.insert("type".into(), Value::String("string".into()));
    encoding.insert(
        "enum".into(),
        Value::Array(vec![Value::String("base64".into())]),
    );
    encoding.insert(
        "description".into(),
        Value::String("Encoding applied to the inline key material.".into()),
    );
    properties.insert("encoding".into(), Value::Object(encoding));

    let mut value = Map::new();
    value.insert("type".into(), Value::String("string".into()));
    value.insert("contentEncoding".into(), Value::String("base64".into()));
    value.insert(
        "description".into(),
        Value::String("Base64 payload containing the raw key bytes (compressed or raw).".into()),
    );
    properties.insert("value".into(), Value::Object(value));

    properties.insert(
        "byte_length".into(),
        integer_schema("Length of the decoded key in bytes.", 1),
    );

    let mut compression = Map::new();
    compression.insert("type".into(), Value::String("string".into()));
    compression.insert(
        "enum".into(),
        Value::Array(vec![
            Value::String("gzip".into()),
            Value::String("none".into()),
        ]),
    );
    compression.insert(
        "description".into(),
        Value::String(
            "Compression applied before encoding; omit or set to 'none' when the payload is raw."
                .into(),
        ),
    );
    properties.insert("compression".into(), Value::Object(compression));

    properties.insert(
        "hash_blake3".into(),
        hex32_schema("Optional BLAKE3 digest of the decoded key, useful for diagnostics."),
    );

    schema.insert("properties".into(), Value::Object(properties));
    schema.insert(
        "required".into(),
        Value::Array(vec![
            Value::String("encoding".into()),
            Value::String("value".into()),
            Value::String("byte_length".into()),
        ]),
    );
    schema.insert("additionalProperties".into(), Value::Bool(false));

    Value::Object(schema)
}

fn hex32_schema(description: &str) -> Value {
    let mut object = Map::new();
    object.insert("type".into(), Value::String("string".into()));
    object.insert("pattern".into(), Value::String("^[0-9a-fA-F]{64}$".into()));
    object.insert("description".into(), Value::String(description.into()));
    Value::Object(object)
}

fn integer_schema(description: &str, minimum: u64) -> Value {
    let mut object = Map::new();
    object.insert("type".into(), Value::String("integer".into()));
    object.insert("minimum".into(), Value::Number(Number::from(minimum)));
    object.insert("description".into(), Value::String(description.into()));
    Value::Object(object)
}

fn boolean_schema(description: &str) -> Value {
    let mut object = Map::new();
    object.insert("type".into(), Value::String("boolean".into()));
    object.insert("description".into(), Value::String(description.into()));
    Value::Object(object)
}

fn enum_schema(description: &str, variants: &[&str]) -> Value {
    let mut object = Map::new();
    object.insert("type".into(), Value::String("string".into()));
    object.insert(
        "enum".into(),
        Value::Array(
            variants
                .iter()
                .map(|value| Value::String((*value).into()))
                .collect(),
        ),
    );
    object.insert("description".into(), Value::String(description.into()));
    Value::Object(object)
}

fn hash_format_schema(description: &str) -> Value {
    enum_schema(description, &[HashFormat::Blake3.as_str()])
}

fn invalid_key_error(circuit: &str, kind: &str, message: impl Into<String>) -> BackendError {
    BackendError::InvalidKeyEncoding {
        circuit: circuit.to_string(),
        kind: kind.to_string(),
        message: message.into(),
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
    let (commitment, proof) = context.prove(&public_inputs)?;
    Ok(ConsensusProof {
        commitment,
        public_inputs,
        proof,
    })
}

pub fn verify_consensus(context: &VerifierContext, proof: &ConsensusProof) -> BackendResult<()> {
    validate_consensus_public_inputs(&proof.public_inputs)?;
    context.verify(&proof.commitment, &proof.public_inputs, &proof.proof)
}
