use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use flate2::read::GzDecoder;
use once_cell::sync::OnceLock;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

mod circuits;
mod config;
mod public_inputs;

use p3_uni_stark::{StarkProvingKey, StarkVerifyingKey};

#[cfg(feature = "plonky3-gpu")]
mod gpu;

#[cfg(feature = "plonky3-gpu")]
pub use gpu::GpuResources;

pub use circuits::consensus::{
    encode_consensus_public_inputs, validate_consensus_public_inputs, ConsensusBindings,
    ConsensusCircuit, ConsensusPublicInputs, ConsensusVrfEntry, ConsensusVrfPoseidonInput,
    ConsensusVrfPublicEntry, ConsensusWitness, VotePower, VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH,
};

/// Number of bytes encoded in the deterministic commitment header extracted
/// from the verifying key. The stub backend uses these values to emulate the
/// transcript commitments that a real Plonky3 prover would embed in the
/// serialized proof.
pub const COMMITMENT_LEN: usize = 32;

pub use public_inputs::{compute_commitment_and_inputs, encode_canonical_json};

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("circuit name must not be empty")]
    EmptyCircuit,
    #[error("verifying key missing for {0} circuit")]
    MissingVerifyingKey(String),
    #[error("proving key missing for {0} circuit")]
    MissingProvingKey(String),
    #[error(
        "proof payload must be at least {expected} bytes for {circuit} circuit, found {actual}"
    )]
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
    #[error("invalid AIR metadata: {0}")]
    InvalidAirMetadata(String),
}

pub type BackendResult<T> = Result<T, BackendError>;

pub use config::{
    build_circuit_stark_config, CircuitBaseField, CircuitChallengeField, CircuitChallenger,
    CircuitFriPcs, CircuitMerkleTreeMmcs, CircuitStarkConfig,
};

/// Convenience alias for verifying key handles emitted by the Plonky3 toolchain
/// once full circuit integration lands.
pub type CircuitStarkVerifyingKey = StarkVerifyingKey<CircuitStarkConfig>;

/// Convenience alias for proving key handles emitted by the Plonky3 toolchain
/// once full circuit integration lands.
pub type CircuitStarkProvingKey = StarkProvingKey<CircuitStarkConfig>;

#[derive(Clone)]
pub struct BackendStarkVerifyingKey {
    key: Arc<CircuitStarkVerifyingKey>,
    serialized_len: usize,
}

impl BackendStarkVerifyingKey {
    fn new(key: CircuitStarkVerifyingKey, serialized_len: usize) -> Self {
        Self {
            key: Arc::new(key),
            serialized_len,
        }
    }

    pub fn key(&self) -> Arc<CircuitStarkVerifyingKey> {
        Arc::clone(&self.key)
    }

    pub fn len(&self) -> usize {
        self.serialized_len
    }
}

impl fmt::Debug for BackendStarkVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BackendStarkVerifyingKey(len={})", self.len())
    }
}

#[derive(Clone)]
pub struct BackendStarkProvingKey {
    key: Arc<CircuitStarkProvingKey>,
    serialized_len: usize,
}

impl BackendStarkProvingKey {
    fn new(key: CircuitStarkProvingKey, serialized_len: usize) -> Self {
        Self {
            key: Arc::new(key),
            serialized_len,
        }
    }

    pub fn key(&self) -> Arc<CircuitStarkProvingKey> {
        Arc::clone(&self.key)
    }

    pub fn len(&self) -> usize {
        self.serialized_len
    }
}

impl fmt::Debug for BackendStarkProvingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BackendStarkProvingKey(len={})", self.len())
    }
}

/// Metadata describing the AIR that produced a proving/verifying key pair.
///
/// `plonky3-keygen` emits this information alongside every fixture so that
/// clients can cross-check evaluation domains and challenge layouts without
/// having to deserialize the binary keys eagerly.  Existing fixtures in the
/// repository omit the `metadata` field, hence the optional accessors.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct AirMetadata {
    #[serde(default)]
    air: Value,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

impl AirMetadata {
    /// Returns the nested `air` object emitted by the key generator if present.
    pub fn air(&self) -> Option<&Map<String, Value>> {
        self.air.as_object()
    }

    /// Looks up a field inside the nested `air` metadata object.
    pub fn air_field(&self, key: &str) -> Option<&Value> {
        self.air().and_then(|object| object.get(key))
    }

    /// Indicates whether the metadata payload is effectively empty.
    pub fn is_empty(&self) -> bool {
        self.air.is_null() && self.extra.is_empty()
    }

    /// Computes a digest that summarises the metadata contents.
    pub fn digest(&self) -> Option<[u8; 32]> {
        if self.is_empty() {
            return None;
        }

        let mut root = Map::new();
        root.insert("air".into(), self.air.clone());

        if !self.extra.is_empty() {
            let mut extra = Map::new();
            let mut entries: Vec<_> = self.extra.iter().collect();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (key, value) in entries {
                extra.insert(key.clone(), value.clone());
            }
            root.insert("extra".into(), Value::Object(extra));
        }

        let encoded = serde_json::to_vec(&Value::Object(root))
            .expect("serialising AIR metadata must not fail");
        let digest = blake3::hash(&encoded);
        Some(*digest.as_bytes())
    }
}

impl Default for AirMetadata {
    fn default() -> Self {
        Self {
            air: Value::Null,
            extra: HashMap::new(),
        }
    }
}

#[derive(Deserialize)]
struct LegacyEncodedKeyPayload<K> {
    key: K,
    #[serde(default)]
    metadata: Option<AirMetadata>,
}

fn validate_air_metadata(metadata: &AirMetadata) -> Result<(), String> {
    if metadata.is_empty() {
        return Ok(());
    }

    if metadata.air().is_none() {
        return Err("decoded AIR metadata missing air descriptor".into());
    }

    Ok(())
}

fn parse_key_payload<K>(
    decompressed: &[u8],
    circuit: &str,
    kind: &str,
) -> BackendResult<(K, AirMetadata)>
where
    K: DeserializeOwned,
{
    match bincode::deserialize::<(AirMetadata, K)>(decompressed) {
        Ok((metadata, key)) => {
            validate_air_metadata(&metadata)
                .map_err(|message| invalid_key_error(circuit, kind, message))?;
            Ok((key, metadata))
        }
        Err(err) => {
            if let Ok(payload) = bincode::deserialize::<LegacyEncodedKeyPayload<K>>(decompressed) {
                let metadata = payload.metadata.unwrap_or_default();
                validate_air_metadata(&metadata)
                    .map_err(|message| invalid_key_error(circuit, kind, message))?;
                Ok((payload.key, metadata))
            } else {
                Err(invalid_key_error(
                    circuit,
                    kind,
                    format!("failed to decode {kind} payload: {err}"),
                ))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyCompression {
    None,
    Gzip,
}

impl KeyCompression {
    fn from_hint(hint: Option<&str>) -> Result<Self, String> {
        let Some(value) = hint
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
        else {
            return Ok(Self::None);
        };
        let normalized = value.to_ascii_lowercase();
        match normalized.as_str() {
            "gzip" | "gz" => Ok(Self::Gzip),
            "none" => Ok(Self::None),
            other => Err(format!("unsupported compression '{other}'")),
        }
    }

    fn infer(bytes: &[u8]) -> Self {
        if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
            Self::Gzip
        } else {
            Self::None
        }
    }

    fn decompress_owned(self, bytes: Vec<u8>) -> std::io::Result<Vec<u8>> {
        match self {
            Self::None => Ok(bytes),
            Self::Gzip => decompress_gzip(&bytes),
        }
    }

    fn decompress_ref(self, bytes: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            Self::None => Ok(bytes.to_vec()),
            Self::Gzip => decompress_gzip(bytes),
        }
    }
}

struct EncodedKeyBytes {
    payload: Vec<u8>,
    compression: KeyCompression,
}

impl EncodedKeyBytes {
    fn new(payload: Vec<u8>, compression: KeyCompression) -> Self {
        Self {
            payload,
            compression,
        }
    }

    fn payload(&self) -> &[u8] {
        &self.payload
    }

    fn compression(&self) -> KeyCompression {
        self.compression
    }

    fn into_parts(self) -> (Vec<u8>, KeyCompression) {
        (self.payload, self.compression)
    }
}

fn decompress_gzip(bytes: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

#[derive(Clone)]
struct SignedFixture {
    verifying_key_hash: [u8; 32],
    air_metadata: Option<Arc<AirMetadata>>,
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
    #[serde(default)]
    metadata: Option<AirMetadata>,
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

/// Returns the parsed AIR metadata for a given circuit if present in the
/// bundled fixtures.
pub fn circuit_air_metadata(circuit: &str) -> BackendResult<Option<Arc<AirMetadata>>> {
    let fixtures = signed_fixtures()?;
    let Some(entry) = fixtures.get(circuit) else {
        return Err(BackendError::SetupManifestMissing(circuit.to_string()));
    };
    let Some(metadata) = &entry.air_metadata else {
        return Ok(None);
    };
    if metadata.is_empty() {
        return Err(BackendError::SetupArtifactMismatch {
            circuit: circuit.to_string(),
            message: "setup artifact metadata payload is empty".into(),
        });
    }
    if metadata.air().is_none() {
        return Err(BackendError::SetupArtifactMismatch {
            circuit: circuit.to_string(),
            message: "setup artifact metadata missing air descriptor".into(),
        });
    }
    Ok(Some(Arc::clone(metadata)))
}

/// Convenience helper for callers that require AIR metadata to be available.
pub fn require_circuit_air_metadata(circuit: &str) -> BackendResult<Arc<AirMetadata>> {
    match circuit_air_metadata(circuit)? {
        Some(metadata) => Ok(metadata),
        None => Err(BackendError::SetupArtifactMismatch {
            circuit: circuit.to_string(),
            message: "setup artifact missing AIR metadata".into(),
        }),
    }
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

        let metadata = fixture
            .metadata
            .as_ref()
            .map(|value| Arc::new(value.clone()));

        let verifying_bytes =
            decode_fixture_key(&fixture, &fixture.verifying_key, "verifying key")?;
        decode_fixture_key(&fixture, &fixture.proving_key, "proving key")?;

        let verifying_hash = blake3::hash(&verifying_bytes);
        if fixtures
            .insert(
                fixture.circuit.clone(),
                SignedFixture {
                    verifying_key_hash: *verifying_hash.as_bytes(),
                    air_metadata: metadata,
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
    let encoded = decode_key_bytes(
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
    let decompressed = encoded
        .compression()
        .decompress_ref(encoded.payload())
        .map_err(|err| BackendError::SetupArtifactMismatch {
            circuit: doc.circuit.clone(),
            message: format!("failed to decompress {kind}: {err}"),
        })?;
    if decompressed.is_empty() {
        return Err(BackendError::SetupArtifactMismatch {
            circuit: doc.circuit.clone(),
            message: format!("{kind} decompressed to zero bytes"),
        });
    }
    if let Some(expected) = descriptor.byte_length {
        if decompressed.len() != expected as usize {
            return Err(BackendError::SetupArtifactMismatch {
                circuit: doc.circuit.clone(),
                message: format!(
                    "{kind} length mismatch: expected {expected} bytes, found {}",
                    decompressed.len()
                ),
            });
        }
    }
    let (payload, _) = encoded.into_parts();
    Ok(payload)
}

#[derive(Clone, Debug)]
pub struct ConsensusProof {
    pub commitment: String,
    pub public_inputs: Value,
    pub proof: Proof,
}

#[derive(Clone)]
pub struct VerifyingKey {
    bytes: Arc<[u8]>,
    hash: [u8; 32],
    typed: Arc<BackendStarkVerifyingKey>,
    metadata: Arc<AirMetadata>,
}

impl VerifyingKey {
    pub fn from_bytes(bytes: Vec<u8>, circuit: &str) -> BackendResult<Self> {
        if bytes.is_empty() {
            return Err(BackendError::MissingVerifyingKey(circuit.to_string()));
        }
        let compression = KeyCompression::infer(&bytes);
        Self::from_compressed_bytes(bytes, compression, circuit)
    }

    pub fn from_encoded_parts(
        value: &str,
        encoding: &str,
        compression: Option<&str>,
        circuit: &str,
    ) -> BackendResult<Self> {
        let encoded = decode_key_bytes(value, encoding, compression, circuit, "verifying key")?;
        let (bytes, compression) = encoded.into_parts();
        Self::from_compressed_bytes(bytes, compression, circuit)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn stark_key(&self) -> &Arc<BackendStarkVerifyingKey> {
        &self.typed
    }

    pub fn air_metadata(&self) -> &Arc<AirMetadata> {
        &self.metadata
    }

    pub fn typed(&self) -> Arc<BackendStarkVerifyingKey> {
        Arc::clone(self.stark_key())
    }

    pub fn metadata(&self) -> Arc<AirMetadata> {
        Arc::clone(self.air_metadata())
    }

    pub fn with_metadata(mut self, metadata: Arc<AirMetadata>) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn json_schema() -> Value {
        key_schema(
            "Plonky3 Verifying Key",
            "Descriptor for a verifying key artifact",
        )
    }

    fn from_compressed_bytes(
        bytes: Vec<u8>,
        compression: KeyCompression,
        circuit: &str,
    ) -> BackendResult<Self> {
        let kind = "verifying key";
        let hash = *blake3::hash(&bytes).as_bytes();
        let decompressed = compression.decompress_owned(bytes).map_err(|err| {
            invalid_key_error(
                circuit,
                kind,
                format!("failed to decompress {kind} payload: {err}"),
            )
        })?;
        if decompressed.is_empty() {
            return Err(invalid_key_error(
                circuit,
                kind,
                "decompressed payload is empty",
            ));
        }
        let serialized_len = decompressed.len();
        let (key, metadata_value) =
            parse_key_payload::<CircuitStarkVerifyingKey>(&decompressed, circuit, kind)?;
        let metadata = Arc::new(metadata_value);
        let typed = Arc::new(BackendStarkVerifyingKey::new(key, serialized_len));
        let bytes: Arc<[u8]> = decompressed.into();
        Ok(Self {
            hash,
            bytes,
            typed,
            metadata,
        })
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let metadata = self.metadata.as_ref();
        let metadata_summary = if metadata.is_empty() {
            "empty".to_string()
        } else {
            let air_fields = metadata.air.as_object().map(|map| map.len()).unwrap_or(0);
            let extra_fields = metadata.extra.len();
            format!("air_fields={air_fields}, extra_fields={extra_fields}")
        };
        f.debug_struct("VerifyingKey")
            .field("hash", &hex::encode(self.hash))
            .field("bytes_len", &self.bytes.len())
            .field("typed_len", &self.typed.len())
            .field("metadata", &metadata_summary)
            .finish()
    }
}

#[derive(Clone)]
pub struct ProvingKey {
    bytes: Arc<[u8]>,
    hash: [u8; 32],
    typed: Arc<BackendStarkProvingKey>,
    metadata: Arc<AirMetadata>,
}

impl ProvingKey {
    pub fn from_bytes(
        bytes: Vec<u8>,
        circuit: &str,
        expected_metadata: Option<&Arc<AirMetadata>>,
    ) -> BackendResult<Self> {
        if bytes.is_empty() {
            return Err(BackendError::MissingProvingKey(circuit.to_string()));
        }
        let compression = KeyCompression::infer(&bytes);
        Self::from_compressed_bytes(bytes, compression, circuit, expected_metadata)
    }

    pub fn from_encoded_parts(
        value: &str,
        encoding: &str,
        compression: Option<&str>,
        circuit: &str,
        expected_metadata: Option<&Arc<AirMetadata>>,
    ) -> BackendResult<Self> {
        let encoded = decode_key_bytes(value, encoding, compression, circuit, "proving key")?;
        let (bytes, compression) = encoded.into_parts();
        Self::from_compressed_bytes(bytes, compression, circuit, expected_metadata)
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    pub fn stark_key(&self) -> &Arc<BackendStarkProvingKey> {
        &self.typed
    }

    pub fn air_metadata(&self) -> &Arc<AirMetadata> {
        &self.metadata
    }

    pub fn typed(&self) -> Arc<BackendStarkProvingKey> {
        Arc::clone(self.stark_key())
    }

    pub fn metadata(&self) -> Arc<AirMetadata> {
        Arc::clone(self.air_metadata())
    }

    pub fn align_metadata(&mut self, shared: &Arc<AirMetadata>) {
        if self.metadata.as_ref() == shared.as_ref() {
            self.metadata = Arc::clone(shared);
        }
    }

    pub fn json_schema() -> Value {
        key_schema(
            "Plonky3 Proving Key",
            "Descriptor for a proving key artifact",
        )
    }

    fn from_compressed_bytes(
        bytes: Vec<u8>,
        compression: KeyCompression,
        circuit: &str,
        expected_metadata: Option<&Arc<AirMetadata>>,
    ) -> BackendResult<Self> {
        let kind = "proving key";
        let hash = *blake3::hash(&bytes).as_bytes();
        let decompressed = compression.decompress_owned(bytes).map_err(|err| {
            invalid_key_error(
                circuit,
                kind,
                format!("failed to decompress {kind} payload: {err}"),
            )
        })?;
        if decompressed.is_empty() {
            return Err(invalid_key_error(
                circuit,
                kind,
                "decompressed payload is empty",
            ));
        }
        let (key, metadata_value) =
            parse_key_payload::<CircuitStarkProvingKey>(&decompressed, circuit, kind)?;
        let metadata = match expected_metadata {
            Some(expected) => {
                if &metadata_value != expected.as_ref() {
                    return Err(invalid_key_error(
                        circuit,
                        kind,
                        "decoded AIR metadata does not match expected fixture metadata",
                    ));
                }
                Arc::clone(expected)
            }
            None => Arc::new(metadata_value),
        };
        let serialized_len = decompressed.len();
        let typed = Arc::new(BackendStarkProvingKey::new(key, serialized_len));
        let bytes: Arc<[u8]> = decompressed.into();
        Ok(Self {
            hash,
            bytes,
            typed,
            metadata,
        })
    }
}

impl fmt::Debug for ProvingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let metadata = self.metadata.as_ref();
        let metadata_summary = if metadata.is_empty() {
            "empty".to_string()
        } else {
            let air_fields = metadata.air.as_object().map(|map| map.len()).unwrap_or(0);
            let extra_fields = metadata.extra.len();
            format!("air_fields={air_fields}, extra_fields={extra_fields}")
        };
        f.debug_struct("ProvingKey")
            .field("hash", &hex::encode(self.hash))
            .field("bytes_len", &self.bytes.len())
            .field("typed_len", &self.typed.len())
            .field("metadata", &metadata_summary)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashFormat {
    PoseidonMerkleCap,
}

impl Default for HashFormat {
    fn default() -> Self {
        Self::PoseidonMerkleCap
    }
}

impl HashFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PoseidonMerkleCap => "poseidon_merkle_cap",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProofMetadata {
    trace_commitment: [u8; 32],
    quotient_commitment: [u8; 32],
    fri_commitment: [u8; 32],
    public_inputs_hash: [u8; 32],
    hash_format: HashFormat,
    security_bits: u32,
    use_gpu: bool,
}

impl ProofMetadata {
    pub fn new(
        trace_commitment: [u8; 32],
        quotient_commitment: [u8; 32],
        fri_commitment: [u8; 32],
        public_inputs_hash: [u8; 32],
        security_bits: u32,
        use_gpu: bool,
    ) -> Self {
        Self::with_hash_format(
            trace_commitment,
            quotient_commitment,
            fri_commitment,
            public_inputs_hash,
            HashFormat::default(),
            security_bits,
            use_gpu,
        )
    }

    pub fn with_hash_format(
        trace_commitment: [u8; 32],
        quotient_commitment: [u8; 32],
        fri_commitment: [u8; 32],
        public_inputs_hash: [u8; 32],
        hash_format: HashFormat,
        security_bits: u32,
        use_gpu: bool,
    ) -> Self {
        Self {
            trace_commitment,
            quotient_commitment,
            fri_commitment,
            public_inputs_hash,
            hash_format,
            security_bits,
            use_gpu,
        }
    }

    pub fn trace_commitment(&self) -> &[u8; 32] {
        &self.trace_commitment
    }

    pub fn quotient_commitment(&self) -> &[u8; 32] {
        &self.quotient_commitment
    }

    pub fn fri_commitment(&self) -> &[u8; 32] {
        &self.fri_commitment
    }

    pub fn public_inputs_hash(&self) -> &[u8; 32] {
        &self.public_inputs_hash
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
                "Hex-encoded transcript commitments and security parameters embedded in a Plonky3 proof payload.".into(),
            ),
        );

        let mut properties = Map::new();
        properties.insert(
            "trace_commitment".into(),
            hex32_schema("Poseidon Merkle cap commitment for the execution trace."),
        );
        properties.insert(
            "quotient_commitment".into(),
            hex32_schema("Poseidon Merkle cap commitment for the quotient domain."),
        );
        properties.insert(
            "fri_commitment".into(),
            hex32_schema("Poseidon Merkle cap commitment representing the FRI transcript."),
        );
        properties.insert(
            "public_inputs_hash".into(),
            hex32_schema("BLAKE3 digest of the encoded public inputs."),
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
                "Digest algorithm used for transcript commitments (header order preserved).",
            ),
        );

        schema.insert("properties".into(), Value::Object(properties));
        schema.insert(
            "required".into(),
            Value::Array(
                [
                    "trace_commitment",
                    "quotient_commitment",
                    "fri_commitment",
                    "public_inputs_hash",
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
    stark_proof: Vec<u8>,
    metadata: ProofMetadata,
}

/// Discrete proof sections used to assemble and disassemble [`Proof`] values.
#[derive(Clone, Debug)]
pub struct ProofParts {
    pub stark_proof: Vec<u8>,
    pub metadata: ProofMetadata,
}

impl ProofParts {
    pub fn new(stark_proof: Vec<u8>, metadata: ProofMetadata) -> Self {
        Self {
            stark_proof,
            metadata,
        }
    }
}

impl Proof {
    pub fn from_parts(circuit: &str, parts: ProofParts) -> BackendResult<Self> {
        let ProofParts {
            stark_proof,
            metadata,
        } = parts;
        let header_len = 3 * COMMITMENT_LEN;
        if stark_proof.len() < header_len {
            return Err(BackendError::InvalidProofLength {
                circuit: circuit.to_string(),
                expected: header_len,
                actual: stark_proof.len(),
            });
        }
        let (trace_segment, rest) = stark_proof.split_at(COMMITMENT_LEN);
        if trace_segment != metadata.trace_commitment() {
            return Err(BackendError::VerifyingKeyMismatch(circuit.to_string()));
        }
        let (quotient_segment, rest) = rest.split_at(COMMITMENT_LEN);
        if quotient_segment != metadata.quotient_commitment() {
            return Err(BackendError::VerifyingKeyMismatch(circuit.to_string()));
        }
        let (fri_segment, _) = rest.split_at(COMMITMENT_LEN);
        if fri_segment != metadata.fri_commitment() {
            return Err(BackendError::FriDigestMismatch(circuit.to_string()));
        }
        Ok(Self {
            stark_proof,
            metadata,
        })
    }

    pub fn stark_proof(&self) -> &[u8] {
        &self.stark_proof
    }

    pub fn metadata(&self) -> &ProofMetadata {
        &self.metadata
    }

    pub fn into_parts(self) -> ProofParts {
        ProofParts::new(self.stark_proof, self.metadata)
    }
}

fn metadata_digest_hex(metadata: &Arc<AirMetadata>) -> Option<String> {
    metadata.digest().map(hex::encode)
}

fn ensure_metadata_alignment<F>(
    expected_label: &str,
    expected: &Arc<AirMetadata>,
    actual_label: &str,
    actual: &Arc<AirMetadata>,
    build_error: F,
) -> BackendResult<()>
where
    F: FnOnce(String) -> BackendError,
{
    if expected.as_ref() == actual.as_ref() {
        return Ok(());
    }

    let expected_digest = metadata_digest_hex(expected).unwrap_or_else(|| "empty".into());
    let actual_digest = metadata_digest_hex(actual).unwrap_or_else(|| "empty".into());
    Err(build_error(format!(
        "{expected_label} metadata digest {expected_digest} does not match {actual_label} metadata digest {actual_digest}",
    )))
}

#[derive(Clone)]
pub struct ProverContext {
    name: String,
    verifying_key: VerifyingKey,
    verifying_metadata: Arc<AirMetadata>,
    proving_key: ProvingKey,
    proving_metadata: Arc<AirMetadata>,
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
        let verifying_metadata = Arc::clone(verifying_key.air_metadata());
        let mut proving_key = proving_key;
        proving_key.align_metadata(&verifying_metadata);
        let proving_metadata = Arc::clone(proving_key.air_metadata());
        ensure_metadata_alignment(
            "verifying key",
            &verifying_metadata,
            "proving key",
            &proving_metadata,
            |message| BackendError::InvalidKeyEncoding {
                circuit: name.clone(),
                kind: "proving key".into(),
                message,
            },
        )?;
        Ok(Self {
            name,
            verifying_key,
            verifying_metadata,
            proving_key,
            proving_metadata,
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

    pub fn verifying_metadata(&self) -> Arc<AirMetadata> {
        Arc::clone(&self.verifying_metadata)
    }

    pub fn proving_metadata(&self) -> Arc<AirMetadata> {
        Arc::clone(&self.proving_metadata)
    }

    pub fn prove(&self, public_inputs: &Value) -> BackendResult<(String, Proof)> {
        let (commitment, encoded_inputs) =
            encode_commitment_and_inputs(self.circuit(), public_inputs)?;
        let proof = self.prove_with_encoded(&commitment, &encoded_inputs)?;
        Ok((commitment, proof))
    }

    fn prove_with_encoded(&self, commitment: &str, encoded_inputs: &[u8]) -> BackendResult<Proof> {
        let inputs_digest = blake3::hash(encoded_inputs);
        let verifying_bytes = self.verifying_key.bytes();
        let header_len = 3 * COMMITMENT_LEN;
        if verifying_bytes.len() < header_len {
            return Err(BackendError::VerifyingKeyMismatch(self.name.clone()));
        }
        let trace_commitment: [u8; 32] = verifying_bytes[..COMMITMENT_LEN]
            .try_into()
            .expect("trace commitment slice length");
        let quotient_commitment: [u8; 32] = verifying_bytes[COMMITMENT_LEN..(2 * COMMITMENT_LEN)]
            .try_into()
            .expect("quotient commitment slice length");
        let fri_commitment: [u8; 32] = verifying_bytes[(2 * COMMITMENT_LEN)..header_len]
            .try_into()
            .expect("fri commitment slice length");

        let metadata = ProofMetadata::new(
            trace_commitment,
            quotient_commitment,
            fri_commitment,
            *inputs_digest.as_bytes(),
            self.security_bits,
            self.use_gpu,
        );

        let mut stark_proof =
            Vec::with_capacity(header_len + commitment.len() + encoded_inputs.len());
        stark_proof.extend_from_slice(metadata.trace_commitment());
        stark_proof.extend_from_slice(metadata.quotient_commitment());
        stark_proof.extend_from_slice(metadata.fri_commitment());
        stark_proof.extend_from_slice(commitment.as_bytes());
        stark_proof.extend_from_slice(encoded_inputs);

        Proof::from_parts(&self.name, ProofParts::new(stark_proof, metadata))
    }

    pub fn verifier(&self) -> VerifierContext {
        VerifierContext {
            name: self.name.clone(),
            verifying_key: self.verifying_key.clone(),
            metadata: self.verifying_metadata(),
            security_bits: self.security_bits,
            use_gpu: self.use_gpu,
        }
    }
}

impl fmt::Debug for ProverContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let metadata = metadata_digest_hex(&self.verifying_metadata);
        f.debug_struct("ProverContext")
            .field("circuit", &self.name)
            .field(
                "verifying_key_hash",
                &hex::encode(self.verifying_key.hash()),
            )
            .field("proving_key_hash", &hex::encode(self.proving_key.hash()))
            .field("metadata_digest", &metadata)
            .field("security_bits", &self.security_bits)
            .field("use_gpu", &self.use_gpu)
            .finish()
    }
}

#[derive(Clone)]
pub struct VerifierContext {
    name: String,
    verifying_key: VerifyingKey,
    metadata: Arc<AirMetadata>,
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
        let metadata = Arc::clone(verifying_key.air_metadata());
        Ok(Self {
            name,
            verifying_key,
            metadata,
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

    pub fn metadata(&self) -> Arc<AirMetadata> {
        Arc::clone(&self.metadata)
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
        if let Some(expected) = &entry.air_metadata {
            ensure_metadata_alignment(
                "signed fixture",
                expected,
                "verifying key",
                &self.metadata,
                |message| BackendError::SetupArtifactMismatch {
                    circuit: self.name.clone(),
                    message,
                },
            )?;
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
        let verifying_bytes = self.verifying_key.bytes();
        let header_len = 3 * COMMITMENT_LEN;
        if verifying_bytes.len() < header_len {
            return Err(BackendError::VerifyingKeyMismatch(self.name.clone()));
        }
        if proof.metadata().trace_commitment() != &verifying_bytes[..COMMITMENT_LEN] {
            return Err(BackendError::VerifyingKeyMismatch(self.name.clone()));
        }
        if proof.metadata().quotient_commitment()
            != &verifying_bytes[COMMITMENT_LEN..(2 * COMMITMENT_LEN)]
        {
            return Err(BackendError::VerifyingKeyMismatch(self.name.clone()));
        }
        if proof.metadata().fri_commitment() != &verifying_bytes[(2 * COMMITMENT_LEN)..header_len] {
            return Err(BackendError::FriDigestMismatch(self.name.clone()));
        }
        let inputs_digest = blake3::hash(encoded_inputs);
        if proof.metadata().public_inputs_hash() != inputs_digest.as_bytes() {
            return Err(BackendError::PublicInputDigestMismatch(self.name.clone()));
        }
        Ok(())
    }
}

impl fmt::Debug for VerifierContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let metadata = metadata_digest_hex(&self.metadata);
        f.debug_struct("VerifierContext")
            .field("circuit", &self.name)
            .field(
                "verifying_key_hash",
                &hex::encode(self.verifying_key.hash()),
            )
            .field("metadata_digest", &metadata)
            .field("security_bits", &self.security_bits)
            .field("use_gpu", &self.use_gpu)
            .finish()
    }
}

fn decode_key_bytes(
    value: &str,
    encoding: &str,
    compression: Option<&str>,
    circuit: &str,
    kind: &str,
) -> BackendResult<EncodedKeyBytes> {
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

    let bytes = match normalized_encoding.as_str() {
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

    let compression = KeyCompression::from_hint(compression.map(|value| value.trim()))
        .map_err(|message| invalid_key_error(circuit, kind, message))?;

    Ok(EncodedKeyBytes::new(bytes, compression))
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
    enum_schema(description, &[HashFormat::PoseidonMerkleCap.as_str()])
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
