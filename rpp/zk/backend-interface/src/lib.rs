use std::fmt;

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

fn canonical_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_little_endian()
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("backend functionality not implemented: {0}")]
    Unsupported(&'static str),
    #[error("backend failure: {0}")]
    Failure(String),
}

pub type BackendResult<T> = Result<T, BackendError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WitnessHeader {
    pub version: u16,
    pub backend: ProofSystemKind,
    pub circuit: String,
}

impl WitnessHeader {
    pub fn new(backend: ProofSystemKind, circuit: impl Into<String>) -> Self {
        Self {
            version: WITNESS_FORMAT_VERSION,
            backend,
            circuit: circuit.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofHeader {
    pub version: u16,
    pub backend: ProofSystemKind,
    pub circuit: String,
}

impl ProofHeader {
    pub fn new(backend: ProofSystemKind, circuit: impl Into<String>) -> Self {
        Self {
            version: PROOF_FORMAT_VERSION,
            backend,
            circuit: circuit.into(),
        }
    }
}

pub const WITNESS_FORMAT_VERSION: u16 = 1;
pub const PROOF_FORMAT_VERSION: u16 = 1;

#[derive(Serialize)]
struct WitnessEnvelope<'a, T> {
    header: &'a WitnessHeader,
    #[serde(borrow)]
    payload: &'a T,
}

#[derive(Deserialize)]
struct WitnessEnvelopeOwned<T> {
    header: WitnessHeader,
    payload: T,
}

#[derive(Serialize)]
struct ProofEnvelope<'a, T> {
    header: &'a ProofHeader,
    #[serde(borrow)]
    payload: &'a T,
}

#[derive(Deserialize)]
struct ProofEnvelopeOwned<T> {
    header: ProofHeader,
    payload: T,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessBytes(pub Vec<u8>);

impl fmt::Debug for WitnessBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WitnessBytes(len={})", self.0.len())
    }
}

impl WitnessBytes {
    pub fn encode<T: Serialize>(header: &WitnessHeader, payload: &T) -> BackendResult<Self> {
        let envelope = WitnessEnvelope { header, payload };
        let bytes = canonical_options()
            .serialize(&envelope)
            .map_err(BackendError::from)?;
        Ok(Self(bytes))
    }

    pub fn decode<T: DeserializeOwned>(&self) -> BackendResult<(WitnessHeader, T)> {
        let envelope: WitnessEnvelopeOwned<T> = canonical_options()
            .deserialize(&self.0)
            .map_err(BackendError::from)?;
        Ok((envelope.header, envelope.payload))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for WitnessBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBytes(pub Vec<u8>);

impl fmt::Debug for ProofBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProofBytes(len={})", self.0.len())
    }
}

impl ProofBytes {
    pub fn encode<T: Serialize>(header: &ProofHeader, payload: &T) -> BackendResult<Self> {
        let envelope = ProofEnvelope { header, payload };
        let bytes = canonical_options()
            .serialize(&envelope)
            .map_err(BackendError::from)?;
        Ok(Self(bytes))
    }

    pub fn decode<T: DeserializeOwned>(&self) -> BackendResult<(ProofHeader, T)> {
        let envelope: ProofEnvelopeOwned<T> = canonical_options()
            .deserialize(&self.0)
            .map_err(BackendError::from)?;
        Ok((envelope.header, envelope.payload))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for ProofBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityLevel {
    Standard128,
    Elevated192,
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Standard128
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxCircuitDef {
    pub identifier: String,
}

impl TxCircuitDef {
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxPublicInputs {
    pub utxo_root: [u8; 32],
    pub transaction_commitment: [u8; 32],
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvingKey(pub Vec<u8>);

impl fmt::Debug for ProvingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProvingKey(len={})", self.0.len())
    }
}

impl ProvingKey {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyingKey(pub Vec<u8>);

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKey(len={})", self.0.len())
    }
}

impl VerifyingKey {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofSystemKind {
    Stwo,
    Mock,
    Plonky3,
    Plonky2,
    Halo2,
}

pub trait ProofBackend: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    fn setup_params(&self, _security: SecurityLevel) -> BackendResult<()> {
        Ok(())
    }

    fn keygen_tx(&self, _circuit: &TxCircuitDef) -> BackendResult<(ProvingKey, VerifyingKey)> {
        Err(BackendError::Unsupported("transaction keygen"))
    }

    fn prove_tx(&self, _pk: &ProvingKey, _witness: &WitnessBytes) -> BackendResult<ProofBytes> {
        Err(BackendError::Unsupported("transaction proving"))
    }

    fn verify_tx(
        &self,
        _vk: &VerifyingKey,
        _proof: &ProofBytes,
        _public_inputs: &TxPublicInputs,
    ) -> BackendResult<bool> {
        Err(BackendError::Unsupported("transaction verification"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct DummyWitness {
        sender: [u8; 32],
        receiver: [u8; 32],
        amount: u64,
    }

    fn sample_witness() -> DummyWitness {
        DummyWitness {
            sender: [0x11; 32],
            receiver: [0x22; 32],
            amount: 42,
        }
    }

    #[test]
    fn witness_roundtrip_is_stable() {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "tx");
        let bytes = WitnessBytes::encode(&header, &sample_witness()).expect("encode witness");
        let (decoded_header, decoded) = bytes.decode::<DummyWitness>().expect("decode witness");
        assert_eq!(decoded_header, header);
        assert_eq!(decoded, sample_witness());
    }

    #[test]
    fn witness_encoding_matches_known_vector() {
        let header = WitnessHeader::new(ProofSystemKind::Stwo, "tx");
        let bytes = WitnessBytes::encode(&header, &sample_witness()).expect("encode witness");
        let encoded = hex::encode(bytes.as_slice());
        assert_eq!(encoded.len(), 176);
        let digest = blake3::hash(bytes.as_slice());
        assert_eq!(
            digest.to_hex().as_str(),
            "87c8c6dfb9cd52ee3366a907bedd206254efb8b75397ee3b0761c6e258f96bde"
        );
    }
}
