//! Common proof artifacts emitted by the STWO scaffolding.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};

use super::circuit::ExecutionTrace;
use super::conversions::{field_bytes, field_to_base, field_to_secure};
use super::params::FieldElement;
use super::params::{PoseidonHasher, StarkParameters};

use stwo::stwo_official::core::fields::qm31::SecureField;
use stwo::stwo_official::core::fri::FriProof as OfficialFriProof;
use stwo::stwo_official::core::poly::line::LinePoly;
use stwo::stwo_official::core::vcs::blake2_hash::{
    Blake2sHash as OfficialBlake2sHash, Blake2sHasher as OfficialBlake2sHasher,
};
use stwo::stwo_official::core::vcs::blake2_merkle::Blake2sMerkleHasher;
use stwo::stwo_official::core::vcs::verifier::MerkleDecommitment;

/// Wrapper around the official `Queries` structure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FriQuery {
    pub log_domain_size: u32,
    pub positions: Vec<usize>,
}

impl FriQuery {
    pub fn new(log_domain_size: u32, positions: Vec<usize>) -> Self {
        Self {
            log_domain_size,
            positions,
        }
    }
}

/// Deterministic FRI-style proof emitted by the prover scaffold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FriProof {
    encoded: Vec<u8>,
}

impl FriProof {
    pub fn empty() -> Self {
        Self::from_elements(&[])
    }

    pub fn from_official(proof: &OfficialFriProof<Blake2sMerkleHasher>) -> Self {
        let encoded = serde_json::to_vec(proof).expect("official FRI proof serialises");
        Self { encoded }
    }

    pub fn to_official(&self) -> OfficialFriProof<Blake2sMerkleHasher> {
        serde_json::from_slice(&self.encoded).expect("official FRI proof deserialises")
    }

    pub fn from_elements(values: &[FieldElement]) -> Self {
        let proof = placeholder_proof(values);
        Self::from_official(&proof)
    }
}

impl Serialize for FriProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.encoded))
    }
}

impl<'de> Deserialize<'de> for FriProof {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = hex::decode(&encoded).map_err(DeError::custom)?;
        Ok(Self { encoded: bytes })
    }
}

fn placeholder_proof(values: &[FieldElement]) -> OfficialFriProof<Blake2sMerkleHasher> {
    let first_layer = stwo::stwo_official::core::fri::FriLayerProof {
        fri_witness: values.iter().map(field_to_secure).collect(),
        decommitment: MerkleDecommitment {
            hash_witness: Vec::new(),
            column_witness: values.iter().map(field_to_base).collect(),
        },
        commitment: digest_elements(values),
    };

    let sum_secure = sum_values(values)
        .map(|value| field_to_secure(&value))
        .unwrap_or_else(|| SecureField::from(0u32));
    let len_secure = SecureField::from(values.len() as u32);
    let last_layer_poly = LinePoly::new(vec![sum_secure, len_secure]);

    OfficialFriProof {
        first_layer,
        inner_layers: Vec::new(),
        last_layer_poly,
    }
}

fn digest_elements(values: &[FieldElement]) -> OfficialBlake2sHash {
    let mut buffer = Vec::new();
    for value in values {
        buffer.extend_from_slice(&field_bytes(value));
    }
    OfficialBlake2sHasher::hash(&buffer)
}

fn sum_values(values: &[FieldElement]) -> Option<FieldElement> {
    let mut iter = values.iter();
    let mut acc = iter.next()?.clone();
    for value in iter {
        acc = acc.add(value).expect("field moduli match");
    }
    Some(acc)
}

/// Enumeration describing which circuit produced a proof artifact.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofKind {
    Transaction,
    State,
    Pruning,
    Recursive,
    Identity,
    Uptime,
    Consensus,
}

/// Serialized witness payloads embedded in placeholder proofs. In a production
/// STARK this data would be committed to rather than stored verbatim, but for
/// the blueprint scaffold we keep it around so verifiers can re-execute the
/// constraints deterministically.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProofPayload {
    Transaction(super::circuit::transaction::TransactionWitness),
    State(super::circuit::state::StateWitness),
    Pruning(super::circuit::pruning::PruningWitness),
    Recursive(super::circuit::recursive::RecursiveWitness),
    Identity(super::circuit::identity::IdentityWitness),
    Uptime(super::circuit::uptime::UptimeWitness),
    Consensus(super::circuit::consensus::ConsensusWitness),
}

/// High-level container describing a STARK-style proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkProof {
    pub kind: ProofKind,
    pub commitment: String,
    pub public_inputs: Vec<String>,
    pub payload: ProofPayload,
    pub trace: ExecutionTrace,
    pub fri_proof: FriProof,
}

impl StarkProof {
    /// Build a proof from a payload and the associated public inputs.
    pub fn new(
        kind: ProofKind,
        payload: ProofPayload,
        public_inputs: Vec<FieldElement>,
        trace: ExecutionTrace,
        fri_proof: FriProof,
        hasher: &PoseidonHasher,
    ) -> Self {
        let commitment_element = hasher.hash(&public_inputs);
        let commitment = commitment_element.to_hex();
        let public_inputs = public_inputs
            .into_iter()
            .map(|element| element.to_hex())
            .collect();
        Self {
            kind,
            commitment,
            public_inputs,
            payload,
            trace,
            fri_proof,
        }
    }

    /// Convenience constructor relying on the blueprint default parameters.
    pub fn with_blueprint_hasher(
        kind: ProofKind,
        payload: ProofPayload,
        inputs: Vec<FieldElement>,
        trace: ExecutionTrace,
        fri_proof: FriProof,
    ) -> Self {
        let params = StarkParameters::blueprint_default();
        let hasher = params.poseidon_hasher();
        Self::new(kind, payload, inputs, trace, fri_proof, &hasher)
    }
}
