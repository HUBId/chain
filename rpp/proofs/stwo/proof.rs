//! Common proof artifacts emitted by the STWO scaffolding.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};

use super::circuit::ExecutionTrace;
use super::params::FieldElement;
use super::params::{PoseidonHasher, StarkParameters};

use stwo::stwo_official::core::fri::FriProof as OfficialFriProof;
use stwo::stwo_official::core::pcs::quotients::CommitmentSchemeProof as OfficialCommitmentSchemeProof;
use stwo::stwo_official::core::vcs::blake2_merkle::Blake2sMerkleHasher;

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

/// Wrapper around the official commitment scheme proof emitted by the prover.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CommitmentSchemeProofData {
    encoded: Vec<u8>,
}

impl CommitmentSchemeProofData {
    pub fn from_official(proof: &OfficialCommitmentSchemeProof<Blake2sMerkleHasher>) -> Self {
        let encoded = bincode::serialize(proof).expect("official commitment proof serialises");
        Self { encoded }
    }

    pub fn to_official(&self) -> Option<OfficialCommitmentSchemeProof<Blake2sMerkleHasher>> {
        if self.encoded.is_empty() {
            None
        } else {
            Some(
                bincode::deserialize(&self.encoded)
                    .expect("official commitment proof deserialises"),
            )
        }
    }
}

impl Serialize for CommitmentSchemeProofData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.encoded))
    }
}

impl<'de> Deserialize<'de> for CommitmentSchemeProofData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = hex::decode(&encoded).map_err(DeError::custom)?;
        Ok(Self { encoded: bytes })
    }
}

/// Deterministic FRI proof emitted by the prover scaffold.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FriProof {
    encoded: Vec<u8>,
}

impl FriProof {
    pub fn from_official(proof: &OfficialFriProof<Blake2sMerkleHasher>) -> Self {
        let encoded = bincode::serialize(proof).expect("official FRI proof serialises");
        Self { encoded }
    }

    pub fn to_official(&self) -> Option<OfficialFriProof<Blake2sMerkleHasher>> {
        if self.encoded.is_empty() {
            None
        } else {
            Some(bincode::deserialize(&self.encoded).expect("official FRI proof deserialises"))
        }
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
    pub commitment_proof: CommitmentSchemeProofData,
    pub fri_proof: FriProof,
}

impl StarkProof {
    /// Build a proof from a payload and the associated public inputs.
    pub fn new(
        kind: ProofKind,
        payload: ProofPayload,
        public_inputs: Vec<FieldElement>,
        trace: ExecutionTrace,
        commitment_proof: CommitmentSchemeProofData,
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
            commitment_proof,
            fri_proof,
        }
    }

    /// Convenience constructor relying on the blueprint default parameters.
    pub fn with_blueprint_hasher(
        kind: ProofKind,
        payload: ProofPayload,
        inputs: Vec<FieldElement>,
        trace: ExecutionTrace,
        commitment_proof: CommitmentSchemeProofData,
        fri_proof: FriProof,
    ) -> Self {
        let params = StarkParameters::blueprint_default();
        let hasher = params.poseidon_hasher();
        Self::new(
            kind,
            payload,
            inputs,
            trace,
            commitment_proof,
            fri_proof,
            &hasher,
        )
    }
}
