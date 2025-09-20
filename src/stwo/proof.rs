//! Common proof artifacts emitted by the STWO scaffolding.

use serde::{Deserialize, Serialize};

use super::circuit::ExecutionTrace;
use super::params::FieldElement;
use super::params::{PoseidonHasher, StarkParameters};

/// Authentication query associated with a polynomial evaluation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriQuery {
    pub index: usize,
    pub evaluation: FieldElement,
    pub auth_path: Vec<FieldElement>,
}

/// Commitment to a single execution-trace column.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolynomialCommitment {
    pub segment: String,
    pub column: String,
    pub domain_size: usize,
    pub merkle_root: FieldElement,
    pub queries: Vec<FriQuery>,
}

/// Deterministic FRI-style proof emitted by the prover scaffold.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriProof {
    pub commitments: Vec<PolynomialCommitment>,
    pub challenges: Vec<FieldElement>,
}

/// Enumeration describing which circuit produced a proof artifact.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofKind {
    Transaction,
    State,
    Pruning,
    Recursive,
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
