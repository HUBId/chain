use serde::{Deserialize, Serialize};

use crate::core::vcs::blake2_hash::Blake2sHasher;
use crate::params::FieldElement;
use crate::utils::{merkle, poseidon};

use super::{CircuitTrace, CircuitWitness};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruningInputs {
    pub utxo_root: String,
    pub reputation_root: String,
    pub previous_proof_digest: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PruningWitness {
    pub inputs: PruningInputs,
    pub leaf_hashes: Vec<[u8; 32]>,
}

impl CircuitWitness for PruningWitness {
    fn label(&self) -> &'static str {
        "pruning"
    }
}

impl PruningWitness {
    pub fn new(inputs: PruningInputs, leaf_hashes: Vec<[u8; 32]>) -> Self {
        Self {
            inputs,
            leaf_hashes,
        }
    }

    pub fn public_inputs(&self) -> serde_json::Value {
        serde_json::json!({
            "utxo_root": self.inputs.utxo_root,
            "reputation_root": self.inputs.reputation_root,
            "previous_digest": hex::encode(self.inputs.previous_proof_digest),
        })
    }

    pub fn trace(&self) -> CircuitTrace {
        let constraint_commitment = poseidon::hash_elements(&[
            FieldElement::from_bytes(self.inputs.utxo_root.as_bytes()),
            FieldElement::from_bytes(self.inputs.reputation_root.as_bytes()),
        ]);

        let merkle_root = merkle::merkle_root(&self.leaf_hashes);
        let mut trace_bytes = Vec::new();
        trace_bytes.extend(self.inputs.utxo_root.as_bytes());
        trace_bytes.extend(self.inputs.reputation_root.as_bytes());
        trace_bytes.extend(self.inputs.previous_proof_digest);
        trace_bytes.extend(merkle_root);
        let trace_commitment = Blake2sHasher::hash(&trace_bytes).0;

        CircuitTrace::new(trace_commitment, constraint_commitment)
    }
}
