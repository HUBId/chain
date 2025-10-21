use serde::{Deserialize, Serialize};

use crate::types::{AttestedIdentityRequest, SignedTransaction};

use super::Plonky3CircuitWitness;

/// Witness for the batched state transition circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateWitness {
    pub prev_state_root: String,
    pub new_state_root: String,
    pub identities: Vec<AttestedIdentityRequest>,
    pub transactions: Vec<SignedTransaction>,
}

impl StateWitness {
    pub fn new(
        prev_state_root: &str,
        new_state_root: &str,
        identities: &[AttestedIdentityRequest],
        transactions: &[SignedTransaction],
    ) -> Self {
        Self {
            prev_state_root: prev_state_root.to_string(),
            new_state_root: new_state_root.to_string(),
            identities: identities.to_vec(),
            transactions: transactions.to_vec(),
        }
    }
}

impl Plonky3CircuitWitness for StateWitness {
    fn circuit(&self) -> &'static str {
        "state"
    }
}
