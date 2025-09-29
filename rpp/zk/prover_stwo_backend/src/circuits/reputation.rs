use serde::{Deserialize, Serialize};

use crate::core::vcs::blake2_hash::Blake2sHasher;
use crate::params::FieldElement;
use crate::utils::poseidon;

use super::{CircuitTrace, CircuitWitness};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReputationState {
    pub participant: String,
    pub score: u64,
    pub tier: u8,
    pub epochs_participated: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReputationWitness {
    pub state: ReputationState,
    pub timetoken: u64,
    pub adjustment: i64,
}

impl CircuitWitness for ReputationWitness {
    fn label(&self) -> &'static str {
        "reputation"
    }
}

impl ReputationWitness {
    pub fn new(state: ReputationState, timetoken: u64, adjustment: i64) -> Self {
        Self {
            state,
            timetoken,
            adjustment,
        }
    }

    pub fn public_inputs(&self) -> serde_json::Value {
        serde_json::json!({
            "participant": self.state.participant,
            "score": self.state.score,
            "tier": self.state.tier,
            "timetoken": self.timetoken,
        })
    }

    pub fn trace(&self) -> CircuitTrace {
        let poseidon_inputs = vec![
            FieldElement::from_bytes(self.state.participant.as_bytes()),
            FieldElement::from(self.state.score as u128),
            FieldElement::from(self.state.tier as u128),
            FieldElement::from(self.timetoken as u128),
        ];
        let constraint_commitment = poseidon::hash_elements(&poseidon_inputs);

        let mut trace_bytes = Vec::new();
        trace_bytes.extend(self.state.participant.as_bytes());
        trace_bytes.extend(self.state.score.to_be_bytes());
        trace_bytes.extend(self.state.tier.to_be_bytes());
        trace_bytes.extend(self.timetoken.to_be_bytes());
        trace_bytes.extend(self.adjustment.to_be_bytes());
        let trace_commitment = Blake2sHasher::hash(&trace_bytes).0;

        let trace_data = serde_json::json!({
            "state": self.state.clone(),
            "timetoken": self.timetoken,
            "adjustment": self.adjustment,
        });

        CircuitTrace::new(trace_commitment, constraint_commitment, trace_data)
    }
}
