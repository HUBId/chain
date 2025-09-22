use serde::{Deserialize, Serialize};

use crate::core::vcs::blake2_hash::Blake2sHasher;
use crate::params::FieldElement;
use crate::utils::poseidon;

use super::{CircuitTrace, CircuitWitness};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityGenesis {
    pub wallet_address: String,
    pub genesis_block: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityWitness {
    pub genesis: IdentityGenesis,
    pub wallet_public_key: String,
    pub vote_signature: String,
}

impl CircuitWitness for IdentityWitness {
    fn label(&self) -> &'static str {
        "identity"
    }
}

impl IdentityWitness {
    pub fn new(genesis: IdentityGenesis, wallet_public_key: String, vote_signature: String) -> Self {
        Self {
            genesis,
            wallet_public_key,
            vote_signature,
        }
    }

    pub fn public_inputs(&self) -> serde_json::Value {
        serde_json::json!({
            "wallet": self.genesis.wallet_address,
            "genesis": self.genesis.genesis_block,
        })
    }

    pub fn trace(&self) -> CircuitTrace {
        let poseidon_inputs = vec![
            FieldElement::from_bytes(self.genesis.wallet_address.as_bytes()),
            FieldElement::from_bytes(self.wallet_public_key.as_bytes()),
        ];
        let constraint_commitment = poseidon::hash_elements(&poseidon_inputs);

        let mut trace_bytes = Vec::new();
        trace_bytes.extend(self.genesis.wallet_address.as_bytes());
        trace_bytes.extend(self.genesis.genesis_block.as_bytes());
        trace_bytes.extend(self.wallet_public_key.as_bytes());
        trace_bytes.extend(self.vote_signature.as_bytes());
        let trace_commitment = Blake2sHasher::hash(&trace_bytes).0;

        CircuitTrace::new(trace_commitment, constraint_commitment)
    }
}
