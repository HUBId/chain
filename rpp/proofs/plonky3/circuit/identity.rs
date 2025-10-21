use serde::{Deserialize, Serialize};

use crate::types::IdentityGenesis;

use super::Plonky3CircuitWitness;

/// Witness representation for the identity genesis circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityWitness {
    pub genesis: IdentityGenesis,
}

impl IdentityWitness {
    pub fn new(genesis: &IdentityGenesis) -> Self {
        Self {
            genesis: genesis.clone(),
        }
    }
}

impl Plonky3CircuitWitness for IdentityWitness {
    fn circuit(&self) -> &'static str {
        "identity"
    }
}
