use serde::{Deserialize, Serialize};

use crate::types::IdentityGenesis;

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
