use serde::{Deserialize, Serialize};

use crate::types::{AttestedIdentityRequest, PruningProof, SignedTransaction};

/// Witness capturing the pruning relation between consecutive blocks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningWitness {
    pub previous_identities: Vec<AttestedIdentityRequest>,
    pub previous_transactions: Vec<SignedTransaction>,
    pub pruning_proof: PruningProof,
    pub removed_transactions: Vec<String>,
}

impl PruningWitness {
    pub fn new(
        previous_identities: &[AttestedIdentityRequest],
        previous_transactions: &[SignedTransaction],
        pruning_proof: &PruningProof,
        removed_transactions: Vec<String>,
    ) -> Self {
        Self {
            previous_identities: previous_identities.to_vec(),
            previous_transactions: previous_transactions.to_vec(),
            pruning_proof: pruning_proof.clone(),
            removed_transactions,
        }
    }
}
