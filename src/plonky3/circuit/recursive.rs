use serde::{Deserialize, Serialize};

use crate::rpp::GlobalStateCommitments;
use crate::types::ChainProof;

/// Witness structure for recursive aggregation in the Plonky3 backend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveWitness {
    pub previous_recursive: Option<ChainProof>,
    pub identity_proofs: Vec<ChainProof>,
    pub transaction_proofs: Vec<ChainProof>,
    pub uptime_proofs: Vec<ChainProof>,
    pub consensus_proofs: Vec<ChainProof>,
    pub state_commitments: GlobalStateCommitments,
    pub state_proof: ChainProof,
    pub pruning_proof: ChainProof,
    pub block_height: u64,
}

impl RecursiveWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        previous_recursive: Option<ChainProof>,
        identity_proofs: &[ChainProof],
        transaction_proofs: &[ChainProof],
        uptime_proofs: &[ChainProof],
        consensus_proofs: &[ChainProof],
        state_commitments: &GlobalStateCommitments,
        state_proof: &ChainProof,
        pruning_proof: &ChainProof,
        block_height: u64,
    ) -> Self {
        Self {
            previous_recursive,
            identity_proofs: identity_proofs.to_vec(),
            transaction_proofs: transaction_proofs.to_vec(),
            uptime_proofs: uptime_proofs.to_vec(),
            consensus_proofs: consensus_proofs.to_vec(),
            state_commitments: *state_commitments,
            state_proof: state_proof.clone(),
            pruning_proof: pruning_proof.clone(),
            block_height,
        }
    }
}
