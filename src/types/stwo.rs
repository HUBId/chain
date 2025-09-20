use serde::{Deserialize, Serialize};

use crate::stwo::proof::StarkProof;

use super::transaction::SignedTransaction;

/// Bundle tying a signed transaction with its STARK proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionProofBundle {
    pub transaction: SignedTransaction,
    pub proof: StarkProof,
}

impl TransactionProofBundle {
    pub fn new(transaction: SignedTransaction, proof: StarkProof) -> Self {
        Self { transaction, proof }
    }

    pub fn hash(&self) -> String {
        hex::encode(self.transaction.hash())
    }
}

/// Collection of STARK artifacts associated with a block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockStarkProofs {
    pub transaction_proofs: Vec<StarkProof>,
    pub state_proof: StarkProof,
    pub pruning_proof: StarkProof,
    pub recursive_proof: StarkProof,
}

impl BlockStarkProofs {
    pub fn new(
        transaction_proofs: Vec<StarkProof>,
        state_proof: StarkProof,
        pruning_proof: StarkProof,
        recursive_proof: StarkProof,
    ) -> Self {
        Self {
            transaction_proofs,
            state_proof,
            pruning_proof,
            recursive_proof,
        }
    }
}
