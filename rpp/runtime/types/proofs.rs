use serde::{Deserialize, Serialize};

#[cfg(feature = "backend-plonky3")]
use crate::errors::ChainError;
use crate::errors::ChainResult;
use crate::rpp::ProofSystemKind;
use crate::stwo::proof::StarkProof;

use super::transaction::SignedTransaction;

/// Unified proof representation that captures the originating backend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChainProof {
    #[serde(rename = "stwo")]
    Stwo(StarkProof),
    #[cfg(feature = "backend-plonky3")]
    #[serde(rename = "plonky3")]
    Plonky3(serde_json::Value),
}

impl ChainProof {
    /// Return the proof system that produced the artifact.
    pub fn system(&self) -> ProofSystemKind {
        match self {
            ChainProof::Stwo(_) => ProofSystemKind::Stwo,
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => ProofSystemKind::Plonky3,
        }
    }

    /// Borrow the underlying STWO proof, returning an error if the backend mismatches.
    pub fn expect_stwo(&self) -> ChainResult<&StarkProof> {
        match self {
            ChainProof::Stwo(proof) => Ok(proof),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => Err(ChainError::Crypto(
                "expected STWO proof, received PLONKY3 artifact".into(),
            )),
        }
    }

    /// Consume the proof and yield the contained STWO artifact if present.
    pub fn into_stwo(self) -> ChainResult<StarkProof> {
        match self {
            ChainProof::Stwo(proof) => Ok(proof),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => Err(ChainError::Crypto(
                "expected STWO proof, received PLONKY3 artifact".into(),
            )),
        }
    }
}

/// Bundle tying a signed transaction with its proof artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionProofBundle {
    pub transaction: SignedTransaction,
    pub proof: ChainProof,
}

impl TransactionProofBundle {
    pub fn new(transaction: SignedTransaction, proof: ChainProof) -> Self {
        Self { transaction, proof }
    }

    pub fn hash(&self) -> String {
        hex::encode(self.transaction.hash())
    }
}

/// Collection of proof artifacts associated with a block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockProofBundle {
    pub transaction_proofs: Vec<ChainProof>,
    pub state_proof: ChainProof,
    pub pruning_proof: ChainProof,
    pub recursive_proof: ChainProof,
}

impl BlockProofBundle {
    pub fn new(
        transaction_proofs: Vec<ChainProof>,
        state_proof: ChainProof,
        pruning_proof: ChainProof,
        recursive_proof: ChainProof,
    ) -> Self {
        Self {
            transaction_proofs,
            state_proof,
            pruning_proof,
            recursive_proof,
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "backend-plonky3")]
    mod plonky3 {
        use super::super::{ChainProof, ProofSystemKind};
        use crate::errors::ChainError;

        #[test]
        fn chain_proof_reports_backend() {
            let proof = ChainProof::Plonky3(serde_json::json!({"commitment": "abc"}));
            assert_eq!(proof.system(), ProofSystemKind::Plonky3);
            assert!(matches!(proof.expect_stwo(), Err(ChainError::Crypto(_))));
            assert!(matches!(
                proof.clone().into_stwo(),
                Err(ChainError::Crypto(_))
            ));
        }
    }
}
