use serde::{Deserialize, Serialize};

use crate::errors::{ChainError, ChainResult};
use crate::proof_backend::TxPublicInputs;
use crate::rpp::ProofSystemKind;
use crate::stwo::circuit::transaction::TransactionWitness;
use crate::stwo::proof::{ProofPayload, StarkProof};

use super::transaction::SignedTransaction;

#[cfg(feature = "backend-rpp-stark")]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RppStarkProof {
    pub params: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub proof: Vec<u8>,
}

#[cfg(feature = "backend-rpp-stark")]
impl RppStarkProof {
    pub fn new(params: Vec<u8>, public_inputs: Vec<u8>, proof: Vec<u8>) -> Self {
        Self {
            params,
            public_inputs,
            proof,
        }
    }

    pub fn params(&self) -> &[u8] {
        &self.params
    }

    pub fn public_inputs(&self) -> &[u8] {
        &self.public_inputs
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }

    pub fn params_len(&self) -> usize {
        self.params.len()
    }

    pub fn public_inputs_len(&self) -> usize {
        self.public_inputs.len()
    }

    pub fn proof_len(&self) -> usize {
        self.proof.len()
    }

    pub fn total_len(&self) -> usize {
        self.params_len() + self.public_inputs_len() + self.proof_len()
    }
}

/// Unified proof representation that captures the originating backend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ChainProof {
    #[serde(rename = "stwo")]
    Stwo(StarkProof),
    #[cfg(feature = "backend-plonky3")]
    #[serde(rename = "plonky3")]
    Plonky3(serde_json::Value),
    #[cfg(feature = "backend-rpp-stark")]
    #[serde(rename = "rpp-stark")]
    RppStark(RppStarkProof),
}

impl ChainProof {
    /// Return the proof system that produced the artifact.
    pub fn system(&self) -> ProofSystemKind {
        match self {
            ChainProof::Stwo(_) => ProofSystemKind::Stwo,
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => ProofSystemKind::Plonky3,
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => ProofSystemKind::RppStark,
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
            #[cfg(all(feature = "backend-rpp-stark", not(feature = "backend-plonky3")))]
            ChainProof::RppStark(_) => Err(ChainError::Crypto(
                "expected STWO proof, received RPP-STARK artifact".into(),
            )),
            #[cfg(all(feature = "backend-plonky3", feature = "backend-rpp-stark"))]
            ChainProof::RppStark(_) => Err(ChainError::Crypto(
                "expected STWO proof, received RPP-STARK artifact".into(),
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
            #[cfg(all(feature = "backend-rpp-stark", not(feature = "backend-plonky3")))]
            ChainProof::RppStark(_) => Err(ChainError::Crypto(
                "expected STWO proof, received RPP-STARK artifact".into(),
            )),
            #[cfg(all(feature = "backend-plonky3", feature = "backend-rpp-stark"))]
            ChainProof::RppStark(_) => Err(ChainError::Crypto(
                "expected STWO proof, received RPP-STARK artifact".into(),
            )),
        }
    }

    /// Borrow the underlying RPP-STARK proof, returning an error if a different backend was used.
    #[cfg(feature = "backend-rpp-stark")]
    pub fn expect_rpp_stark(&self) -> ChainResult<&RppStarkProof> {
        match self {
            ChainProof::RppStark(proof) => Ok(proof),
            ChainProof::Stwo(_) => Err(ChainError::Crypto(
                "expected RPP-STARK proof, received STWO artifact".into(),
            )),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => Err(ChainError::Crypto(
                "expected RPP-STARK proof, received PLONKY3 artifact".into(),
            )),
        }
    }

    /// Consume the proof and yield the contained RPP-STARK artifact if present.
    #[cfg(feature = "backend-rpp-stark")]
    pub fn into_rpp_stark(self) -> ChainResult<RppStarkProof> {
        match self {
            ChainProof::RppStark(proof) => Ok(proof),
            ChainProof::Stwo(_) => Err(ChainError::Crypto(
                "expected RPP-STARK proof, received STWO artifact".into(),
            )),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => Err(ChainError::Crypto(
                "expected RPP-STARK proof, received PLONKY3 artifact".into(),
            )),
        }
    }
}

/// Bundle tying a signed transaction with its proof artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionProofBundle {
    pub transaction: SignedTransaction,
    pub proof: ChainProof,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<TransactionWitness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_payload: Option<ProofPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stwo_proof_bytes: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stwo_public_inputs: Option<TxPublicInputs>,
}

impl TransactionProofBundle {
    pub fn new(
        transaction: SignedTransaction,
        proof: ChainProof,
        witness: Option<TransactionWitness>,
        proof_payload: Option<ProofPayload>,
    ) -> Self {
        Self {
            transaction,
            proof,
            witness,
            proof_payload,
            stwo_proof_bytes: None,
            stwo_public_inputs: None,
        }
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
    mod stwo {
        use super::super::ChainProof;
        use crate::stwo::circuit::ExecutionTrace;
        use crate::stwo::circuit::recursive::RecursiveWitness;
        use crate::stwo::proof::{
            CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
        };

        fn sample_stwo_proof() -> StarkProof {
            let witness = RecursiveWitness {
                previous_commitment: Some("aa".repeat(32)),
                aggregated_commitment: "bb".repeat(32),
                identity_commitments: vec!["cc".repeat(32)],
                tx_commitments: vec!["dd".repeat(32)],
                uptime_commitments: vec!["ee".repeat(32)],
                consensus_commitments: vec!["ff".repeat(32)],
                state_commitment: "11".repeat(32),
                global_state_root: "22".repeat(32),
                utxo_root: "33".repeat(32),
                reputation_root: "44".repeat(32),
                timetoke_root: "55".repeat(32),
                zsi_root: "66".repeat(32),
                proof_root: "77".repeat(32),
                pruning_commitment: "88".repeat(32),
                block_height: 1,
            };
            StarkProof {
                kind: ProofKind::Recursive,
                commitment: "99".repeat(32),
                public_inputs: vec!["aa".repeat(32)],
                payload: ProofPayload::Recursive(witness),
                trace: ExecutionTrace {
                    segments: Vec::new(),
                },
                commitment_proof: CommitmentSchemeProofData::default(),
                fri_proof: FriProof::default(),
            }
        }

        #[test]
        fn json_roundtrip_preserves_stwo_proof() {
            let proof = ChainProof::Stwo(sample_stwo_proof());
            let json = serde_json::to_string(&proof).expect("serialize chain proof");
            let decoded: ChainProof = serde_json::from_str(&json).expect("deserialize chain proof");
            let original = serde_json::to_value(&proof).expect("encode original");
            let recovered = serde_json::to_value(&decoded).expect("encode decoded");
            assert_eq!(recovered, original);
        }

        #[test]
        fn binary_roundtrip_preserves_stwo_proof() {
            let proof = ChainProof::Stwo(sample_stwo_proof());
            let bytes = bincode::serialize(&proof).expect("serialize chain proof");
            let decoded: ChainProof =
                bincode::deserialize(&bytes).expect("deserialize chain proof");
            let original = serde_json::to_value(&proof).expect("encode original");
            let recovered = serde_json::to_value(&decoded).expect("encode decoded");
            assert_eq!(recovered, original);
        }
    }

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

    #[cfg(feature = "backend-rpp-stark")]
    mod rpp_stark {
        use super::super::{ChainProof, ProofSystemKind, RppStarkProof};

        fn sample_proof() -> RppStarkProof {
            RppStarkProof::new(vec![1, 2, 3], vec![4, 5], vec![6, 7, 8, 9])
        }

        #[test]
        fn chain_proof_reports_backend() {
            let proof = ChainProof::RppStark(sample_proof());
            assert_eq!(proof.system(), ProofSystemKind::RppStark);
            let view = proof.expect_rpp_stark().expect("rpp-stark proof");
            assert_eq!(view.params(), &[1, 2, 3]);
            assert_eq!(view.public_inputs(), &[4, 5]);
            assert_eq!(view.proof(), &[6, 7, 8, 9]);
            assert_eq!(view.total_len(), 9);
        }

        #[test]
        fn json_roundtrip_preserves_rpp_stark_proof() {
            let proof = ChainProof::RppStark(sample_proof());
            let json = serde_json::to_string(&proof).expect("serialize chain proof");
            let decoded: ChainProof = serde_json::from_str(&json).expect("deserialize chain proof");
            assert_eq!(decoded.system(), ProofSystemKind::RppStark);
            assert_eq!(decoded.expect_rpp_stark().unwrap().total_len(), 9);
        }

        #[test]
        fn binary_roundtrip_preserves_rpp_stark_proof() {
            let proof = ChainProof::RppStark(sample_proof());
            let bytes = bincode::serialize(&proof).expect("serialize chain proof");
            let decoded: ChainProof =
                bincode::deserialize(&bytes).expect("deserialize chain proof");
            assert_eq!(decoded.system(), ProofSystemKind::RppStark);
            assert_eq!(decoded.expect_rpp_stark().unwrap().total_len(), 9);
        }
    }
}
