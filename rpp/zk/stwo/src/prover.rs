use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::circuits::identity::{IdentityGenesis, IdentityWitness};
use crate::circuits::pruning::{PruningInputs, PruningWitness};
use crate::circuits::reputation::{ReputationState, ReputationWitness};
use crate::circuits::transaction::{Transaction, TransactionWitness, UtxoState};
use crate::circuits::{CircuitTrace, CircuitWitness};
use crate::params::FieldElement;
use crate::recursion::RecursiveProof;
use crate::utils::fri::{FriProof, FriProver};
use crate::utils::poseidon;

/// Supported proof encodings.  The prover currently emits JSON by default but
/// the enum leaves space for a binary format when needed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofFormat {
    Json(serde_json::Value),
    Binary(Vec<u8>),
}

/// Enumeration of circuits handled by the prover.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofCircuit {
    Transaction,
    Reputation,
    Block,
    Identity,
}

/// Lightweight proof representation used by the local prover.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proof {
    pub circuit: ProofCircuit,
    pub payload: ProofFormat,
    pub commitment: [u8; 32],
    pub public_inputs: Vec<FieldElement>,
    pub trace: CircuitTrace,
    pub fri_proof: FriProof,
}

impl Proof {
    pub fn digest(&self) -> [u8; 32] {
        let encoded = serde_json::to_vec(self).expect("proof is serialisable");
        poseidon::hash_elements(&[
            FieldElement::from_bytes(&encoded[..encoded.len().min(16)]),
            FieldElement::from_bytes(&encoded[encoded.len().saturating_sub(16)..]),
        ])
    }
}

/// Helper trait implemented by all witness types so that the prover can derive
/// field elements for the simplified FRI commitment.
trait WitnessExt: CircuitWitness {
    fn trace_commitments(&self) -> CircuitTrace;

    fn public_input_elements(&self) -> Vec<FieldElement>;

    fn payload(&self) -> ProofFormat {
        ProofFormat::Json(self.to_json())
    }

    fn fri_values(&self, trace: &CircuitTrace) -> Vec<FieldElement> {
        let mut values = self.public_input_elements();
        values.extend(commitment_elements(&trace.trace_commitment));
        values.extend(commitment_elements(&trace.constraint_commitment));
        values
    }
}

impl WitnessExt for TransactionWitness {
    fn trace_commitments(&self) -> CircuitTrace {
        self.trace()
    }

    fn public_input_elements(&self) -> Vec<FieldElement> {
        vec![
            FieldElement::from_bytes(self.tx.tx_id.as_bytes()),
            FieldElement::from_bytes(self.state.root.as_bytes()),
            FieldElement::from(self.tx.tier as u128),
            FieldElement::from(self.balance_sum),
        ]
    }
}

impl WitnessExt for ReputationWitness {
    fn trace_commitments(&self) -> CircuitTrace {
        self.trace()
    }

    fn public_input_elements(&self) -> Vec<FieldElement> {
        vec![
            FieldElement::from_bytes(self.state.participant.as_bytes()),
            FieldElement::from(self.state.score as u128),
            FieldElement::from(self.state.tier as u128),
            FieldElement::from(self.timetoken as u128),
        ]
    }
}

impl WitnessExt for IdentityWitness {
    fn trace_commitments(&self) -> CircuitTrace {
        self.trace()
    }

    fn public_input_elements(&self) -> Vec<FieldElement> {
        vec![
            FieldElement::from_bytes(self.genesis.wallet_address.as_bytes()),
            FieldElement::from_bytes(self.genesis.genesis_block.as_bytes()),
        ]
    }
}

impl WitnessExt for PruningWitness {
    fn trace_commitments(&self) -> CircuitTrace {
        self.trace()
    }

    fn public_input_elements(&self) -> Vec<FieldElement> {
        vec![
            FieldElement::from_bytes(self.inputs.utxo_root.as_bytes()),
            FieldElement::from_bytes(self.inputs.reputation_root.as_bytes()),
            FieldElement::from_bytes(&self.inputs.previous_proof_digest[..16]),
            FieldElement::from_bytes(&self.inputs.previous_proof_digest[16..]),
        ]
    }
}

fn commitment_elements(commitment: &[u8; 32]) -> [FieldElement; 2] {
    [
        FieldElement::from_bytes(&commitment[..16]),
        FieldElement::from_bytes(&commitment[16..]),
    ]
}

fn build_proof<W>(circuit: ProofCircuit, witness: &W) -> Proof
where
    W: WitnessExt,
{
    let trace = witness.trace_commitments();
    let public_inputs = witness.public_input_elements();
    let fri_inputs = witness.fri_values(&trace);
    let fri_proof = FriProver::prove(&fri_inputs);
    let commitment = poseidon::hash_elements(&public_inputs);

    Proof {
        circuit,
        payload: witness.payload(),
        commitment,
        public_inputs,
        trace,
        fri_proof,
    }
}

/// Generate a transaction proof.
pub fn prove_tx(tx: &Transaction, state: &UtxoState) -> Proof {
    let witness = TransactionWitness::new(tx.clone(), state.clone());
    build_proof(ProofCircuit::Transaction, &witness)
}

/// Generate a reputation proof.
pub fn prove_reputation(state: &ReputationState) -> Proof {
    let witness = ReputationWitness::new(state.clone(), state.epochs_participated, 0);
    build_proof(ProofCircuit::Reputation, &witness)
}

/// Generate a block proof by linking it with the previous recursive digest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Block {
    pub height: u64,
    pub tx_root: String,
    pub reputation_root: String,
}

pub fn prove_block(block: &Block, prev_proof: &Proof) -> Proof {
    let inputs = PruningInputs {
        utxo_root: block.tx_root.clone(),
        reputation_root: block.reputation_root.clone(),
        previous_proof_digest: prev_proof.digest(),
    };
    let leaves = vec![
        prev_proof.digest(),
        poseidon::hash_elements(&[
            FieldElement::from(block.height as u128),
            FieldElement::from_bytes(block.tx_root.as_bytes()),
        ]),
    ];
    let witness = PruningWitness::new(inputs, leaves);
    build_proof(ProofCircuit::Block, &witness)
}

/// Produce an identity proof for the wallet genesis procedure.
pub fn prove_identity(wallet_key: &str, genesis: &IdentityGenesis) -> Proof {
    let witness = IdentityWitness::new(genesis.clone(), wallet_key.to_owned(), "vote".into());
    build_proof(ProofCircuit::Identity, &witness)
}

/// Convenience helper to export proofs into a recursive wrapper.
pub fn to_recursive_proof(proof: &Proof) -> RecursiveProof {
    RecursiveProof {
        aggregate_digest: proof.digest(),
        proof: proof.clone(),
    }
}

impl ProofFormat {
    pub(crate) fn decode_json<T: DeserializeOwned>(&self) -> Option<T> {
        match self {
            ProofFormat::Json(value) => serde_json::from_value(value.clone()).ok(),
            ProofFormat::Binary(bytes) => serde_json::from_slice(bytes).ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::identity::IdentityGenesis;
    use crate::circuits::reputation::ReputationState;
    use crate::circuits::transaction::{Transaction, UtxoState};
    use crate::verifier::{
        verify_block, verify_identity, verify_reputation, verify_tx, VerificationError,
    };

    fn sample_transaction() -> (Transaction, UtxoState) {
        let tx = Transaction {
            tx_id: "tx-001".into(),
            inputs: vec!["input-a".into()],
            outputs: vec!["output-b".into()],
            tier: 2,
        };
        let state = UtxoState {
            root: "root-1234".into(),
            height: 7,
        };
        (tx, state)
    }

    fn sample_reputation() -> ReputationState {
        ReputationState {
            participant: "alice".into(),
            score: 42,
            tier: 3,
            epochs_participated: 11,
        }
    }

    fn sample_identity() -> (String, IdentityGenesis) {
        let genesis = IdentityGenesis {
            wallet_address: "wallet-xyz".into(),
            genesis_block: "block-1".into(),
        };
        ("wallet-pk".into(), genesis)
    }

    fn sample_block() -> Block {
        Block {
            height: 9,
            tx_root: "tx-root".into(),
            reputation_root: "rep-root".into(),
        }
    }

    #[test]
    fn transaction_roundtrip() {
        let (tx, state) = sample_transaction();
        let proof = prove_tx(&tx, &state);
        assert!(verify_tx(&tx, &proof).is_ok());
    }

    #[test]
    fn reputation_roundtrip() {
        let state = sample_reputation();
        let proof = prove_reputation(&state);
        assert!(verify_reputation(&state, &proof).is_ok());
    }

    #[test]
    fn identity_roundtrip() {
        let (wallet_key, genesis) = sample_identity();
        let proof = prove_identity(&wallet_key, &genesis);
        assert!(verify_identity(&genesis, &proof).is_ok());
    }

    #[test]
    fn block_roundtrip() {
        let (wallet_key, genesis) = sample_identity();
        let prev_proof = prove_identity(&wallet_key, &genesis);
        let block = sample_block();
        let proof = prove_block(&block, &prev_proof);
        assert!(verify_block(&block, &proof).is_ok());
    }

    #[test]
    fn transaction_witness_mismatch() {
        let (tx, state) = sample_transaction();
        let mut other_tx = tx.clone();
        other_tx.tx_id = "tx-002".into();
        let proof = prove_tx(&tx, &state);
        let err = verify_tx(&other_tx, &proof).expect_err("witness mismatch");
        assert_eq!(
            err,
            VerificationError::WitnessMismatch("transaction payload")
        );
    }

    #[test]
    fn tampered_commitment_fails() {
        let (tx, state) = sample_transaction();
        let proof = prove_tx(&tx, &state);
        let mut tampered = proof.clone();
        tampered.commitment[0] ^= 0x01;
        let err = verify_tx(&tx, &tampered).expect_err("commitment mismatch");
        assert_eq!(err, VerificationError::CommitmentMismatch);
    }
}
