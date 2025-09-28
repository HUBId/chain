use serde::{Deserialize, Serialize};

use crate::circuits::identity::{IdentityGenesis, IdentityWitness};
use crate::circuits::pruning::{PruningInputs, PruningWitness};
use crate::circuits::reputation::{ReputationState, ReputationWitness};
use crate::circuits::transaction::{Transaction, TransactionWitness, UtxoState};
use crate::circuits::{CircuitTrace, CircuitWitness};
use crate::params::{FieldElement, StwoConfig};
use crate::recursion::RecursiveProof;
use crate::utils::fri::{FriProof, FriProver};
use crate::utils::poseidon;

/// Supported proof encodings.  The prover currently emits JSON by default but
/// the enum leaves space for a binary format when needed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofFormat {
    Json,
    Binary,
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
    pub format: ProofFormat,
    pub config: StwoConfig,
    pub public_inputs: serde_json::Value,
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

    fn fri_values(&self) -> Vec<FieldElement> {
        let trace = self.trace_commitments();
        let mut values = Vec::new();
        values.push(FieldElement::from_bytes(&trace.trace_commitment[..16]));
        values.push(FieldElement::from_bytes(&trace.trace_commitment[16..]));
        values.push(FieldElement::from_bytes(&trace.constraint_commitment[..16]));
        values.push(FieldElement::from_bytes(&trace.constraint_commitment[16..]));
        values
    }
}

impl WitnessExt for TransactionWitness {
    fn trace_commitments(&self) -> CircuitTrace {
        self.trace()
    }
}

impl WitnessExt for ReputationWitness {
    fn trace_commitments(&self) -> CircuitTrace {
        self.trace()
    }
}

impl WitnessExt for IdentityWitness {
    fn trace_commitments(&self) -> CircuitTrace {
        self.trace()
    }
}

impl WitnessExt for PruningWitness {
    fn trace_commitments(&self) -> CircuitTrace {
        self.trace()
    }
}

fn build_proof<W>(circuit: ProofCircuit, witness: &W) -> Proof
where
    W: WitnessExt,
{
    let config = StwoConfig::default();
    let public_inputs = witness.to_json();
    let trace = witness.trace_commitments();
    let fri_values = witness.fri_values();
    let fri_proof = FriProver::prove(&fri_values, &config)
        .expect("fri prover should generate a proof for the witness");

    Proof {
        circuit,
        format: ProofFormat::Json,
        config,
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
