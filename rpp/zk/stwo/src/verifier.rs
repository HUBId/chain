use crate::circuits::identity::{IdentityGenesis, IdentityWitness};
use crate::circuits::pruning::{PruningInputs, PruningWitness};
use crate::circuits::reputation::{ReputationState, ReputationWitness};
use crate::circuits::transaction::{Transaction, TransactionWitness, UtxoState};
use crate::params::{FieldElement, StwoConfig};
use crate::prover::{Block, Proof, ProofCircuit, ProofFormat};
use crate::utils::fri::FriProver;
use crate::utils::poseidon;

fn fri_inputs_from_trace(trace: &crate::circuits::CircuitTrace) -> Vec<FieldElement> {
    vec![
        FieldElement::from_bytes(&trace.trace_commitment[..16]),
        FieldElement::from_bytes(&trace.trace_commitment[16..]),
        FieldElement::from_bytes(&trace.constraint_commitment[..16]),
        FieldElement::from_bytes(&trace.constraint_commitment[16..]),
    ]
}

fn verify_witness(
    proof: &Proof,
    witness_trace: crate::circuits::CircuitTrace,
    public_inputs: serde_json::Value,
) -> bool {
    if proof.format != ProofFormat::Json {
        return false;
    }
    if proof.config != StwoConfig::default() {
        return false;
    }
    if proof.trace != witness_trace {
        return false;
    }
    if proof.public_inputs != public_inputs {
        return false;
    }
    let fri_inputs = fri_inputs_from_trace(&witness_trace);
    FriProver::verify(&fri_inputs, &proof.fri_proof)
}

pub fn verify_tx(tx: &Transaction, proof: &Proof) -> bool {
    if proof.circuit != ProofCircuit::Transaction {
        return false;
    }
    let state_root = proof
        .public_inputs
        .get("state_root")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let state = UtxoState {
        root: state_root.to_owned(),
        height: 0,
    };
    let witness = TransactionWitness::new(tx.clone(), state);
    verify_witness(proof, witness.trace(), witness.public_inputs())
}

pub fn verify_reputation(state: &ReputationState, proof: &Proof) -> bool {
    if proof.circuit != ProofCircuit::Reputation {
        return false;
    }
    let witness = ReputationWitness::new(state.clone(), state.epochs_participated, 0);
    verify_witness(proof, witness.trace(), witness.public_inputs())
}

pub fn verify_block(block: &Block, proof: &Proof) -> bool {
    if proof.circuit != ProofCircuit::Block {
        return false;
    }
    let previous_digest = proof
        .public_inputs
        .get("previous_digest")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let mut digest_bytes = [0u8; 32];
    hex::decode_to_slice(previous_digest, &mut digest_bytes).ok();
    let inputs = PruningInputs {
        utxo_root: block.tx_root.clone(),
        reputation_root: block.reputation_root.clone(),
        previous_proof_digest: digest_bytes,
    };
    let leaves = vec![
        digest_bytes,
        poseidon::hash_elements(&[
            FieldElement::from(block.height as u128),
            FieldElement::from_bytes(block.tx_root.as_bytes()),
        ]),
    ];
    let witness = PruningWitness::new(inputs, leaves);
    verify_witness(proof, witness.trace(), witness.public_inputs())
}

pub fn verify_identity(genesis: &IdentityGenesis, proof: &Proof) -> bool {
    if proof.circuit != ProofCircuit::Identity {
        return false;
    }
    let wallet_key = proof
        .public_inputs
        .get("wallet")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let witness = IdentityWitness::new(genesis.clone(), wallet_key.to_owned(), "vote".into());
    verify_witness(proof, witness.trace(), witness.public_inputs())
}
