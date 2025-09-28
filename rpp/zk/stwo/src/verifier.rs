use crate::circuits::identity::IdentityWitness;
use crate::circuits::pruning::PruningWitness;
use crate::circuits::reputation::ReputationWitness;
use crate::circuits::transaction::TransactionWitness;
use crate::circuits::CircuitWitness;
use crate::params::FieldElement;
use crate::prover::{Block, Proof, ProofCircuit};
use crate::utils::fri::FriProver;
use crate::utils::poseidon;

fn commitment_from_inputs(inputs: &[FieldElement]) -> String {
    hex::encode(poseidon::hash_elements(inputs))
}

fn decode_witness<T: serde::de::DeserializeOwned>(proof: &Proof) -> Option<T> {
    proof.payload.decode_json()
}

fn encode_inputs(inputs: &[FieldElement]) -> Vec<String> {
    inputs
        .iter()
        .map(|element| hex::encode(element.to_bytes()))
        .collect()
}

fn commitment_elements(commitment: &[u8; 32]) -> [FieldElement; 2] {
    [
        FieldElement::from_bytes(&commitment[..16]),
        FieldElement::from_bytes(&commitment[16..]),
    ]
}

fn fri_inputs(trace: &crate::circuits::CircuitTrace, inputs: &[FieldElement]) -> Vec<FieldElement> {
    let mut values = inputs.to_vec();
    values.extend(commitment_elements(&trace.trace_commitment));
    values.extend(commitment_elements(&trace.constraint_commitment));
    values
}

fn verify_generic<W>(proof: &Proof, expected_circuit: ProofCircuit) -> Option<W>
where
    W: CircuitWitness + Clone + PartialEq,
{
    if proof.circuit != expected_circuit {
        return None;
    }
    decode_witness::<W>(proof)
}

fn transaction_inputs(witness: &TransactionWitness) -> Vec<FieldElement> {
    vec![
        FieldElement::from_bytes(witness.tx.tx_id.as_bytes()),
        FieldElement::from_bytes(witness.state.root.as_bytes()),
        FieldElement::from(witness.tx.tier as u128),
        FieldElement::from(witness.balance_sum),
    ]
}

fn reputation_inputs(witness: &ReputationWitness) -> Vec<FieldElement> {
    vec![
        FieldElement::from_bytes(witness.state.participant.as_bytes()),
        FieldElement::from(witness.state.score as u128),
        FieldElement::from(witness.state.tier as u128),
        FieldElement::from(witness.timetoken as u128),
    ]
}

fn identity_inputs(witness: &IdentityWitness) -> Vec<FieldElement> {
    vec![
        FieldElement::from_bytes(witness.genesis.wallet_address.as_bytes()),
        FieldElement::from_bytes(witness.genesis.genesis_block.as_bytes()),
    ]
}

fn pruning_inputs(witness: &PruningWitness) -> Vec<FieldElement> {
    vec![
        FieldElement::from_bytes(witness.inputs.utxo_root.as_bytes()),
        FieldElement::from_bytes(witness.inputs.reputation_root.as_bytes()),
        FieldElement::from_bytes(&witness.inputs.previous_proof_digest[..16]),
        FieldElement::from_bytes(&witness.inputs.previous_proof_digest[16..]),
    ]
}

pub fn verify_tx(tx: &crate::circuits::transaction::Transaction, proof: &Proof) -> bool {
    let witness: TransactionWitness = match verify_generic(proof, ProofCircuit::Transaction) {
        Some(witness) => witness,
        None => return false,
    };
    if witness.tx != *tx {
        return false;
    }
    let expected_inputs = transaction_inputs(&witness);
    if encode_inputs(&expected_inputs) != proof.public_inputs {
        return false;
    }
    if commitment_from_inputs(&expected_inputs) != proof.commitment {
        return false;
    }
    let expected_trace = witness.trace();
    if proof.trace != expected_trace {
        return false;
    }
    let fri_values = fri_inputs(&expected_trace, &expected_inputs);
    FriProver::verify(&fri_values, &proof.fri_proof)
}

pub fn verify_reputation(
    state: &crate::circuits::reputation::ReputationState,
    proof: &Proof,
) -> bool {
    let witness: ReputationWitness = match verify_generic(proof, ProofCircuit::Reputation) {
        Some(witness) => witness,
        None => return false,
    };
    if witness.state != *state {
        return false;
    }
    let expected_inputs = reputation_inputs(&witness);
    if encode_inputs(&expected_inputs) != proof.public_inputs {
        return false;
    }
    if commitment_from_inputs(&expected_inputs) != proof.commitment {
        return false;
    }
    let expected_trace = witness.trace();
    if proof.trace != expected_trace {
        return false;
    }
    let fri_values = fri_inputs(&expected_trace, &expected_inputs);
    FriProver::verify(&fri_values, &proof.fri_proof)
}

pub fn verify_block(block: &Block, proof: &Proof) -> bool {
    let witness: PruningWitness = match verify_generic(proof, ProofCircuit::Block) {
        Some(witness) => witness,
        None => return false,
    };
    if witness.inputs.utxo_root != block.tx_root {
        return false;
    }
    if witness.inputs.reputation_root != block.reputation_root {
        return false;
    }
    let expected_inputs = pruning_inputs(&witness);
    if encode_inputs(&expected_inputs) != proof.public_inputs {
        return false;
    }
    if commitment_from_inputs(&expected_inputs) != proof.commitment {
        return false;
    }
    let expected_trace = witness.trace();
    if proof.trace != expected_trace {
        return false;
    }
    let fri_values = fri_inputs(&expected_trace, &expected_inputs);
    FriProver::verify(&fri_values, &proof.fri_proof)
}

pub fn verify_identity(
    genesis: &crate::circuits::identity::IdentityGenesis,
    proof: &Proof,
) -> bool {
    let witness: IdentityWitness = match verify_generic(proof, ProofCircuit::Identity) {
        Some(witness) => witness,
        None => return false,
    };
    if witness.genesis != *genesis {
        return false;
    }
    let expected_inputs = identity_inputs(&witness);
    if encode_inputs(&expected_inputs) != proof.public_inputs {
        return false;
    }
    if commitment_from_inputs(&expected_inputs) != proof.commitment {
        return false;
    }
    let expected_trace = witness.trace();
    if proof.trace != expected_trace {
        return false;
    }
    let fri_values = fri_inputs(&expected_trace, &expected_inputs);
    FriProver::verify(&fri_values, &proof.fri_proof)
}
