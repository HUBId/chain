use crate::circuits::identity::IdentityWitness;
use crate::circuits::pruning::PruningWitness;
use crate::circuits::reputation::ReputationWitness;
use crate::circuits::transaction::TransactionWitness;
use crate::circuits::CircuitWitness;
use crate::params::FieldElement;
use crate::prover::{Block, Proof, ProofCircuit};
use crate::utils::fri::FriProver;
use crate::utils::poseidon;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationError {
    CircuitMismatch,
    PayloadDecode,
    WitnessMismatch(&'static str),
    PublicInputMismatch,
    CommitmentMismatch,
    TraceMismatch,
    FriMismatch,
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use VerificationError::*;
        match self {
            CircuitMismatch => write!(f, "proof circuit mismatch"),
            PayloadDecode => write!(f, "proof payload could not be decoded"),
            WitnessMismatch(ctx) => write!(f, "witness mismatch: {ctx}"),
            PublicInputMismatch => write!(f, "public inputs mismatch"),
            CommitmentMismatch => write!(f, "commitment mismatch"),
            TraceMismatch => write!(f, "trace mismatch"),
            FriMismatch => write!(f, "fri proof mismatch"),
        }
    }
}

impl VerificationError {
    fn witness(label: &'static str) -> Self {
        VerificationError::WitnessMismatch(label)
    }
}

pub type VerificationResult<T> = Result<T, VerificationError>;

fn commitment_from_inputs(inputs: &[FieldElement]) -> [u8; 32] {
    poseidon::hash_elements(inputs)
}

fn decode_witness<T: serde::de::DeserializeOwned>(proof: &Proof) -> Option<T> {
    proof.payload.decode_json()
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

fn verify_witness<W>(proof: &Proof, expected_circuit: ProofCircuit) -> VerificationResult<W>
where
    W: CircuitWitness + Clone + PartialEq,
{
    if proof.circuit != expected_circuit {
        return Err(VerificationError::CircuitMismatch);
    }
    decode_witness::<W>(proof).ok_or(VerificationError::PayloadDecode)
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

pub fn verify_tx(
    tx: &crate::circuits::transaction::Transaction,
    proof: &Proof,
) -> VerificationResult<()> {
    let witness: TransactionWitness = verify_witness(proof, ProofCircuit::Transaction)?;
    if witness.tx != *tx {
        return Err(VerificationError::witness("transaction payload"));
    }
    let expected_inputs = transaction_inputs(&witness);
    if proof.public_inputs != expected_inputs {
        return Err(VerificationError::PublicInputMismatch);
    }
    if commitment_from_inputs(&expected_inputs) != proof.commitment {
        return Err(VerificationError::CommitmentMismatch);
    }
    let expected_trace = witness.trace();
    if proof.trace != expected_trace {
        return Err(VerificationError::TraceMismatch);
    }
    let fri_values = fri_inputs(&expected_trace, &expected_inputs);
    if !FriProver::verify(&fri_values, &proof.fri_proof) {
        return Err(VerificationError::FriMismatch);
    }
    Ok(())
}

pub fn verify_reputation(
    state: &crate::circuits::reputation::ReputationState,
    proof: &Proof,
) -> VerificationResult<()> {
    let witness: ReputationWitness = verify_witness(proof, ProofCircuit::Reputation)?;
    if witness.state != *state {
        return Err(VerificationError::witness("reputation state"));
    }
    let expected_inputs = reputation_inputs(&witness);
    if proof.public_inputs != expected_inputs {
        return Err(VerificationError::PublicInputMismatch);
    }
    if commitment_from_inputs(&expected_inputs) != proof.commitment {
        return Err(VerificationError::CommitmentMismatch);
    }
    let expected_trace = witness.trace();
    if proof.trace != expected_trace {
        return Err(VerificationError::TraceMismatch);
    }
    let fri_values = fri_inputs(&expected_trace, &expected_inputs);
    if !FriProver::verify(&fri_values, &proof.fri_proof) {
        return Err(VerificationError::FriMismatch);
    }
    Ok(())
}

pub fn verify_block(block: &Block, proof: &Proof) -> VerificationResult<()> {
    let witness: PruningWitness = verify_witness(proof, ProofCircuit::Block)?;
    if witness.inputs.utxo_root != block.tx_root {
        return Err(VerificationError::witness("utxo root"));
    }
    if witness.inputs.reputation_root != block.reputation_root {
        return Err(VerificationError::witness("reputation root"));
    }
    let expected_inputs = pruning_inputs(&witness);
    if proof.public_inputs != expected_inputs {
        return Err(VerificationError::PublicInputMismatch);
    }
    if commitment_from_inputs(&expected_inputs) != proof.commitment {
        return Err(VerificationError::CommitmentMismatch);
    }
    let expected_trace = witness.trace();
    if proof.trace != expected_trace {
        return Err(VerificationError::TraceMismatch);
    }
    let fri_values = fri_inputs(&expected_trace, &expected_inputs);
    if !FriProver::verify(&fri_values, &proof.fri_proof) {
        return Err(VerificationError::FriMismatch);
    }
    Ok(())
}

pub fn verify_identity(
    genesis: &crate::circuits::identity::IdentityGenesis,
    proof: &Proof,
) -> VerificationResult<()> {
    let witness: IdentityWitness = verify_witness(proof, ProofCircuit::Identity)?;
    if witness.genesis != *genesis {
        return Err(VerificationError::witness("identity genesis"));
    }
    let expected_inputs = identity_inputs(&witness);
    if proof.public_inputs != expected_inputs {
        return Err(VerificationError::PublicInputMismatch);
    }
    if commitment_from_inputs(&expected_inputs) != proof.commitment {
        return Err(VerificationError::CommitmentMismatch);
    }
    let expected_trace = witness.trace();
    if proof.trace != expected_trace {
        return Err(VerificationError::TraceMismatch);
    }
    let fri_values = fri_inputs(&expected_trace, &expected_inputs);
    if !FriProver::verify(&fri_values, &proof.fri_proof) {
        return Err(VerificationError::FriMismatch);
    }
    Ok(())
}
