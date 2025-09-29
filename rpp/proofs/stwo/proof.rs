use super::air::AirDefinition;
use super::circuit::ExecutionTrace;
use super::fri::FriProver;
use super::params::{FieldElement, StarkParameters};

pub use stwo::official::proof::{
    CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
};

/// Construct a proof artifact by committing to the supplied trace and public inputs.
pub fn placeholder_proof(
    parameters: &StarkParameters,
    kind: ProofKind,
    payload: ProofPayload,
    public_inputs: Vec<FieldElement>,
    trace: ExecutionTrace,
    air: AirDefinition,
) -> StarkProof {
    let fri_prover = FriProver::new(parameters);
    let fri_output = fri_prover.prove(&air, &trace, &public_inputs);
    let hasher = parameters.poseidon_hasher();

    StarkProof::new(
        kind,
        payload,
        public_inputs,
        trace,
        fri_output.commitment_proof,
        fri_output.fri_proof,
        &hasher,
    )
}
