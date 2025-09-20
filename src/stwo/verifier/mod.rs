//! Verifier-side integration for STWO/STARK proofs.

use crate::errors::{ChainError, ChainResult};

use super::aggregation::RecursiveAggregator;
use super::circuit::{
    CircuitError, ExecutionTrace, StarkCircuit, pruning::PruningCircuit,
    recursive::RecursiveCircuit, state::StateCircuit, transaction::TransactionCircuit,
};
use super::fri::FriProver;
use super::params::{FieldElement, StarkParameters};
use super::proof::{ProofKind, ProofPayload, StarkProof};

/// Trait implemented by STWO proof verifiers on the node side.
pub trait StarkVerifier {
    /// Verify a transaction proof payload.
    fn verify_transaction(&self, proof: &StarkProof) -> ChainResult<()>;

    /// Verify a state transition proof.
    fn verify_state(&self, proof: &StarkProof) -> ChainResult<()>;

    /// Verify a pruning proof payload.
    fn verify_pruning(&self, proof: &StarkProof) -> ChainResult<()>;

    /// Verify the recursive aggregation proof.
    fn verify_recursive(&self, proof: &StarkProof) -> ChainResult<()>;
}

fn string_to_field(parameters: &StarkParameters, value: &str) -> FieldElement {
    let bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
    parameters.element_from_bytes(&bytes)
}

fn map_circuit_error(err: CircuitError) -> ChainError {
    ChainError::Crypto(err.to_string())
}

/// Lightweight verifier that recomputes commitments by replaying circuits.
pub struct NodeVerifier {
    parameters: StarkParameters,
}

impl NodeVerifier {
    pub fn new() -> Self {
        Self {
            parameters: StarkParameters::blueprint_default(),
        }
    }

    fn check_commitment(&self, proof: &StarkProof) -> ChainResult<Vec<FieldElement>> {
        let inputs = proof
            .public_inputs
            .iter()
            .map(|input| string_to_field(&self.parameters, input))
            .collect::<Vec<_>>();
        let hasher = self.parameters.poseidon_hasher();
        let expected = hasher.hash(&inputs).to_hex();
        if expected != proof.commitment {
            return Err(ChainError::Crypto("proof commitment mismatch".into()));
        }
        Ok(inputs)
    }

    fn expect_kind(&self, proof: &StarkProof, kind: ProofKind) -> ChainResult<()> {
        if proof.kind != kind {
            return Err(ChainError::Crypto("proof kind mismatch".into()));
        }
        Ok(())
    }

    fn check_trace(&self, circuit_trace: ExecutionTrace, proof: &StarkProof) -> ChainResult<()> {
        if proof.trace != circuit_trace {
            return Err(ChainError::Crypto("proof trace mismatch".into()));
        }
        Ok(())
    }

    fn check_fri(
        &self,
        proof: &StarkProof,
        public_inputs: &[FieldElement],
        trace: &ExecutionTrace,
    ) -> ChainResult<()> {
        let fri_prover = FriProver::new(&self.parameters);
        let expected = fri_prover.prove(trace, public_inputs);
        if proof.fri_proof != expected {
            return Err(ChainError::Crypto("fri proof mismatch".into()));
        }
        Ok(())
    }

    fn compute_recursive_commitment(
        &self,
        witness: &super::circuit::recursive::RecursiveWitness,
    ) -> FieldElement {
        let aggregator = RecursiveAggregator::new(self.parameters.clone());
        aggregator.aggregate_commitment(
            witness.previous_commitment.as_deref(),
            &witness.tx_commitments,
            &witness.state_commitment,
            &witness.pruning_commitment,
            witness.block_height,
        )
    }
}

impl Default for NodeVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkVerifier for NodeVerifier {
    fn verify_transaction(&self, proof: &StarkProof) -> ChainResult<()> {
        self.expect_kind(proof, ProofKind::Transaction)?;
        let public_inputs = self.check_commitment(proof)?;
        if let ProofPayload::Transaction(witness) = &proof.payload {
            let circuit = TransactionCircuit::new(witness.clone());
            circuit.evaluate_constraints().map_err(map_circuit_error)?;
            let trace = circuit
                .generate_trace(&self.parameters)
                .map_err(map_circuit_error)?;
            circuit
                .verify_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            self.check_trace(trace.clone(), proof)?;
            self.check_fri(proof, &public_inputs, &trace)
        } else {
            Err(ChainError::Crypto(
                "transaction proof payload mismatch".into(),
            ))
        }
    }

    fn verify_state(&self, proof: &StarkProof) -> ChainResult<()> {
        self.expect_kind(proof, ProofKind::State)?;
        let public_inputs = self.check_commitment(proof)?;
        if let ProofPayload::State(witness) = &proof.payload {
            let circuit = StateCircuit::new(witness.clone());
            circuit.evaluate_constraints().map_err(map_circuit_error)?;
            let trace = circuit
                .generate_trace(&self.parameters)
                .map_err(map_circuit_error)?;
            circuit
                .verify_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            self.check_trace(trace.clone(), proof)?;
            self.check_fri(proof, &public_inputs, &trace)
        } else {
            Err(ChainError::Crypto("state proof payload mismatch".into()))
        }
    }

    fn verify_pruning(&self, proof: &StarkProof) -> ChainResult<()> {
        self.expect_kind(proof, ProofKind::Pruning)?;
        let public_inputs = self.check_commitment(proof)?;
        if let ProofPayload::Pruning(witness) = &proof.payload {
            let circuit = PruningCircuit::new(witness.clone());
            circuit.evaluate_constraints().map_err(map_circuit_error)?;
            let trace = circuit
                .generate_trace(&self.parameters)
                .map_err(map_circuit_error)?;
            circuit
                .verify_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            self.check_trace(trace.clone(), proof)?;
            self.check_fri(proof, &public_inputs, &trace)
        } else {
            Err(ChainError::Crypto("pruning proof payload mismatch".into()))
        }
    }

    fn verify_recursive(&self, proof: &StarkProof) -> ChainResult<()> {
        self.expect_kind(proof, ProofKind::Recursive)?;
        let public_inputs = self.check_commitment(proof)?;
        if let ProofPayload::Recursive(witness) = &proof.payload {
            let circuit = RecursiveCircuit::new(witness.clone());
            circuit.evaluate_constraints().map_err(map_circuit_error)?;
            let trace = circuit
                .generate_trace(&self.parameters)
                .map_err(map_circuit_error)?;
            circuit
                .verify_air(&self.parameters, &trace)
                .map_err(map_circuit_error)?;
            self.check_trace(trace.clone(), proof)?;
            self.check_fri(proof, &public_inputs, &trace)
        } else {
            Err(ChainError::Crypto(
                "recursive proof payload mismatch".into(),
            ))
        }
    }
}

impl NodeVerifier {
    /// Verify a full bundle of proofs associated with a block.
    pub fn verify_bundle(
        &self,
        tx_proofs: &[StarkProof],
        state_proof: &StarkProof,
        pruning_proof: &StarkProof,
        recursive_proof: &StarkProof,
        expected_previous_commitment: Option<&str>,
    ) -> ChainResult<String> {
        if tx_proofs.is_empty() && expected_previous_commitment.is_some() {
            return Err(ChainError::Crypto(
                "recursive bundle must include at least one transaction proof".into(),
            ));
        }

        for proof in tx_proofs {
            self.verify_transaction(proof)?;
        }
        self.verify_state(state_proof)?;
        self.verify_pruning(pruning_proof)?;
        self.verify_recursive(recursive_proof)?;

        let witness = match &recursive_proof.payload {
            ProofPayload::Recursive(witness) => witness,
            _ => {
                return Err(ChainError::Crypto(
                    "recursive proof payload mismatch".into(),
                ));
            }
        };

        if witness.tx_commitments.len() != tx_proofs.len() {
            return Err(ChainError::Crypto(
                "recursive witness transaction commitment count mismatch".into(),
            ));
        }
        for (expected_commitment, proof) in witness.tx_commitments.iter().zip(tx_proofs) {
            if expected_commitment != &proof.commitment {
                return Err(ChainError::Crypto(
                    "recursive witness transaction commitment mismatch".into(),
                ));
            }
        }

        if witness.state_commitment != state_proof.commitment {
            return Err(ChainError::Crypto(
                "recursive witness state commitment mismatch".into(),
            ));
        }
        if witness.pruning_commitment != pruning_proof.commitment {
            return Err(ChainError::Crypto(
                "recursive witness pruning commitment mismatch".into(),
            ));
        }

        if let Some(expected) = expected_previous_commitment {
            match &witness.previous_commitment {
                Some(actual) if actual == expected => {}
                Some(_) => {
                    return Err(ChainError::Crypto(
                        "recursive witness previous commitment mismatch".into(),
                    ));
                }
                None => {
                    return Err(ChainError::Crypto(
                        "recursive witness missing previous commitment".into(),
                    ));
                }
            }
        }

        let aggregated = self.compute_recursive_commitment(witness);
        let aggregated_hex = aggregated.to_hex();
        if aggregated_hex != witness.aggregated_commitment {
            return Err(ChainError::Crypto(
                "recursive witness aggregated commitment mismatch".into(),
            ));
        }

        if let Some(previous_input) = recursive_proof.public_inputs.get(0) {
            let expected_previous = witness.previous_commitment.clone().unwrap_or_default();
            if previous_input != &expected_previous {
                return Err(ChainError::Crypto(
                    "recursive proof public inputs do not encode previous commitment".into(),
                ));
            }
        }

        if let Some(aggregated_input) = recursive_proof.public_inputs.get(1) {
            if aggregated_input != &witness.aggregated_commitment {
                return Err(ChainError::Crypto(
                    "recursive proof public inputs do not encode aggregated commitment".into(),
                ));
            }
        }

        if let Some(tx_count_input) = recursive_proof.public_inputs.get(2) {
            let expected_tx_count = self
                .parameters
                .element_from_u64(witness.tx_commitments.len() as u64)
                .to_hex();
            if tx_count_input != &expected_tx_count {
                return Err(ChainError::Crypto(
                    "recursive proof public inputs do not encode transaction count".into(),
                ));
            }
        }

        Ok(aggregated_hex)
    }
}
