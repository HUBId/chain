//! Prover-side helpers backed by the official STWO implementation.

use crate::official::circuit::{
    string_to_field, transaction::TransactionCircuit, CircuitError, StarkCircuit,
};
use crate::official::circuit::transaction::TransactionWitness;
use crate::official::fri::FriProver;
use crate::official::params::StarkParameters;
use crate::official::proof::{ProofKind, ProofPayload, StarkProof};

/// Minimal prover wrapper that evaluates blueprint circuits using the official
/// STWO implementation.
#[derive(Clone, Debug)]
pub struct WalletProver {
    parameters: StarkParameters,
}

impl WalletProver {
    /// Create a prover bound to a specific parameter set.
    pub fn new(parameters: StarkParameters) -> Self {
        Self { parameters }
    }

    /// Generate a transaction proof for the provided witness data.
    pub fn prove_transaction_witness(
        &self,
        witness: TransactionWitness,
    ) -> Result<StarkProof, CircuitError> {
        let circuit = TransactionCircuit::new(witness.clone());
        circuit.evaluate_constraints()?;
        let trace = circuit.generate_trace(&self.parameters)?;
        circuit.verify_air(&self.parameters, &trace)?;
        let air = circuit.define_air(&self.parameters, &trace)?;

        let tx = &witness.signed_tx.payload;
        let public_inputs = vec![
            string_to_field(&self.parameters, &tx.from),
            string_to_field(&self.parameters, &tx.to),
            self.parameters.element_from_u128(tx.amount),
            self.parameters.element_from_u64(tx.fee as u64),
            self.parameters.element_from_u64(tx.nonce),
        ];

        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &public_inputs);
        let hasher = self.parameters.poseidon_hasher();

        Ok(StarkProof::new(
            ProofKind::Transaction,
            ProofPayload::Transaction(witness),
            public_inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }
}
