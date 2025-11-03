//! Prover-side helpers backed by the official STWO implementation.

use crate::official::circuit::{
    consensus::{ConsensusCircuit, ConsensusWitness},
    identity::{IdentityCircuit, IdentityWitness},
    pruning::{PruningCircuit, PruningWitness},
    recursive::{RecursiveCircuit, RecursiveWitness},
    state::{StateCircuit, StateWitness},
    string_to_field,
    transaction::{TransactionCircuit, TransactionWitness},
    uptime::{UptimeCircuit, UptimeWitness},
    CircuitError, StarkCircuit,
};
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

    /// Generate an identity proof for the provided witness.
    pub fn prove_identity_witness(
        &self,
        witness: IdentityWitness,
    ) -> Result<StarkProof, CircuitError> {
        let circuit = IdentityCircuit::new(witness.clone());
        circuit.evaluate_constraints()?;
        let trace = circuit.generate_trace(&self.parameters)?;
        circuit.verify_air(&self.parameters, &trace)?;
        let air = circuit.define_air(&self.parameters, &trace)?;

        let public_inputs = vec![
            string_to_field(&self.parameters, &witness.wallet_addr),
            string_to_field(&self.parameters, &witness.vrf_tag),
            string_to_field(&self.parameters, &witness.identity_root),
            string_to_field(&self.parameters, &witness.state_root),
        ];

        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &public_inputs);
        let hasher = self.parameters.poseidon_hasher();

        Ok(StarkProof::new(
            ProofKind::Identity,
            ProofPayload::Identity(witness),
            public_inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }

    /// Generate a state transition proof for the provided witness.
    pub fn prove_state_witness(&self, witness: StateWitness) -> Result<StarkProof, CircuitError> {
        let circuit = StateCircuit::new(witness.clone());
        circuit.evaluate_constraints()?;
        let trace = circuit.generate_trace(&self.parameters)?;
        circuit.verify_air(&self.parameters, &trace)?;
        let air = circuit.define_air(&self.parameters, &trace)?;

        let public_inputs = vec![
            string_to_field(&self.parameters, &witness.prev_state_root),
            string_to_field(&self.parameters, &witness.new_state_root),
            self.parameters
                .element_from_u64(witness.transactions.len() as u64),
        ];

        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &public_inputs);
        let hasher = self.parameters.poseidon_hasher();

        Ok(StarkProof::new(
            ProofKind::State,
            ProofPayload::State(witness),
            public_inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }

    /// Generate a pruning proof for the provided witness data.
    pub fn prove_pruning_witness(
        &self,
        witness: PruningWitness,
    ) -> Result<StarkProof, CircuitError> {
        let circuit = PruningCircuit::new(witness.clone());
        circuit.evaluate_constraints()?;
        let trace = circuit.generate_trace(&self.parameters)?;
        circuit.verify_air(&self.parameters, &trace)?;
        let air = circuit.define_air(&self.parameters, &trace)?;

        let public_inputs = vec![
            string_to_field(&self.parameters, &witness.previous_tx_root),
            string_to_field(&self.parameters, &witness.pruned_tx_root),
            self.parameters
                .element_from_u64(witness.removed_transactions.len() as u64),
        ];

        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &public_inputs);
        let hasher = self.parameters.poseidon_hasher();

        Ok(StarkProof::new(
            ProofKind::Pruning,
            ProofPayload::Pruning(witness),
            public_inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }

    /// Generate a recursive aggregation proof for the provided witness data.
    pub fn prove_recursive_witness(
        &self,
        witness: RecursiveWitness,
    ) -> Result<StarkProof, CircuitError> {
        let circuit = RecursiveCircuit::new(witness.clone());
        circuit.evaluate_constraints()?;
        let trace = circuit.generate_trace(&self.parameters)?;
        circuit.verify_air(&self.parameters, &trace)?;
        let air = circuit.define_air(&self.parameters, &trace)?;

        let previous = witness.previous_commitment.clone().unwrap_or_default();
        let public_inputs = vec![
            string_to_field(&self.parameters, &previous),
            string_to_field(&self.parameters, &witness.aggregated_commitment),
            self.parameters
                .element_from_u64(witness.tx_commitments.len() as u64),
        ];

        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &public_inputs);
        let hasher = self.parameters.poseidon_hasher();

        Ok(StarkProof::new(
            ProofKind::Recursive,
            ProofPayload::Recursive(witness),
            public_inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }

    /// Generate an uptime proof for the provided witness data.
    pub fn prove_uptime_witness(&self, witness: UptimeWitness) -> Result<StarkProof, CircuitError> {
        let circuit = UptimeCircuit::new(witness.clone());
        circuit.evaluate_constraints()?;
        let trace = circuit.generate_trace(&self.parameters)?;
        circuit.verify_air(&self.parameters, &trace)?;
        let air = circuit.define_air(&self.parameters, &trace)?;

        let public_inputs = vec![
            string_to_field(&self.parameters, &witness.wallet_address),
            self.parameters.element_from_u64(witness.node_clock),
            self.parameters.element_from_u64(witness.epoch),
            string_to_field(&self.parameters, &witness.head_hash),
            self.parameters.element_from_u64(witness.window_start),
            self.parameters.element_from_u64(witness.window_end),
            string_to_field(&self.parameters, &witness.commitment),
        ];

        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &public_inputs);
        let hasher = self.parameters.poseidon_hasher();

        Ok(StarkProof::new(
            ProofKind::Uptime,
            ProofPayload::Uptime(witness),
            public_inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }

    /// Generate a consensus proof for the provided witness data.
    pub fn prove_consensus_witness(
        &self,
        witness: ConsensusWitness,
    ) -> Result<StarkProof, CircuitError> {
        let circuit = ConsensusCircuit::new(witness.clone());
        circuit.evaluate_constraints()?;
        let trace = circuit.generate_trace(&self.parameters)?;
        circuit.verify_air(&self.parameters, &trace)?;
        let air = circuit.define_air(&self.parameters, &trace)?;

        let public_inputs = ConsensusCircuit::public_inputs(&self.parameters, &witness)?;

        let fri_prover = FriProver::new(&self.parameters);
        let fri_output = fri_prover.prove(&air, &trace, &public_inputs);
        let hasher = self.parameters.poseidon_hasher();

        Ok(StarkProof::new(
            ProofKind::Consensus,
            ProofPayload::Consensus(witness),
            public_inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        ))
    }
}
