use serde::{Deserialize, Serialize};

use crate::core::vcs::blake2_hash::Blake2sHasher;
use crate::params::FieldElement;
use crate::utils::poseidon;

use super::{CircuitTrace, CircuitWitness};

/// Minimal representation of a transaction used for local proving.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transaction {
    pub tx_id: String,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub tier: u8,
}

/// Snapshot of the UTXO set referenced by the transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UtxoState {
    pub root: String,
    pub height: u64,
}

/// Witness container for the transaction circuit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionWitness {
    pub tx: Transaction,
    pub state: UtxoState,
    pub balance_sum: u128,
    pub ownership_seal: String,
}

impl CircuitWitness for TransactionWitness {
    fn label(&self) -> &'static str {
        "transaction"
    }
}

impl TransactionWitness {
    /// Build a witness from a transaction and the referenced state.
    pub fn new(tx: Transaction, state: UtxoState) -> Self {
        let balance_sum = tx
            .outputs
            .iter()
            .chain(tx.inputs.iter())
            .map(|value| value.as_bytes().iter().map(|b| *b as u128).sum::<u128>())
            .sum();
        let ownership_seal = hex::encode(Blake2sHasher::hash(tx.tx_id.as_bytes()).0);
        Self {
            tx,
            state,
            balance_sum,
            ownership_seal,
        }
    }

    /// Compute the public inputs committed by the prover.
    pub fn public_inputs(&self) -> serde_json::Value {
        serde_json::json!({
            "tx_id": self.tx.tx_id,
            "state_root": self.state.root,
            "tier": self.tx.tier,
            "balance_sum": self.balance_sum,
        })
    }

    /// Derive commitments summarising the execution trace.
    pub fn trace(&self) -> CircuitTrace {
        let mut poseidon_inputs: Vec<FieldElement> = Vec::new();
        poseidon_inputs.push(FieldElement::from_bytes(self.tx.tx_id.as_bytes()));
        poseidon_inputs.push(FieldElement::from_bytes(self.state.root.as_bytes()));
        poseidon_inputs.push(FieldElement::from(self.balance_sum));
        let constraint_commitment = poseidon::hash_elements(&poseidon_inputs);

        let mut trace_bytes = Vec::new();
        trace_bytes.extend(self.tx.tx_id.as_bytes());
        trace_bytes.extend(self.state.root.as_bytes());
        trace_bytes.extend(self.ownership_seal.as_bytes());
        let trace_commitment = Blake2sHasher::hash(&trace_bytes).0;

        CircuitTrace::new(trace_commitment, constraint_commitment)
    }
}
