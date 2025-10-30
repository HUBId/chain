use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::CircuitError;

/// Representation of an UTXO reference used in the double spend circuit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OutpointWitness {
    pub tx_id: String,
    pub index: u32,
}

impl OutpointWitness {
    pub fn new(tx_id: impl Into<String>, index: u32) -> Self {
        Self {
            tx_id: tx_id.into(),
            index,
        }
    }
}

/// Witness describing the input set of a transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoubleSpendWitness {
    pub available_inputs: Vec<OutpointWitness>,
    pub consumed_inputs: Vec<OutpointWitness>,
    pub produced_outputs: Vec<OutpointWitness>,
}

impl DoubleSpendWitness {
    pub fn new(
        available_inputs: Vec<OutpointWitness>,
        consumed_inputs: Vec<OutpointWitness>,
        produced_outputs: Vec<OutpointWitness>,
    ) -> Self {
        Self {
            available_inputs,
            consumed_inputs,
            produced_outputs,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoubleSpendCircuit {
    witness: DoubleSpendWitness,
}

impl DoubleSpendCircuit {
    pub fn new(witness: DoubleSpendWitness) -> Result<Self, CircuitError> {
        if witness.consumed_inputs.is_empty() {
            return Err(CircuitError::invalid(
                "double spend circuit requires at least one consumed input",
            ));
        }
        Ok(Self { witness })
    }

    pub fn verify(&self) -> Result<(), CircuitError> {
        let mut available: HashSet<&OutpointWitness> = HashSet::new();
        for input in &self.witness.available_inputs {
            if input.tx_id.is_empty() {
                return Err(CircuitError::invalid(
                    "available input must provide a transaction identifier",
                ));
            }
            available.insert(input);
        }

        let mut seen_consumed = HashSet::new();
        for input in &self.witness.consumed_inputs {
            if !available.contains(input) {
                return Err(CircuitError::violated(
                    "consumed input not present in available set",
                ));
            }
            if !seen_consumed.insert(input) {
                return Err(CircuitError::violated(
                    "duplicate input detected in consumed set",
                ));
            }
        }

        let produced: HashSet<_> = self.witness.produced_outputs.iter().collect();
        if !produced.is_disjoint(&seen_consumed) {
            return Err(CircuitError::violated(
                "transaction re-introduces a consumed input as output",
            ));
        }

        Ok(())
    }

    pub fn witness(&self) -> &DoubleSpendWitness {
        &self.witness
    }
}
