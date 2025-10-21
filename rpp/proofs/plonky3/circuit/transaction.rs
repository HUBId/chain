use serde::{Deserialize, Serialize};

use crate::types::SignedTransaction;

use super::Plonky3CircuitWitness;

/// Witness representation for the transaction validity circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionWitness {
    pub transaction: SignedTransaction,
}

impl TransactionWitness {
    pub fn new(transaction: &SignedTransaction) -> Self {
        Self {
            transaction: transaction.clone(),
        }
    }
}

impl Plonky3CircuitWitness for TransactionWitness {
    fn circuit(&self) -> &'static str {
        "transaction"
    }
}
