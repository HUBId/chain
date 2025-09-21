use serde::{Deserialize, Serialize};

use crate::types::SignedTransaction;

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
