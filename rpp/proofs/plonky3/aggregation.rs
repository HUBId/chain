//! Helpers for describing recursive aggregation layouts in Plonky3.

use serde::{Deserialize, Serialize};

use crate::errors::{ChainError, ChainResult};
use crate::types::ChainProof;

use super::proof::Plonky3Proof;

/// Minimal recursive aggregator placeholder used until the Plonky3 circuits
/// are wired up.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RecursiveAggregator {
    /// Proofs that have been combined so far.
    pub commitments: Vec<ChainProof>,
    /// Height of the block the aggregation belongs to.
    pub block_height: u64,
}

impl RecursiveAggregator {
    /// Construct a new aggregator snapshot.
    pub fn new(block_height: u64, commitments: Vec<ChainProof>) -> Self {
        Self {
            commitments,
            block_height,
        }
    }

    /// Build a placeholder Plonky3 proof referencing all aggregated
    /// commitments. The actual recursion gadget will replace this once the
    /// backend is fully implemented.
    pub fn finalize(self) -> ChainResult<Plonky3Proof> {
        let witness = serde_json::to_value(&self.commitments).map_err(|err| {
            ChainError::Crypto(format!("failed to encode recursive commitments: {err}"))
        })?;
        Ok(Plonky3Proof::placeholder(
            "recursive",
            witness,
            self.block_height,
        ))
    }
}
