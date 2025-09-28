//! Helpers for describing recursive aggregation layouts in Plonky3.

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::errors::{ChainError, ChainResult};
use crate::types::ChainProof;

use super::{crypto, proof::Plonky3Proof};

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

    /// Build a recursive proof that hashes the commitments from every
    /// aggregated sub-proof. This emulates the recursion circuit until the
    /// native Plonky3 backend is wired up.
    pub fn finalize(self) -> ChainResult<Plonky3Proof> {
        let mut aggregated = Vec::new();
        for proof in self.commitments {
            let value = match proof {
                ChainProof::Plonky3(value) => value,
                ChainProof::Stwo(_) => {
                    return Err(ChainError::Crypto(
                        "cannot aggregate STWO proof inside Plonky3 recursion".into(),
                    ));
                }
            };
            let inner = Plonky3Proof::from_value(&value)?;
            crypto::verify_proof(&inner)?;
            aggregated.push(inner.commitment);
        }
        let mut accumulator_hasher = Hasher::new();
        for commitment in &aggregated {
            accumulator_hasher.update(commitment.as_bytes());
        }
        let accumulator = accumulator_hasher.finalize().to_hex().to_string();
        let public_inputs = json!({
            "block_height": self.block_height,
            "commitments": aggregated,
            "accumulator": accumulator,
        });
        let proof = Plonky3Proof::new("recursive", public_inputs)?;
        crypto::verify_proof(&proof)?;
        Ok(proof)
    }
}
