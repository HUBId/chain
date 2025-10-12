//! Batched verification helpers for FRI proofs.
//!
//! The batching API is intentionally lightweight: it stores the proofs,
//! deterministic seeds and aggregate digest exposed by the transcript.  Callers
//! can feed the structure into [`FriBatch::verify`] to replay all FRI proofs
//! using the deterministic [`FriVerifier`] logic.

use crate::field::FieldElement;

use super::proof::{FriProof, FriVerifier};
use super::types::{FriError, FriSecurityLevel, FriTranscriptSeed};
use crate::hash::hash;

/// Seed shared across the batch, typically derived from a transcript challenge.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BatchSeed {
    /// Raw bytes sourced from the Fiat-Shamir transcript.
    pub bytes: [u8; 32],
}

/// Aggregated digest binding all batched openings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BatchDigest {
    /// Canonical digest over the ordered batch openings.
    pub bytes: [u8; 32],
}

/// Describes a query position inside a batched verification request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BatchQueryPosition {
    /// Index of the proof inside the batch.
    pub proof_index: usize,
    /// Position queried in the corresponding codeword.
    pub position: usize,
}

/// Declarative container describing the inputs to a batched FRI verification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FriBatch {
    /// Proofs participating in the batch.
    pub proofs: Vec<FriProof>,
    /// Seed that is common across all proofs in the batch.
    pub joint_seed: BatchSeed,
    /// Disjoint query positions assigned to each proof.
    pub query_positions: Vec<BatchQueryPosition>,
    /// Digest aggregating all openings in the order imposed by the transcript.
    pub aggregate_digest: BatchDigest,
}

impl FriBatch {
    /// Verifies all proofs in the batch by delegating to [`FriVerifier`].
    ///
    /// The closure `final_value_oracle` receives the proof index and the index of
    /// the residual polynomial queried by the verifier.  Implementations can use
    /// this hook to supply the expected final-layer value for the query.
    pub fn verify<F>(
        &self,
        security_level: FriSecurityLevel,
        transcript_seed: FriTranscriptSeed,
        mut final_value_oracle: F,
    ) -> Result<(), FriError>
    where
        F: FnMut(usize, usize) -> FieldElement,
    {
        for (proof_index, proof) in self.proofs.iter().enumerate() {
            let mut seed_input = Vec::with_capacity(72);
            seed_input.extend_from_slice(&self.joint_seed.bytes);
            seed_input.extend_from_slice(&(proof_index as u64).to_le_bytes());
            seed_input.extend_from_slice(&transcript_seed);
            let seed: [u8; 32] = hash(&seed_input).into();
            FriVerifier::verify(proof, security_level, seed, |final_index| {
                final_value_oracle(proof_index, final_index)
            })?;
        }
        Ok(())
    }
}

/// Trait summarising the read-only API required by batched verification logic.
pub trait FriBatchVerificationApi {
    /// Returns the proofs being verified.
    fn proofs(&self) -> &[FriProof];

    /// Returns the joint seed used to derive batched randomness.
    fn joint_seed(&self) -> &BatchSeed;

    /// Returns the disjoint set of query positions.
    fn query_positions(&self) -> &[BatchQueryPosition];

    /// Returns the digest binding the batched openings.
    fn aggregate_digest(&self) -> &BatchDigest;
}

impl FriBatchVerificationApi for FriBatch {
    fn proofs(&self) -> &[FriProof] {
        &self.proofs
    }

    fn joint_seed(&self) -> &BatchSeed {
        &self.joint_seed
    }

    fn query_positions(&self) -> &[BatchQueryPosition] {
        &self.query_positions
    }

    fn aggregate_digest(&self) -> &BatchDigest {
        &self.aggregate_digest
    }
}
