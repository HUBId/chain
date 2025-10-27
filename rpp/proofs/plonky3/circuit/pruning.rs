use serde::{Deserialize, Serialize};

use crate::types::{AttestedIdentityRequest, SignedTransaction};
use rpp_pruning::{Commitment, Envelope, ProofSegment, Snapshot, TaggedDigest};

use super::Plonky3CircuitWitness;

/// Witness capturing the pruning relation between consecutive blocks.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningWitness {
    pub previous_identities: Vec<AttestedIdentityRequest>,
    pub previous_transactions: Vec<SignedTransaction>,
    pub snapshot: Snapshot,
    pub segments: Vec<ProofSegment>,
    pub commitment: Commitment,
    pub binding_digest: TaggedDigest,
    pub removed_transactions: Vec<String>,
}

impl PruningWitness {
    pub fn new(
        previous_identities: &[AttestedIdentityRequest],
        previous_transactions: &[SignedTransaction],
        pruning_proof: &Envelope,
        removed_transactions: Vec<String>,
    ) -> Self {
        Self {
            previous_identities: previous_identities.to_vec(),
            previous_transactions: previous_transactions.to_vec(),
            snapshot: pruning_proof.snapshot().clone(),
            segments: pruning_proof.segments().to_vec(),
            commitment: pruning_proof.commitment().clone(),
            binding_digest: pruning_proof.binding_digest(),
            removed_transactions,
        }
    }
}

impl Plonky3CircuitWitness for PruningWitness {
    fn circuit(&self) -> &'static str {
        "pruning"
    }
}
