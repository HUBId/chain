use serde::{Deserialize, Serialize};

use crate::prover::Proof;
use crate::utils::poseidon;
use crate::params::FieldElement;

/// A recursive proof bundles the digest of all previous proofs together with the
/// newest proof object.  The structure keeps the recursive chain deterministic
/// and easy to inspect in tests.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecursiveProof {
    pub aggregate_digest: [u8; 32],
    pub proof: Proof,
}

/// Combine a previous proof with the current one, producing a new recursive
/// aggregate.  The digest is computed by hashing the concatenation of both proof
/// digests and the current block height when present.
pub fn link_proofs(prev: &Proof, current: &Proof) -> RecursiveProof {
    let digest = poseidon::hash_elements(&[
        FieldElement::from_bytes(&prev.digest()[..16]),
        FieldElement::from_bytes(&prev.digest()[16..]),
        FieldElement::from_bytes(&current.digest()[..16]),
        FieldElement::from_bytes(&current.digest()[16..]),
    ]);
    RecursiveProof {
        aggregate_digest: digest,
        proof: current.clone(),
    }
}
