use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::core::vcs::blake2_hash::Blake2sHasher;
use crate::params::FieldElement;
use crate::utils::poseidon;

/// Minimal representation of a FRI query.  The randomness is deterministic for
/// repeatability during testing.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriQuery {
    pub index: usize,
    pub value: FieldElement,
}

/// Proof object returned by the simplified FRI protocol.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FriProof {
    pub commitment: [u8; 32],
    pub queries: Vec<FriQuery>,
}

pub struct FriProver;

impl FriProver {
    pub fn commit(values: &[FieldElement]) -> [u8; 32] {
        poseidon::hash_elements(values)
    }

    pub fn prove(values: &[FieldElement]) -> FriProof {
        let commitment = Self::commit(values);
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);
        let queries: Vec<FriQuery> = values
            .iter()
            .enumerate()
            .take(4)
            .map(|(index, value)| FriQuery {
                index: (index + rng.gen::<usize>()) % values.len().max(1),
                value: value.clone(),
            })
            .collect();
        FriProof {
            commitment,
            queries,
        }
    }

    pub fn verify(values: &[FieldElement], proof: &FriProof) -> bool {
        let expected_commitment = Self::commit(values);
        if expected_commitment != proof.commitment {
            return false;
        }
        proof.queries.iter().all(|query| {
            values
                .get(query.index % values.len().max(1))
                .map(|v| v == &query.value)
                .unwrap_or(false)
        })
    }
}

pub fn compress_proof(proof: &FriProof) -> [u8; 32] {
    let encoded = serde_json::to_vec(proof).expect("fri proof is serialisable");
    Blake2sHasher::hash(&encoded).0
}
