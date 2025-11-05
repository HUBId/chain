use serde::{Deserialize, Serialize};

use crate::rpp::GlobalStateCommitments;
use crate::types::ChainProof;

use super::{CircuitParams, Plonky3CircuitWitness};

/// Marker type for the recursive circuit fixtures.
pub struct RecursiveCircuit;

impl RecursiveCircuit {
    /// Canonical domain and FRI digests extracted from the bundled recursive
    /// proving/verifying keys.
    pub const PARAMS: CircuitParams = CircuitParams {
        domain_root: [
            0x54, 0xb7, 0x1a, 0xb0, 0x76, 0x84, 0x65, 0x6c, 0x75, 0xe9, 0x35, 0xda, 0x9d, 0xfe,
            0x8f, 0x22, 0x64, 0x04, 0x1f, 0x90, 0x98, 0x40, 0x66, 0x2a, 0x9b, 0x8a, 0x94, 0x5e,
            0xb8, 0xe4, 0x20, 0x1a,
        ],
        quotient_root: [
            0x80, 0xfa, 0x40, 0xbd, 0x1f, 0x55, 0x65, 0xb5, 0x61, 0xcd, 0x66, 0x65, 0x30, 0x82,
            0x4c, 0x54, 0x54, 0xd6, 0xb7, 0x37, 0x70, 0x32, 0x53, 0x4e, 0x15, 0x35, 0x3f, 0xb8,
            0xc0, 0xad, 0xf0, 0x19,
        ],
        fri_digest: [
            0x1b, 0xd7, 0x4c, 0x85, 0x6e, 0x9d, 0x21, 0xaf, 0x8b, 0xd3, 0x9c, 0x73, 0xfd, 0xb6,
            0xd4, 0x3e, 0xad, 0x8d, 0x05, 0x35, 0x4c, 0x4d, 0x5b, 0xa9, 0xe1, 0x64, 0x2d, 0x02,
            0xbc, 0xae, 0xf1, 0x2a,
        ],
        verifying_key_hash: [
            0x4b, 0xff, 0x41, 0xc7, 0x6f, 0x6c, 0xcd, 0x89, 0x8e, 0x07, 0xdb, 0x2d, 0xae, 0x44,
            0x64, 0x64, 0x04, 0x02, 0xbb, 0xe8, 0x0f, 0xc6, 0xaa, 0x14, 0x57, 0xe9, 0x6c, 0x13,
            0xc9, 0xee, 0xad, 0x6b,
        ],
        proving_key_hash: [
            0x62, 0x19, 0x5a, 0xbd, 0x9a, 0x0e, 0x94, 0xce, 0x67, 0xe7, 0xe0, 0xfd, 0xa9, 0x72,
            0x36, 0x7e, 0xa4, 0xb6, 0xe2, 0xdf, 0xc3, 0xc8, 0x95, 0xf3, 0x2a, 0x2d, 0x37, 0xb4,
            0x97, 0xb7, 0xdd, 0x20,
        ],
    };
}

/// Witness structure for recursive aggregation in the Plonky3 backend.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecursiveWitness {
    pub previous_recursive: Option<ChainProof>,
    pub identity_proofs: Vec<ChainProof>,
    pub transaction_proofs: Vec<ChainProof>,
    pub uptime_proofs: Vec<ChainProof>,
    pub consensus_proofs: Vec<ChainProof>,
    pub state_commitments: GlobalStateCommitments,
    pub state_proof: ChainProof,
    pub pruning_proof: ChainProof,
    pub block_height: u64,
}

impl RecursiveWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        previous_recursive: Option<ChainProof>,
        identity_proofs: &[ChainProof],
        transaction_proofs: &[ChainProof],
        uptime_proofs: &[ChainProof],
        consensus_proofs: &[ChainProof],
        state_commitments: &GlobalStateCommitments,
        state_proof: &ChainProof,
        pruning_proof: &ChainProof,
        block_height: u64,
    ) -> Self {
        Self {
            previous_recursive,
            identity_proofs: identity_proofs.to_vec(),
            transaction_proofs: transaction_proofs.to_vec(),
            uptime_proofs: uptime_proofs.to_vec(),
            consensus_proofs: consensus_proofs.to_vec(),
            state_commitments: *state_commitments,
            state_proof: state_proof.clone(),
            pruning_proof: pruning_proof.clone(),
            block_height,
        }
    }
}

impl Plonky3CircuitWitness for RecursiveWitness {
    fn circuit(&self) -> &'static str {
        "recursive"
    }

    fn block_height(&self) -> Option<u64> {
        Some(self.block_height)
    }
}
