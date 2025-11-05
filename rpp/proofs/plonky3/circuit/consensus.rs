use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::{ChainError, ChainResult};

use super::{CircuitParams, Plonky3CircuitWitness};
use plonky3_backend::{
    ConsensusCircuit as BackendConsensusCircuit, ConsensusWitness as BackendConsensusWitness,
    VotePower as BackendVotePower,
};

/// Marker type for the consensus circuit fixtures.
pub struct ConsensusCircuit;

impl ConsensusCircuit {
    /// Canonical domain and FRI digests extracted from the bundled consensus
    /// proving/verifying keys.
    pub const PARAMS: CircuitParams = CircuitParams {
        domain_root: [
            0x2c, 0x62, 0xc6, 0x2d, 0x7c, 0x1c, 0x79, 0xb1, 0xf1, 0xa1, 0x14, 0x0f, 0x67, 0xab,
            0x7b, 0xb0, 0xc6, 0xa3, 0x32, 0x78, 0x79, 0x65, 0x8a, 0x89, 0xee, 0x3c, 0x65, 0x9d,
            0xc3, 0x78, 0x1a, 0xa6,
        ],
        quotient_root: [
            0x7c, 0xdc, 0x15, 0x0a, 0xc9, 0x47, 0xa3, 0x3a, 0x6e, 0xf2, 0x14, 0x22, 0x51, 0x32,
            0x88, 0x6e, 0x3d, 0x74, 0x97, 0xd8, 0x2a, 0x28, 0x15, 0x76, 0xe0, 0x05, 0x71, 0x43,
            0x28, 0x29, 0xa6, 0x5d,
        ],
        fri_digest: [
            0x4e, 0x8a, 0xa4, 0x82, 0x58, 0xf6, 0x07, 0x6f, 0x1a, 0x3d, 0x0d, 0xd9, 0xdf, 0xc1,
            0x2b, 0x9f, 0xf4, 0x35, 0xc4, 0x14, 0x7a, 0xd7, 0x0d, 0x0c, 0xce, 0xe7, 0xc5, 0x2f,
            0x24, 0xe7, 0x2d, 0xeb,
        ],
        verifying_key_hash: [
            0x92, 0x71, 0x4c, 0x6f, 0x34, 0x73, 0xbe, 0x80, 0xb0, 0x7b, 0x28, 0x42, 0x80, 0x08,
            0xfb, 0x0b, 0xc9, 0x66, 0xcf, 0x5b, 0x2f, 0x62, 0xc4, 0xef, 0xb5, 0xab, 0x9f, 0xbc,
            0xac, 0x9c, 0xee, 0xa8,
        ],
        proving_key_hash: [
            0x1f, 0xfe, 0xa2, 0x1d, 0xb7, 0xa7, 0xca, 0x39, 0x71, 0xf9, 0x1a, 0x41, 0x21, 0x7a,
            0x8f, 0x9d, 0x76, 0xb6, 0xc9, 0x72, 0xbb, 0x6f, 0x16, 0x3f, 0xf8, 0xc8, 0x53, 0x59,
            0xab, 0x50, 0x32, 0x31,
        ],
    };
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusVrfPoseidonInput {
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub last_block_header: String,
    #[serde(default)]
    pub epoch: String,
    #[serde(default)]
    pub tier_seed: String,
}

impl Default for ConsensusVrfPoseidonInput {
    fn default() -> Self {
        let zero_digest = "00".repeat(32);
        Self {
            digest: zero_digest.clone(),
            last_block_header: zero_digest.clone(),
            epoch: "0".to_string(),
            tier_seed: zero_digest,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ConsensusVrfEntry {
    #[serde(default)]
    pub randomness: String,
    #[serde(default)]
    pub pre_output: String,
    #[serde(default)]
    pub proof: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
    pub poseidon: ConsensusVrfPoseidonInput,
}

impl Default for ConsensusVrfEntry {
    fn default() -> Self {
        let zero_hex_32 = "00".repeat(32);
        Self {
            randomness: zero_hex_32.clone(),
            pre_output: zero_hex_32.clone(),
            proof: "00".repeat(80),
            public_key: zero_hex_32,
            poseidon: ConsensusVrfPoseidonInput::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VotePower {
    pub voter: String,
    pub weight: u64,
}

impl From<&VotePower> for BackendVotePower {
    fn from(value: &VotePower) -> Self {
        Self {
            voter: value.voter.clone(),
            weight: value.weight,
        }
    }
}

/// Witness representation for the BFT consensus circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusWitness {
    pub block_hash: String,
    pub round: u64,
    pub epoch: u64,
    pub slot: u64,
    pub leader_proposal: String,
    pub quorum_threshold: u64,
    pub pre_votes: Vec<VotePower>,
    pub pre_commits: Vec<VotePower>,
    pub commit_votes: Vec<VotePower>,
    pub quorum_bitmap_root: String,
    pub quorum_signature_root: String,
    #[serde(default)]
    pub vrf_entries: Vec<ConsensusVrfEntry>,
    pub witness_commitments: Vec<String>,
    pub reputation_roots: Vec<String>,
}

impl ConsensusWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_hash: impl Into<String>,
        round: u64,
        epoch: u64,
        slot: u64,
        leader_proposal: impl Into<String>,
        quorum_threshold: u64,
        pre_votes: Vec<VotePower>,
        pre_commits: Vec<VotePower>,
        commit_votes: Vec<VotePower>,
        quorum_bitmap_root: impl Into<String>,
        quorum_signature_root: impl Into<String>,
        vrf_entries: Vec<ConsensusVrfEntry>,
        witness_commitments: Vec<String>,
        reputation_roots: Vec<String>,
    ) -> Self {
        Self {
            block_hash: block_hash.into(),
            round,
            epoch,
            slot,
            leader_proposal: leader_proposal.into(),
            quorum_threshold,
            pre_votes,
            pre_commits,
            commit_votes,
            quorum_bitmap_root: quorum_bitmap_root.into(),
            quorum_signature_root: quorum_signature_root.into(),
            vrf_entries,
            witness_commitments,
            reputation_roots,
        }
    }

    pub fn to_backend(&self) -> ChainResult<BackendConsensusWitness> {
        if self.vrf_entries.is_empty() {
            return Err(ChainError::Crypto(
                "consensus witness missing VRF entries".into(),
            ));
        }

        for (index, entry) in self.vrf_entries.iter().enumerate() {
            let ensure_present = |label: &str, value: &str| -> ChainResult<()> {
                if value.trim().is_empty() {
                    return Err(ChainError::Crypto(format!(
                        "consensus witness vrf entry #{index} missing {label}",
                    )));
                }
                Ok(())
            };

            ensure_present("randomness", &entry.randomness)?;
            ensure_present("pre-output", &entry.pre_output)?;
            ensure_present("proof", &entry.proof)?;
            ensure_present("public key", &entry.public_key)?;
            ensure_present("poseidon digest", &entry.poseidon.digest)?;
            ensure_present(
                "poseidon last block header",
                &entry.poseidon.last_block_header,
            )?;
            ensure_present("poseidon epoch", &entry.poseidon.epoch)?;
            ensure_present("poseidon tier seed", &entry.poseidon.tier_seed)?;
        }

        Ok(BackendConsensusWitness {
            block_hash: self.block_hash.clone(),
            round: self.round,
            epoch: self.epoch,
            slot: self.slot,
            leader_proposal: self.leader_proposal.clone(),
            quorum_threshold: self.quorum_threshold,
            pre_votes: self.pre_votes.iter().map(BackendVotePower::from).collect(),
            pre_commits: self
                .pre_commits
                .iter()
                .map(BackendVotePower::from)
                .collect(),
            commit_votes: self
                .commit_votes
                .iter()
                .map(BackendVotePower::from)
                .collect(),
            quorum_bitmap_root: self.quorum_bitmap_root.clone(),
            quorum_signature_root: self.quorum_signature_root.clone(),
            vrf_entries: self.vrf_entries.clone(),
            witness_commitments: self.witness_commitments.clone(),
            reputation_roots: self.reputation_roots.clone(),
        })
    }

    pub(crate) fn validate_metadata(&self) -> ChainResult<()> {
        let backend = self.to_backend()?;
        BackendConsensusCircuit::new(backend)
            .map(|_| ())
            .map_err(|err| {
                ChainError::Crypto(format!(
                    "invalid consensus witness metadata for Plonky3 circuit: {err}"
                ))
            })
    }
}

impl Plonky3CircuitWitness for ConsensusWitness {
    fn circuit(&self) -> &'static str {
        "consensus"
    }

    fn block_height(&self) -> Option<u64> {
        Some(self.round)
    }

    fn public_inputs(&self) -> ChainResult<Value> {
        let backend_witness = self.to_backend()?;
        let circuit = BackendConsensusCircuit::new(backend_witness).map_err(|err| {
            ChainError::Crypto(format!(
                "failed to prepare consensus public inputs for Plonky3 circuit: {err}"
            ))
        })?;
        circuit.public_inputs_value().map_err(|err| {
            ChainError::Crypto(format!(
                "failed to serialize consensus public inputs for Plonky3 circuit: {err}"
            ))
        })
    }
}
