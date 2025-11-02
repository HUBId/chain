use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::errors::{ChainError, ChainResult};

use super::Plonky3CircuitWitness;
use plonky3_backend::{
    ConsensusCircuit as BackendConsensusCircuit, ConsensusWitness as BackendConsensusWitness,
    VotePower as BackendVotePower,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusVrfWitnessPoseidonInput {
    pub digest: String,
    pub last_block_header: String,
    pub epoch: u64,
    pub tier_seed: String,
}

impl Default for ConsensusVrfWitnessPoseidonInput {
    fn default() -> Self {
        let zero_digest = "00".repeat(32);
        Self {
            digest: zero_digest.clone(),
            last_block_header: zero_digest.clone(),
            epoch: 0,
            tier_seed: zero_digest,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ConsensusVrfWitnessEntry {
    pub randomness: String,
    pub pre_output: String,
    pub proof: String,
    pub public_key: String,
    pub poseidon: ConsensusVrfWitnessPoseidonInput,
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
    pub vrf_entries: Vec<ConsensusVrfWitnessEntry>,
    pub vrf_outputs: Vec<String>,
    pub vrf_proofs: Vec<String>,
    pub witness_commitments: Vec<String>,
    pub reputation_roots: Vec<String>,
}

impl From<&ConsensusWitness> for BackendConsensusWitness {
    fn from(value: &ConsensusWitness) -> Self {
        Self {
            block_hash: value.block_hash.clone(),
            round: value.round,
            epoch: value.epoch,
            slot: value.slot,
            leader_proposal: value.leader_proposal.clone(),
            quorum_threshold: value.quorum_threshold,
            pre_votes: value.pre_votes.iter().map(BackendVotePower::from).collect(),
            pre_commits: value
                .pre_commits
                .iter()
                .map(BackendVotePower::from)
                .collect(),
            commit_votes: value
                .commit_votes
                .iter()
                .map(BackendVotePower::from)
                .collect(),
            quorum_bitmap_root: value.quorum_bitmap_root.clone(),
            quorum_signature_root: value.quorum_signature_root.clone(),
            vrf_outputs: value.vrf_outputs.clone(),
            vrf_proofs: value.vrf_proofs.clone(),
            witness_commitments: value.witness_commitments.clone(),
            reputation_roots: value.reputation_roots.clone(),
        }
    }
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
        vrf_entries: Vec<ConsensusVrfWitnessEntry>,
        vrf_outputs: Vec<String>,
        vrf_proofs: Vec<String>,
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
            vrf_outputs,
            vrf_proofs,
            witness_commitments,
            reputation_roots,
        }
    }

    pub(crate) fn validate_metadata(&self) -> ChainResult<()> {
        let backend = BackendConsensusWitness::from(self);
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
        let backend_witness = BackendConsensusWitness::from(self);
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
