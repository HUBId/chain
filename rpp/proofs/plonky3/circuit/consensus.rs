use serde::{Deserialize, Serialize};

use super::Plonky3CircuitWitness;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VotePower {
    pub voter: String,
    pub weight: u64,
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
    #[serde(default)]
    pub quorum_bitmap_root: String,
    #[serde(default)]
    pub quorum_signature_root: String,
    #[serde(default)]
    pub vrf_outputs: Vec<String>,
    #[serde(default)]
    pub vrf_proofs: Vec<String>,
    #[serde(default)]
    pub witness_commitments: Vec<String>,
    #[serde(default)]
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
            vrf_outputs,
            vrf_proofs,
            witness_commitments,
            reputation_roots,
        }
    }
}

impl Plonky3CircuitWitness for ConsensusWitness {
    fn circuit(&self) -> &'static str {
        "consensus"
    }

    fn block_height(&self) -> Option<u64> {
        Some(self.round)
    }
}
