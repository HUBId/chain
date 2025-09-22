use blake3::Hasher;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::validator::ValidatorId;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BlockId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    pub epoch: u64,
    pub payload: Value,
    pub timestamp: u64,
}

impl Block {
    pub fn hash(&self) -> BlockId {
        let mut hasher = Hasher::new();
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        let payload = serde_json::to_vec(&self.payload).unwrap_or_default();
        hasher.update(&payload);
        BlockId(hasher.finalize().to_hex().to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusProof {
    pub commitment: String,
    pub witness_hash: String,
    pub recursion_depth: u32,
    pub valid: bool,
}

impl ConsensusProof {
    pub fn verify(&self) -> bool {
        self.valid && !self.commitment.is_empty() && !self.witness_hash.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub block: Block,
    pub proof: ConsensusProof,
    pub leader_id: ValidatorId,
}

impl Proposal {
    pub fn block_hash(&self) -> BlockId {
        self.block.hash()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreVote {
    pub block_hash: BlockId,
    pub proof_valid: bool,
    pub validator_id: ValidatorId,
    pub round: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreCommit {
    pub block_hash: BlockId,
    pub validator_id: ValidatorId,
    pub round: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub validator_id: ValidatorId,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub block: Block,
    pub proof: ConsensusProof,
    pub signatures: Vec<Signature>,
}
