use std::fmt;

pub mod bft_loop;
pub mod evidence;
pub mod leader;
pub mod messages;
pub mod rewards;
pub mod state;
pub mod validator;

pub use bft_loop::{
    finalize_block, run_bft_loop, shutdown, submit_precommit, submit_prevote, submit_proposal,
};
pub use evidence::{submit_evidence, Evidence, EvidenceRecord, EvidenceType};
pub use leader::{Leader, LeaderContext};
pub use messages::{Block, Commit, ConsensusProof, PreCommit, PreVote, Proposal, Signature};
pub use rewards::{distribute_rewards, RewardDistribution};
pub use state::{ConsensusConfig, ConsensusState, GenesisConfig};
pub use validator::{
    select_leader, select_validators, VRFOutput, Validator, ValidatorId, ValidatorLedgerEntry,
    ValidatorSet,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusError {
    ChannelNotInitialized,
    ChannelClosed,
    InvalidValidator(String),
    InvalidProposal(String),
}

impl fmt::Display for ConsensusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusError::ChannelNotInitialized => write!(f, "consensus channel not initialized"),
            ConsensusError::ChannelClosed => write!(f, "consensus channel closed"),
            ConsensusError::InvalidValidator(msg) => write!(f, "invalid validator: {}", msg),
            ConsensusError::InvalidProposal(msg) => write!(f, "invalid proposal: {}", msg),
        }
    }
}

impl std::error::Error for ConsensusError {}

pub type ConsensusResult<T> = Result<T, ConsensusError>;

#[cfg(test)]
mod tests;
