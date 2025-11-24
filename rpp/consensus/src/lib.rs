//! Consensus engine coordinating the validator set and proof backends.
//!
//! # STWO feature toggles
//! * `prover-stwo` enables the STWO backend for real proof verification.
//! * `prover-stwo-simd` layers on `prover-stwo` and allows the STWO fork to use
//!   its SIMD optimisations. Enable it when the runtime environment guarantees
//!   the necessary vector extensions; omit it to rely on the portable scalar
//!   implementation.
//! * `prover-mock` replaces the prover with a mock implementation for
//!   simulation-heavy workflows.
//!
//! Toggling these options only requires adjusting Cargo feature flags; no code
//! snippets or manual wiring is needed.
#![deny(clippy::panic, clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(test, allow(clippy::panic, clippy::unwrap_used, clippy::expect_used))]
use std::fmt;

#[cfg(all(
    feature = "prover-stwo",
    feature = "prover-mock",
    not(feature = "unstable-all-provers"),
))]
compile_error!("features `prover-stwo` and `prover-mock` are mutually exclusive");

pub use prover_backend_interface as proof_backend;

#[cfg(feature = "prover-stwo")]
pub use prover_stwo_backend;

pub mod bft_loop;
pub mod evidence;
pub mod governance;
pub mod leader;
pub mod malachite;
pub mod messages;
pub mod network;
pub mod proofs;
pub mod reputation;
pub mod rewards;
pub mod state;
pub mod timetoke;
pub mod validator;

pub use bft_loop::{
    finalize_block, run_bft_loop, shutdown, submit_precommit, submit_prevote, submit_proposal,
};
pub use evidence::{
    submit_evidence, Evidence, EvidenceKind, EvidencePipeline, EvidenceRecord, EvidenceType,
};
pub use governance::{TimetokeRewardBudgets, TimetokeRewardGovernance};
pub use leader::{Leader, LeaderContext};
pub use messages::{
    Block, Commit, ConsensusCertificate, ConsensusProof, ConsensusProofMetadata,
    ConsensusProofMetadataVrf, ConsensusWitnessBindings, ConsensusWitnessBundle, PreCommit,
    PreVote, ProofVerificationError, Proposal, Signature,
};
pub use proofs::build_consensus_witness;
pub use reputation::{
    MalachiteReputationManager, SlashingEvent, SlashingHeuristics, SlashingKind, SlashingSnapshot,
    SlashingTrigger, UptimeObservation, UptimeOutcome,
};
pub use rewards::{distribute_rewards, RewardDistribution};
pub use state::{ConsensusConfig, ConsensusState, GenesisConfig};
pub use timetoke::{
    distribute_timetoke_rewards, TimetokeRecord, TimetokeReplayError, TimetokeReplayValidator,
    TimetokeRewardDistribution, TimetokeRewardPoolPayout, TimetokeSnapshot,
    TimetokeSnapshotConsumer, TimetokeSnapshotError, TimetokeSnapshotHandle,
    TimetokeSnapshotProducer,
};
pub use validator::{
    select_leader, select_validators, StakeInfo, VRFOutput, Validator, ValidatorId,
    ValidatorLedgerEntry, ValidatorSet,
};

pub mod vrf {
    pub use rpp_crypto_vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};
}

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
