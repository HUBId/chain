use serde::{Deserialize, Serialize};

use crate::bft_loop::ConsensusMessage;
use crate::state::register_message_sender;
use crate::validator::{StakeInfo, ValidatorId};
use crate::{ConsensusError, ConsensusResult};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceType {
    DoubleSign { height: u64 },
    FalseProof { block_hash: String },
    VoteWithholding { round: u64 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub reporter: ValidatorId,
    pub accused: ValidatorId,
    pub evidence: EvidenceType,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Evidence {
    pub record: EvidenceRecord,
}

pub fn submit_evidence(record: EvidenceRecord) -> ConsensusResult<()> {
    if let Some(sender) = register_message_sender(None) {
        sender
            .send(ConsensusMessage::Evidence(record))
            .map_err(|_| ConsensusError::ChannelClosed)
    } else {
        Err(ConsensusError::ChannelNotInitialized)
    }
}

pub fn slash(accused: &ValidatorId, amount: u64, state: &mut crate::state::ConsensusState) {
    if let Some(validator) = state
        .validator_set
        .validators
        .iter_mut()
        .find(|validator| &validator.id == accused)
    {
        validator.timetoken_balance = validator.timetoken_balance.saturating_sub(amount);
        validator.reputation_tier = validator.reputation_tier.saturating_sub(1);
        validator.update_weight(StakeInfo::new(validator.stake));
        state.recompute_totals();
    }
}
