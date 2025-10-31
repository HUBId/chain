use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::bft_loop::ConsensusMessage;
use crate::state::register_message_sender;
use crate::validator::{StakeInfo, ValidatorId};
use crate::{ConsensusError, ConsensusResult};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EvidenceKind {
    DoubleSign,
    Availability,
    Witness,
    Censorship,
    Inactivity,
}

impl EvidenceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceKind::DoubleSign => "double_sign",
            EvidenceKind::Availability => "availability",
            EvidenceKind::Witness => "witness",
            EvidenceKind::Censorship => "censorship",
            EvidenceKind::Inactivity => "inactivity",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CensorshipStage {
    Prevote,
    Precommit,
    Proof,
}

impl CensorshipStage {
    pub fn as_str(self) -> &'static str {
        match self {
            CensorshipStage::Prevote => "prevote",
            CensorshipStage::Precommit => "precommit",
            CensorshipStage::Proof => "proof",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceType {
    DoubleSign {
        height: u64,
    },
    FalseProof {
        block_hash: String,
    },
    VoteWithholding {
        round: u64,
    },
    Censorship {
        round: u64,
        stage: CensorshipStage,
        consecutive_misses: u64,
    },
    Inactivity {
        round: u64,
        consecutive_misses: u64,
    },
}

impl EvidenceType {
    pub fn kind(&self) -> EvidenceKind {
        match self {
            EvidenceType::DoubleSign { .. } => EvidenceKind::DoubleSign,
            EvidenceType::FalseProof { .. } => EvidenceKind::Availability,
            EvidenceType::VoteWithholding { .. } => EvidenceKind::Witness,
            EvidenceType::Censorship { .. } => EvidenceKind::Censorship,
            EvidenceType::Inactivity { .. } => EvidenceKind::Inactivity,
        }
    }
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EvidenceCounts {
    pub double_signs: usize,
    pub availability: usize,
    pub witness: usize,
    pub censorship: usize,
    pub inactivity: usize,
}

#[derive(Clone, Debug, Default)]
pub struct EvidencePipeline {
    double_signs: VecDeque<EvidenceRecord>,
    availability: VecDeque<EvidenceRecord>,
    witness: VecDeque<EvidenceRecord>,
    censorship: VecDeque<EvidenceRecord>,
    inactivity: VecDeque<EvidenceRecord>,
}

impl EvidencePipeline {
    pub fn push(&mut self, record: EvidenceRecord) {
        match record.evidence.kind() {
            EvidenceKind::DoubleSign => self.double_signs.push_back(record),
            EvidenceKind::Availability => self.availability.push_back(record),
            EvidenceKind::Witness => self.witness.push_back(record),
            EvidenceKind::Censorship => self.censorship.push_back(record),
            EvidenceKind::Inactivity => self.inactivity.push_back(record),
        }
    }

    pub fn pop(&mut self) -> Option<EvidenceRecord> {
        if let Some(record) = self.double_signs.pop_front() {
            return Some(record);
        }
        if let Some(record) = self.availability.pop_front() {
            return Some(record);
        }
        if let Some(record) = self.censorship.pop_front() {
            return Some(record);
        }
        if let Some(record) = self.witness.pop_front() {
            return Some(record);
        }
        self.inactivity.pop_front()
    }

    pub fn iter(&self) -> impl Iterator<Item = &EvidenceRecord> {
        self.double_signs
            .iter()
            .chain(self.availability.iter())
            .chain(self.censorship.iter())
            .chain(self.witness.iter())
            .chain(self.inactivity.iter())
    }

    pub fn is_empty(&self) -> bool {
        self.double_signs.is_empty()
            && self.availability.is_empty()
            && self.witness.is_empty()
            && self.censorship.is_empty()
            && self.inactivity.is_empty()
    }

    pub fn len(&self) -> usize {
        self.double_signs.len()
            + self.availability.len()
            + self.witness.len()
            + self.censorship.len()
            + self.inactivity.len()
    }

    pub fn counts(&self) -> EvidenceCounts {
        EvidenceCounts {
            double_signs: self.double_signs.len(),
            availability: self.availability.len(),
            witness: self.witness.len(),
            censorship: self.censorship.len(),
            inactivity: self.inactivity.len(),
        }
    }

    pub fn drain(&mut self) -> Vec<EvidenceRecord> {
        let mut drained = Vec::with_capacity(self.len());
        while let Some(record) = self.pop() {
            drained.push(record);
        }
        drained
    }
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
