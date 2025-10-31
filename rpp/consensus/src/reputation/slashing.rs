use std::collections::VecDeque;

use crate::evidence::{CensorshipStage, EvidenceKind, EvidenceRecord, EvidenceType};
use crate::validator::ValidatorId;

use super::SlashingTrigger;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SlashingKind {
    DoubleSign,
    Availability,
    Witness,
    Censorship,
    Inactivity,
}

impl SlashingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SlashingKind::DoubleSign => "double_sign",
            SlashingKind::Availability => "availability",
            SlashingKind::Witness => "witness",
            SlashingKind::Censorship => "censorship",
            SlashingKind::Inactivity => "inactivity",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SlashingSnapshot {
    pub double_signs: u64,
    pub availability_failures: u64,
    pub witness_reports: u64,
    pub censorship_events: u64,
    pub inactivity_events: u64,
}

impl SlashingSnapshot {
    pub fn total(&self) -> u64 {
        self.double_signs
            + self.availability_failures
            + self.witness_reports
            + self.censorship_events
            + self.inactivity_events
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingEvent {
    pub kind: SlashingKind,
    pub accused: ValidatorId,
    pub reporter: Option<ValidatorId>,
    pub detail: String,
}

impl SlashingEvent {
    pub fn kind(&self) -> SlashingKind {
        self.kind
    }
}

#[derive(Clone, Debug)]
pub struct SlashingHeuristics {
    snapshot: SlashingSnapshot,
    recent: VecDeque<SlashingEvent>,
    capacity: usize,
}

impl SlashingHeuristics {
    const DEFAULT_CAPACITY: usize = 64;

    pub fn new() -> Self {
        Self {
            snapshot: SlashingSnapshot::default(),
            recent: VecDeque::with_capacity(Self::DEFAULT_CAPACITY),
            capacity: Self::DEFAULT_CAPACITY,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut heuristics = Self::new();
        heuristics.capacity = capacity.max(1);
        heuristics.recent = VecDeque::with_capacity(heuristics.capacity);
        heuristics
    }

    pub fn snapshot(&self) -> SlashingSnapshot {
        self.snapshot.clone()
    }

    pub fn observe_evidence(&mut self, record: &EvidenceRecord) -> SlashingEvent {
        let kind = record.evidence.kind();
        let detail = match &record.evidence {
            EvidenceType::DoubleSign { height } => format!("height={height}"),
            EvidenceType::FalseProof { block_hash } => format!("block_hash={block_hash}"),
            EvidenceType::VoteWithholding { round } => format!("round={round}"),
            EvidenceType::Censorship {
                stage,
                consecutive_misses,
                round,
            } => format!(
                "stage={} misses={} round={round}",
                stage.as_str(),
                consecutive_misses
            ),
            EvidenceType::Inactivity {
                consecutive_misses,
                round,
            } => format!("misses={} round={round}", consecutive_misses),
        };
        let event = SlashingEvent {
            kind: kind.into(),
            accused: record.accused.clone(),
            reporter: Some(record.reporter.clone()),
            detail,
        };
        self.record_event(&event);
        event
    }

    pub fn observe_trigger(&mut self, trigger: &SlashingTrigger) -> SlashingEvent {
        let detail = format!(
            "{}:{}-{}",
            trigger.reason, trigger.window_start, trigger.window_end
        );
        let kind = if trigger.reason.starts_with("consensus_censorship") {
            SlashingKind::Censorship
        } else if trigger.reason.starts_with("consensus_inactivity") {
            SlashingKind::Inactivity
        } else {
            SlashingKind::Witness
        };
        let event = SlashingEvent {
            kind,
            accused: trigger.validator.clone(),
            reporter: None,
            detail,
        };
        self.record_event(&event);
        event
    }

    pub fn drain_recent(&mut self) -> Vec<SlashingEvent> {
        self.recent.drain(..).collect()
    }

    pub fn recent_len(&self) -> usize {
        self.recent.len()
    }

    fn record_event(&mut self, event: &SlashingEvent) {
        match event.kind {
            SlashingKind::DoubleSign => self.snapshot.double_signs += 1,
            SlashingKind::Availability => self.snapshot.availability_failures += 1,
            SlashingKind::Witness => self.snapshot.witness_reports += 1,
            SlashingKind::Censorship => self.snapshot.censorship_events += 1,
            SlashingKind::Inactivity => self.snapshot.inactivity_events += 1,
        }

        if self.recent.len() == self.capacity {
            self.recent.pop_front();
        }
        self.recent.push_back(event.clone());
    }
}

impl Default for SlashingHeuristics {
    fn default() -> Self {
        Self::new()
    }
}

impl From<EvidenceKind> for SlashingKind {
    fn from(kind: EvidenceKind) -> Self {
        match kind {
            EvidenceKind::DoubleSign => SlashingKind::DoubleSign,
            EvidenceKind::Availability => SlashingKind::Availability,
            EvidenceKind::Witness => SlashingKind::Witness,
            EvidenceKind::Censorship => SlashingKind::Censorship,
            EvidenceKind::Inactivity => SlashingKind::Inactivity,
        }
    }
}

impl Default for SlashingKind {
    fn default() -> Self {
        SlashingKind::Witness
    }
}
