use std::collections::{BTreeMap, HashMap};

use tracing::{info, warn};

use crate::validator::{ValidatorId, ValidatorLedgerEntry};

pub mod slashing;

pub use slashing::{SlashingEvent, SlashingHeuristics, SlashingKind, SlashingSnapshot};

const MAX_UPTIME_HOURS: u64 = 720;
const TIER2_THRESHOLD: u64 = 24;
const TIER3_THRESHOLD: u64 = 72;
const TIER4_THRESHOLD: u64 = 168;
const TIER5_THRESHOLD: u64 = MAX_UPTIME_HOURS;

#[derive(Clone, Debug, Default)]
struct ValidatorReputation {
    uptime_hours: u64,
    score: f64,
    tier: u8,
    last_window_end: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UptimeObservation {
    pub validator: ValidatorId,
    pub window_start: u64,
    pub window_end: u64,
}

impl UptimeObservation {
    pub fn new(validator: ValidatorId, window_start: u64, window_end: u64) -> Self {
        Self {
            validator,
            window_start,
            window_end,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SlashingTrigger {
    pub validator: ValidatorId,
    pub reason: String,
    pub window_start: u64,
    pub window_end: u64,
}

impl SlashingTrigger {
    fn new(validator: &ValidatorId, reason: impl Into<String>, start: u64, end: u64) -> Self {
        Self {
            validator: validator.clone(),
            reason: reason.into(),
            window_start: start,
            window_end: end,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct UptimeOutcome {
    pub validator: ValidatorId,
    pub credited_hours: Option<u64>,
    pub new_score: Option<f64>,
    pub new_tier: Option<u8>,
    pub slashing_trigger: Option<SlashingTrigger>,
}

pub struct MalachiteReputationManager {
    ledger: BTreeMap<ValidatorId, ValidatorLedgerEntry>,
    records: HashMap<ValidatorId, ValidatorReputation>,
    slashing_triggers: Vec<SlashingTrigger>,
}

impl MalachiteReputationManager {
    pub fn new(ledger: BTreeMap<ValidatorId, ValidatorLedgerEntry>) -> Self {
        let mut records = HashMap::new();
        for (validator, entry) in &ledger {
            let mut reputation = ValidatorReputation::default();
            reputation.tier = entry.reputation_tier;
            reputation.score = entry.reputation_score;
            reputation.uptime_hours = match entry.reputation_tier {
                0 => 0,
                1 => 1,
                2 => TIER2_THRESHOLD,
                3 => TIER3_THRESHOLD,
                4 => TIER4_THRESHOLD,
                _ => TIER5_THRESHOLD,
            };
            records.insert(validator.clone(), reputation);
        }

        Self {
            ledger,
            records,
            slashing_triggers: Vec::new(),
        }
    }

    pub fn ledger(&self) -> &BTreeMap<ValidatorId, ValidatorLedgerEntry> {
        &self.ledger
    }

    pub fn reputation_of(&self, validator: &ValidatorId) -> Option<&ValidatorReputation> {
        self.records.get(validator)
    }

    pub fn uptime_hours_of(&self, validator: &ValidatorId) -> Option<u64> {
        self.records
            .get(validator)
            .map(|record| record.uptime_hours)
    }

    pub fn slashing_triggers(&self) -> &[SlashingTrigger] {
        &self.slashing_triggers
    }

    pub fn take_slashing_triggers(&mut self) -> Vec<SlashingTrigger> {
        std::mem::take(&mut self.slashing_triggers)
    }

    pub fn ingest_observation(&mut self, observation: UptimeObservation) -> UptimeOutcome {
        let mut outcome = UptimeOutcome {
            validator: observation.validator.clone(),
            ..Default::default()
        };

        if observation.window_end <= observation.window_start {
            let trigger = SlashingTrigger::new(
                &observation.validator,
                "uptime_window_invalid",
                observation.window_start,
                observation.window_end,
            );
            warn!(
                validator = %observation.validator,
                reason = %trigger.reason,
                "rejected uptime observation"
            );
            self.slashing_triggers.push(trigger.clone());
            outcome.slashing_trigger = Some(trigger);
            return outcome;
        }

        let entry = self
            .records
            .entry(observation.validator.clone())
            .or_insert_with(ValidatorReputation::default);

        if observation.window_start < entry.last_window_end {
            let trigger = SlashingTrigger::new(
                &observation.validator,
                "uptime_window_overlap",
                observation.window_start,
                observation.window_end,
            );
            warn!(
                validator = %observation.validator,
                reason = %trigger.reason,
                "detected overlapping uptime proof"
            );
            self.slashing_triggers.push(trigger.clone());
            outcome.slashing_trigger = Some(trigger);
            return outcome;
        }

        let credited_hours = (observation.window_end - observation.window_start) / 3_600;
        if credited_hours == 0 {
            let trigger = SlashingTrigger::new(
                &observation.validator,
                "uptime_window_too_small",
                observation.window_start,
                observation.window_end,
            );
            warn!(
                validator = %observation.validator,
                reason = %trigger.reason,
                "ignored uptime observation with insufficient coverage"
            );
            self.slashing_triggers.push(trigger.clone());
            outcome.slashing_trigger = Some(trigger);
            return outcome;
        }

        entry.last_window_end = observation.window_end;
        entry.uptime_hours = entry
            .uptime_hours
            .saturating_add(credited_hours)
            .min(MAX_UPTIME_HOURS);
        entry.score = compute_score(entry.uptime_hours);
        entry.tier = tier_for_hours(entry.uptime_hours);

        let ledger_entry = self
            .ledger
            .entry(observation.validator.clone())
            .or_insert_with(|| ValidatorLedgerEntry {
                stake: 0,
                reputation_tier: 0,
                reputation_score: 0.0,
            });
        ledger_entry.reputation_tier = entry.tier;
        ledger_entry.reputation_score = entry.score;

        outcome.credited_hours = Some(credited_hours);
        outcome.new_score = Some(entry.score);
        outcome.new_tier = Some(entry.tier);

        info!(
            validator = %observation.validator,
            credited_hours,
            uptime_hours = entry.uptime_hours,
            score = entry.score,
            tier = entry.tier,
            "ingested uptime observation",
        );

        outcome
    }
}

fn compute_score(hours: u64) -> f64 {
    (hours.min(MAX_UPTIME_HOURS) as f64) / (MAX_UPTIME_HOURS as f64)
}

fn tier_for_hours(hours: u64) -> u8 {
    if hours >= TIER5_THRESHOLD {
        5
    } else if hours >= TIER4_THRESHOLD {
        4
    } else if hours >= TIER3_THRESHOLD {
        3
    } else if hours >= TIER2_THRESHOLD {
        2
    } else if hours > 0 {
        1
    } else {
        0
    }
}
