use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::TryInto;

use rpp_crypto_vrf::{
    derive_tier_seed, verify_vrf, PoseidonVrfInput, VrfOutput as CryptoVrfOutput, VrfPublicKey,
};

pub type ValidatorId = String;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VRFOutput {
    pub validator_id: ValidatorId,
    pub output: [u8; 32],
    pub preoutput: Vec<u8>,
    pub proof: Vec<u8>,
    pub reputation_tier: u8,
    pub reputation_score: f64,
    pub timetoken_balance: u64,
    pub seed: [u8; 32],
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ValidatorLedgerEntry {
    pub stake: u64,
    pub reputation_tier: u8,
    pub reputation_score: f64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeInfo {
    pub stake: u64,
}

impl StakeInfo {
    pub fn new(stake: u64) -> Self {
        Self { stake }
    }
}

impl From<&ValidatorLedgerEntry> for StakeInfo {
    fn from(entry: &ValidatorLedgerEntry) -> Self {
        Self { stake: entry.stake }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    pub id: ValidatorId,
    pub reputation_tier: u8,
    pub reputation_score: f64,
    pub stake: u64,
    pub timetoken_balance: u64,
    pub vrf_output: [u8; 32],
    pub weight: u64,
}

impl Validator {
    pub fn voting_power(&self) -> u64 {
        self.weight
    }

    pub fn update_weight(&mut self, stake_info: StakeInfo) {
        self.stake = stake_info.stake;

        let tier_multiplier = u64::from(self.reputation_tier.max(1)).saturating_mul(100);

        let score_multiplier = {
            let rounded = (self.reputation_score * 1000.0).round();
            let clamped = if rounded.is_finite() {
                rounded.max(1.0).min(u64::MAX as f64)
            } else {
                u64::MAX as f64
            };
            clamped as u64
        };

        let timetoken_bonus = (self.timetoken_balance / 1_000_000).max(1);
        let effective_stake = stake_info.stake;

        self.weight = tier_multiplier
            .saturating_mul(score_multiplier)
            .saturating_mul(timetoken_bonus)
            .saturating_mul(effective_stake);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
    pub total_voting_power: u64,
    pub quorum_threshold: u64,
}

impl ValidatorSet {
    pub fn new(validators: Vec<Validator>) -> Self {
        Self::with_stake_lookup(validators, |_| None)
    }

    pub fn with_stake_lookup<F>(mut validators: Vec<Validator>, mut stake_lookup: F) -> Self
    where
        F: FnMut(&ValidatorId) -> Option<StakeInfo>,
    {
        for validator in &mut validators {
            let stake_info = stake_lookup(&validator.id).unwrap_or_else(|| {
                // Fall back to the validator's current stake if no external
                // information is provided.
                StakeInfo::new(validator.stake)
            });
            validator.update_weight(stake_info);
        }
        validators.sort_by(|a, b| a.id.cmp(&b.id));
        let total_voting_power = validators.iter().map(|v| v.voting_power()).sum();
        let quorum_threshold = (total_voting_power * 2) / 3 + 1;
        Self {
            validators,
            total_voting_power,
            quorum_threshold,
        }
    }

    pub fn get(&self, id: &ValidatorId) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.id == id)
    }

    pub fn voting_power(&self, id: &ValidatorId) -> u64 {
        self.get(id).map(|v| v.voting_power()).unwrap_or_default()
    }

    pub fn contains(&self, id: &ValidatorId) -> bool {
        self.get(id).is_some()
    }
}

pub fn select_validators(
    epoch: u64,
    vrf_outputs: &[VRFOutput],
    ledger_entries: &BTreeMap<ValidatorId, ValidatorLedgerEntry>,
) -> ValidatorSet {
    let mut eligible: Vec<Validator> = Vec::new();

    for output in vrf_outputs.iter() {
        let Some(entry) = ledger_entries.get(&output.validator_id) else {
            continue;
        };

        if entry.reputation_tier < 3 {
            continue;
        }

        let tier_seed = derive_tier_seed(&output.validator_id, output.timetoken_balance);
        let input = PoseidonVrfInput::new(output.seed, epoch, tier_seed);

        let public_key_bytes: [u8; 32] = match output.public_key.as_slice().try_into() {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        let public_key = match VrfPublicKey::try_from(public_key_bytes) {
            Ok(key) => key,
            Err(_) => continue,
        };

        let vrf_output =
            match CryptoVrfOutput::from_bytes(&output.output, &output.preoutput, &output.proof) {
                Ok(value) => value,
                Err(_) => continue,
            };

        if verify_vrf(&input, &public_key, &vrf_output).is_err() {
            continue;
        }

        let validator = Validator {
            id: output.validator_id.clone(),
            reputation_tier: entry.reputation_tier,
            reputation_score: entry.reputation_score,
            stake: entry.stake,
            timetoken_balance: output.timetoken_balance,
            vrf_output: output.output,
            weight: 0,
        };
        eligible.push(validator);
    }

    eligible.sort_by(|a, b| a.vrf_output.cmp(&b.vrf_output));
    ValidatorSet::with_stake_lookup(eligible, |id| ledger_entries.get(id).map(StakeInfo::from))
}

pub fn select_leader(validators: &ValidatorSet) -> Option<Validator> {
    validators.validators.iter().cloned().max_by(|a, b| {
        a.reputation_tier
            .cmp(&b.reputation_tier)
            .then_with(|| a.timetoken_balance.cmp(&b.timetoken_balance))
            .then_with(|| a.vrf_output.cmp(&b.vrf_output))
    })
}

pub fn timetoken_balances(validators: &ValidatorSet) -> BTreeMap<ValidatorId, u64> {
    validators
        .validators
        .iter()
        .map(|v| (v.id.clone(), v.timetoken_balance))
        .collect()
}
