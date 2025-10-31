use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::state::{TreasuryAccounts, WitnessPoolWeights};
use crate::validator::{Validator, ValidatorId, ValidatorSet};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RewardDistribution {
    pub block_height: u64,
    pub total_reward: u64,
    pub leader_bonus: u64,
    pub rewards: BTreeMap<ValidatorId, u64>,
    pub witness_rewards: BTreeMap<ValidatorId, u64>,
    pub treasury_accounts: TreasuryAccounts,
    pub witness_pool_weights: WitnessPoolWeights,
    pub validator_treasury_debit: u64,
    pub witness_treasury_debit: u64,
    pub witness_fee_debit: u64,
}

impl RewardDistribution {
    pub fn reward_for(&self, validator: &ValidatorId) -> u64 {
        self.rewards.get(validator).copied().unwrap_or_default()
    }

    pub fn witness_reward_for(&self, witness: &ValidatorId) -> u64 {
        self.witness_rewards
            .get(witness)
            .copied()
            .unwrap_or_default()
    }

    pub fn apply_witness_rewards(&mut self, rewards: BTreeMap<ValidatorId, u64>) {
        self.witness_rewards = rewards;
        let total: u64 = self.witness_rewards.values().copied().sum();
        let (treasury, fees) = self.witness_pool_weights.split(total);
        self.witness_treasury_debit = treasury;
        self.witness_fee_debit = fees;
        self.total_reward = self.total_reward.saturating_add(total);
    }

    pub fn validator_total(&self) -> u64 {
        self.rewards.values().copied().sum()
    }
}

pub fn distribute_rewards(
    validators: &ValidatorSet,
    leader: &Validator,
    block_height: u64,
    base_reward: u64,
    leader_bonus: f64,
    treasury_accounts: &TreasuryAccounts,
    witness_pool_weights: &WitnessPoolWeights,
) -> RewardDistribution {
    let mut distribution = RewardDistribution {
        block_height,
        total_reward: 0,
        leader_bonus: 0,
        rewards: BTreeMap::new(),
        witness_rewards: BTreeMap::new(),
        treasury_accounts: treasury_accounts.clone(),
        witness_pool_weights: *witness_pool_weights,
        validator_treasury_debit: 0,
        witness_treasury_debit: 0,
        witness_fee_debit: 0,
    };

    if validators.validators.is_empty() {
        return distribution;
    }

    let leader_extra = ((base_reward as f64) * leader_bonus).round() as u64;
    let total_pool = base_reward * validators.validators.len() as u64;
    distribution.total_reward = total_pool + leader_extra;
    distribution.leader_bonus = leader_extra;
    distribution.validator_treasury_debit = distribution.total_reward;

    let base = base_reward;
    for validator in &validators.validators {
        distribution.rewards.insert(
            validator.id.clone(),
            base + if validator.id == leader.id {
                leader_extra
            } else {
                0
            },
        );
    }

    distribution
}
