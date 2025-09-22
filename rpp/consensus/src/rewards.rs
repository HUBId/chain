use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::validator::{Validator, ValidatorId, ValidatorSet};

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct RewardDistribution {
    pub block_height: u64,
    pub total_reward: u64,
    pub leader_bonus: u64,
    pub rewards: BTreeMap<ValidatorId, u64>,
}

impl RewardDistribution {
    pub fn reward_for(&self, validator: &ValidatorId) -> u64 {
        self.rewards.get(validator).copied().unwrap_or_default()
    }
}

pub fn distribute_rewards(
    validators: &ValidatorSet,
    leader: &Validator,
    block_height: u64,
    base_reward: u64,
    leader_bonus: f64,
) -> RewardDistribution {
    let mut distribution = RewardDistribution {
        block_height,
        total_reward: 0,
        leader_bonus: 0,
        rewards: BTreeMap::new(),
    };

    if validators.validators.is_empty() {
        return distribution;
    }

    let leader_extra = ((base_reward as f64) * leader_bonus).round() as u64;
    let total_pool = base_reward * validators.validators.len() as u64;
    distribution.total_reward = total_pool + leader_extra;
    distribution.leader_bonus = leader_extra;

    let base = base_reward;
    for validator in &validators.validators {
        distribution
            .rewards
            .insert(validator.id.clone(), base + if validator.id == leader.id { leader_extra } else { 0 });
    }

    distribution
}
