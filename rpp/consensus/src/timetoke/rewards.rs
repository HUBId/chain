use std::collections::BTreeMap;

use crate::governance::TimetokeRewardGovernance;

use super::TimetokeRecord;

/// Allocation result for a single Timetoke reward pool.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TimetokeRewardPoolPayout {
    pub budget: u64,
    pub allocations: BTreeMap<String, u64>,
}

impl TimetokeRewardPoolPayout {
    pub fn reward_for(&self, identity: &str) -> u64 {
        self.allocations.get(identity).copied().unwrap_or_default()
    }

    pub fn total_allocated(&self) -> u64 {
        self.allocations.values().copied().sum()
    }

    pub fn is_empty(&self) -> bool {
        self.allocations.is_empty()
    }
}

/// Timetoke reward distribution across leader and witness pools.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TimetokeRewardDistribution {
    pub leader: TimetokeRewardPoolPayout,
    pub witness: TimetokeRewardPoolPayout,
    pub remainder: u64,
}

/// Splits the `total_reward` across leader and witness pools according to the
/// supplied governance policy and Timetoke records.
pub fn distribute_timetoke_rewards(
    governance: &TimetokeRewardGovernance,
    total_reward: u64,
    leader_records: &[TimetokeRecord],
    witness_records: &[TimetokeRecord],
) -> TimetokeRewardDistribution {
    if !governance.enabled() || total_reward == 0 {
        return TimetokeRewardDistribution::default();
    }

    let budgets = governance.budgets(total_reward);
    let minimum = governance.minimum_balance_hours();

    TimetokeRewardDistribution {
        leader: distribute_pool(budgets.leader, leader_records, minimum),
        witness: distribute_pool(budgets.witness, witness_records, minimum),
        remainder: budgets.remainder,
    }
}

fn distribute_pool(
    budget: u64,
    records: &[TimetokeRecord],
    minimum_balance_hours: u64,
) -> TimetokeRewardPoolPayout {
    let mut payout = TimetokeRewardPoolPayout {
        budget,
        allocations: BTreeMap::new(),
    };

    if budget == 0 {
        return payout;
    }

    let threshold = minimum_balance_hours as u128;
    let mut eligible: Vec<&TimetokeRecord> = records
        .iter()
        .filter(|record| record.balance >= threshold)
        .collect();

    if eligible.is_empty() {
        return payout;
    }

    eligible.sort_by(|a, b| a.identity.cmp(&b.identity));
    let total_weight: u128 = eligible.iter().map(|record| record.balance).sum();
    if total_weight == 0 {
        return payout;
    }

    let mut allocated = 0u64;
    for (index, record) in eligible.iter().enumerate() {
        let amount = if index + 1 == eligible.len() {
            budget.saturating_sub(allocated)
        } else {
            let numerator = (budget as u128).saturating_mul(record.balance);
            (numerator / total_weight) as u64
        };

        if amount > 0 {
            payout.allocations.insert(record.identity.clone(), amount);
            allocated = allocated.saturating_add(amount);
        }
    }

    payout
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::TimetokeRewardGovernance;
    use crate::timetoke::TimetokeRecord;

    fn record(identity: &str, balance: u64) -> TimetokeRecord {
        TimetokeRecord {
            identity: identity.into(),
            balance: balance as u128,
            epoch_accrual: 0,
            decay_rate: 1.0,
            last_update: 0,
            last_sync: 0,
            last_decay: 0,
        }
    }

    #[test]
    fn pool_distribution_skips_ineligible_entries() {
        let governance = TimetokeRewardGovernance::new(true, 0.6, 0.3, 2);
        governance.validate().expect("policy should validate");
        let records = vec![record("a", 1), record("b", 9), record("c", 10)];
        let payout = distribute_pool(1_000, &records, governance.minimum_balance_hours());
        assert_eq!(payout.total_allocated(), 1_000);
        assert_eq!(payout.reward_for("a"), 0);
        assert!(payout.reward_for("c") > payout.reward_for("b"));
    }
}
