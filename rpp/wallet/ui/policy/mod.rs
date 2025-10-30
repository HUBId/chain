use std::fmt;

use crate::reputation::Tier;

/// Limits enforced for a tiered UTXO spend evaluation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TieredSpendLimit {
    pub max_inputs: usize,
    pub max_debit_value: u128,
    pub max_change_value: u128,
}

impl TieredSpendLimit {
    pub fn for_tier(tier: Tier) -> Self {
        match tier {
            Tier::Tl0 => Self {
                max_inputs: 1,
                max_debit_value: 50_000,
                max_change_value: 0,
            },
            Tier::Tl1 => Self {
                max_inputs: 2,
                max_debit_value: 100_000,
                max_change_value: 10_000,
            },
            Tier::Tl2 => Self {
                max_inputs: 4,
                max_debit_value: 250_000,
                max_change_value: 50_000,
            },
            Tier::Tl3 => Self {
                max_inputs: 6,
                max_debit_value: 1_000_000,
                max_change_value: 100_000,
            },
            Tier::Tl4 => Self {
                max_inputs: 8,
                max_debit_value: 5_000_000,
                max_change_value: 500_000,
            },
            Tier::Tl5 => Self {
                max_inputs: 16,
                max_debit_value: u128::MAX,
                max_change_value: u128::MAX,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleKind {
    MaxInputs,
    MaxDebitValue,
    MaxChangeValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitValue {
    Inputs(usize),
    Value(u128),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TieredRuleViolation {
    pub tier: Tier,
    pub rule: RuleKind,
    pub limit: LimitValue,
    pub observed: LimitValue,
}

impl fmt::Display for TieredRuleViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rule = match self.rule {
            RuleKind::MaxInputs => "utxo input count",
            RuleKind::MaxDebitValue => "total debit",
            RuleKind::MaxChangeValue => "change value",
        };
        let limit = match self.limit {
            LimitValue::Inputs(limit) => format!("{limit}"),
            LimitValue::Value(limit) => format!("{limit}"),
        };
        let observed = match self.observed {
            LimitValue::Inputs(observed) => format!("{observed}"),
            LimitValue::Value(observed) => format!("{observed}"),
        };
        write!(
            f,
            "tier {:?} violates {rule} policy: limit {limit}, observed {observed}",
            self.tier
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TieredEvaluation {
    pub tier: Tier,
    pub limits: TieredSpendLimit,
    pub input_count: usize,
    pub debit_value: u128,
    pub change_value: u128,
}

impl TieredEvaluation {
    pub fn new(
        tier: Tier,
        limits: TieredSpendLimit,
        input_count: usize,
        debit_value: u128,
        change_value: u128,
    ) -> Self {
        Self {
            tier,
            limits,
            input_count,
            debit_value,
            change_value,
        }
    }
}

pub fn evaluate_tiered_spend(
    tier: Tier,
    input_count: usize,
    debit_value: u128,
    change_value: u128,
) -> Result<TieredEvaluation, TieredRuleViolation> {
    let limits = TieredSpendLimit::for_tier(tier);
    if input_count > limits.max_inputs {
        return Err(TieredRuleViolation {
            tier,
            rule: RuleKind::MaxInputs,
            limit: LimitValue::Inputs(limits.max_inputs),
            observed: LimitValue::Inputs(input_count),
        });
    }
    if debit_value > limits.max_debit_value {
        return Err(TieredRuleViolation {
            tier,
            rule: RuleKind::MaxDebitValue,
            limit: LimitValue::Value(limits.max_debit_value),
            observed: LimitValue::Value(debit_value),
        });
    }
    if change_value > limits.max_change_value {
        return Err(TieredRuleViolation {
            tier,
            rule: RuleKind::MaxChangeValue,
            limit: LimitValue::Value(limits.max_change_value),
            observed: LimitValue::Value(change_value),
        });
    }
    Ok(TieredEvaluation::new(
        tier,
        limits,
        input_count,
        debit_value,
        change_value,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_tl5_high_values() {
        let result = evaluate_tiered_spend(Tier::Tl5, 12, 5_000_000_000, 1_000_000_000);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_tl0_change() {
        let error = evaluate_tiered_spend(Tier::Tl0, 1, 40_000, 10_000).unwrap_err();
        assert!(matches!(error.rule, RuleKind::MaxChangeValue));
        assert_eq!(error.limit, LimitValue::Value(0));
    }
}
