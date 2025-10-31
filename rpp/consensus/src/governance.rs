use std::fmt;

const WEIGHT_TOLERANCE: f64 = 1e-9;

/// Governance policy controlling how Timetoke rewards are split between
/// consensus leaders and witness reporters.
#[derive(Debug, Clone, PartialEq)]
pub struct TimetokeRewardGovernance {
    enabled: bool,
    leader_weight: f64,
    witness_weight: f64,
    minimum_balance_hours: u64,
}

impl TimetokeRewardGovernance {
    /// Creates a new governance policy. Call [`Self::validate`] before use to
    /// ensure the configured weights and thresholds are coherent.
    pub const fn new(
        enabled: bool,
        leader_weight: f64,
        witness_weight: f64,
        minimum_balance_hours: u64,
    ) -> Self {
        Self {
            enabled,
            leader_weight,
            witness_weight,
            minimum_balance_hours,
        }
    }

    /// Verifies that the configured weights fall within the expected range.
    pub fn validate(&self) -> Result<(), GovernanceError> {
        self.validate_weight("leader_pool_weight", self.leader_weight)?;
        self.validate_weight("witness_pool_weight", self.witness_weight)?;
        if self.leader_weight + self.witness_weight > 1.0 + WEIGHT_TOLERANCE {
            return Err(GovernanceError::CombinedWeightExceedsLimit {
                leader: self.leader_weight,
                witness: self.witness_weight,
            });
        }
        if self.minimum_balance_hours == 0 {
            return Err(GovernanceError::MinimumBalanceZero);
        }
        Ok(())
    }

    fn validate_weight(&self, field: &'static str, value: f64) -> Result<(), GovernanceError> {
        if !value.is_finite() {
            return Err(GovernanceError::WeightNotFinite { field });
        }
        if !(0.0..=1.0).contains(&value) {
            return Err(GovernanceError::WeightOutOfRange { field, value });
        }
        Ok(())
    }

    /// Returns `true` when the reward pools should be allocated.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Portion of the total reward budget assigned to leaders.
    pub const fn leader_weight(&self) -> f64 {
        self.leader_weight
    }

    /// Portion of the total reward budget assigned to witnesses.
    pub const fn witness_weight(&self) -> f64 {
        self.witness_weight
    }

    /// Minimum Timetoke balance required for a validator or witness to
    /// participate in the reward pools.
    pub const fn minimum_balance_hours(&self) -> u64 {
        self.minimum_balance_hours
    }

    /// Splits `total_reward` into leader and witness budgets according to the
    /// configured weights. The remainder is returned so operators can forward it
    /// to a treasury or burn account.
    pub fn budgets(&self, total_reward: u64) -> TimetokeRewardBudgets {
        if !self.enabled || total_reward == 0 {
            return TimetokeRewardBudgets::default();
        }

        let mut leader = ((total_reward as f64) * self.leader_weight).round() as u64;
        if leader > total_reward {
            leader = total_reward;
        }

        let mut witness = ((total_reward as f64) * self.witness_weight).round() as u64;
        if leader + witness > total_reward {
            witness = total_reward.saturating_sub(leader);
        }

        let remainder = total_reward.saturating_sub(leader).saturating_sub(witness);

        TimetokeRewardBudgets {
            leader,
            witness,
            remainder,
        }
    }
}

/// Split of the total reward budget across the configured Timetoke pools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TimetokeRewardBudgets {
    pub leader: u64,
    pub witness: u64,
    pub remainder: u64,
}

/// Validation failure raised when governance parameters fall outside the
/// supported range.
#[derive(Debug, Clone, PartialEq)]
pub enum GovernanceError {
    WeightNotFinite { field: &'static str },
    WeightOutOfRange { field: &'static str, value: f64 },
    CombinedWeightExceedsLimit { leader: f64, witness: f64 },
    MinimumBalanceZero,
}

impl fmt::Display for GovernanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GovernanceError::WeightNotFinite { field } => {
                write!(f, "{field} must be a finite number")
            }
            GovernanceError::WeightOutOfRange { field, value } => {
                write!(f, "{field} must be within [0.0, 1.0], got {value}")
            }
            GovernanceError::CombinedWeightExceedsLimit { leader, witness } => write!(
                f,
                "leader+witness pool weights exceed 1.0 (leader={leader}, witness={witness})",
            ),
            GovernanceError::MinimumBalanceZero => {
                write!(f, "minimum_balance_hours must be greater than 0")
            }
        }
    }
}

impl std::error::Error for GovernanceError {}

#[cfg(test)]
mod tests {
    use super::{GovernanceError, TimetokeRewardGovernance, WEIGHT_TOLERANCE};

    #[test]
    fn governance_validation_rejects_invalid_weights() {
        let policy = TimetokeRewardGovernance::new(true, 1.2, 0.0, 1);
        assert!(matches!(
            policy.validate(),
            Err(GovernanceError::WeightOutOfRange { .. })
        ));

        let policy = TimetokeRewardGovernance::new(true, 0.7, 0.4, 1);
        assert!(matches!(
            policy.validate(),
            Err(GovernanceError::CombinedWeightExceedsLimit { .. })
        ));

        let policy = TimetokeRewardGovernance::new(true, f64::NAN, 0.2, 1);
        assert!(matches!(
            policy.validate(),
            Err(GovernanceError::WeightNotFinite { .. })
        ));

        let policy = TimetokeRewardGovernance::new(true, 0.5, 0.5, 0);
        assert!(matches!(
            policy.validate(),
            Err(GovernanceError::MinimumBalanceZero)
        ));

        let policy = TimetokeRewardGovernance::new(true, 0.6, 0.4, 1);
        assert!(policy.validate().is_ok());

        // Allow slight floating point noise near the tolerance boundary.
        let policy = TimetokeRewardGovernance::new(true, 0.6, 0.4 + WEIGHT_TOLERANCE / 2.0, 1);
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn governance_budgets_respect_weights_and_remainder() {
        let policy = TimetokeRewardGovernance::new(true, 0.6, 0.3, 1);
        policy.validate().expect("policy should validate");
        let split = policy.budgets(1_000);
        assert_eq!(split.leader, 600);
        assert_eq!(split.witness, 300);
        assert_eq!(split.remainder, 100);

        let disabled = TimetokeRewardGovernance::new(false, 0.6, 0.4, 1);
        let split = disabled.budgets(1_000);
        assert_eq!(split.leader, 0);
        assert_eq!(split.witness, 0);
        assert_eq!(split.remainder, 0);
    }
}
