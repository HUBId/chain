use crate::config::wallet::WalletPolicyConfig;
use crate::db::UtxoOutpoint;
use serde::Serialize;

use super::{CandidateUtxo, DraftOutput};

#[derive(Clone, Debug)]
pub struct PolicyEngine {
    min_confirmations: u32,
    dust_limit: u128,
    max_change_outputs: u32,
    daily_limit: Option<u128>,
}

impl PolicyEngine {
    pub fn new(
        min_confirmations: u32,
        dust_limit: u128,
        max_change_outputs: u32,
        daily_limit: Option<u128>,
    ) -> Self {
        Self {
            min_confirmations,
            dust_limit,
            max_change_outputs,
            daily_limit,
        }
    }

    pub fn from_config(config: &WalletPolicyConfig) -> Self {
        Self::new(
            config.min_confirmations,
            config.dust_limit,
            config.max_change_outputs,
            config.spend_limit_daily,
        )
    }

    pub fn min_confirmations(&self) -> u32 {
        self.min_confirmations
    }

    pub fn dust_limit(&self) -> u128 {
        self.dust_limit
    }

    pub fn max_change_outputs(&self) -> u32 {
        self.max_change_outputs
    }

    pub fn daily_limit(&self) -> Option<u128> {
        self.daily_limit
    }

    pub fn set_daily_limit(&mut self, limit: Option<u128>) {
        self.daily_limit = limit;
    }

    pub fn evaluate_selection(&self, utxos: &[CandidateUtxo]) -> Vec<PolicyViolation> {
        utxos
            .iter()
            .filter(|candidate| candidate.confirmations < self.min_confirmations)
            .map(|candidate| PolicyViolation::InsufficientConfirmations {
                outpoint: candidate.record.outpoint.clone(),
                confirmations: candidate.confirmations,
                required: self.min_confirmations,
            })
            .collect()
    }

    pub fn evaluate_outputs(&self, outputs: &[DraftOutput]) -> Vec<PolicyViolation> {
        let mut violations: Vec<PolicyViolation> = outputs
            .iter()
            .filter(|output| output.value < self.dust_limit)
            .map(|output| {
                if output.change {
                    PolicyViolation::ChangeOutputDust {
                        address: output.address.clone(),
                        value: output.value,
                        threshold: self.dust_limit,
                    }
                } else {
                    PolicyViolation::DustOutput {
                        address: output.address.clone(),
                        value: output.value,
                        threshold: self.dust_limit,
                    }
                }
            })
            .collect();

        let change_count = outputs.iter().filter(|output| output.change).count() as u32;
        if change_count > self.max_change_outputs {
            violations.push(PolicyViolation::ChangeOutputLimit {
                limit: self.max_change_outputs,
                observed: change_count,
            });
        }

        violations
    }

    pub fn evaluate_daily_limit(&self, amount: u128) -> Option<PolicyViolation> {
        self.daily_limit.and_then(|limit| {
            if amount > limit {
                Some(PolicyViolation::DailyLimitExceeded {
                    limit,
                    attempted: amount,
                })
            } else {
                None
            }
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Clone, Debug, Serialize, PartialEq, Eq)]
pub enum PolicyViolation {
    DustOutput {
        address: String,
        value: u128,
        threshold: u128,
    },
    ChangeOutputDust {
        address: String,
        value: u128,
        threshold: u128,
    },
    ChangeOutputLimit {
        limit: u32,
        observed: u32,
    },
    InsufficientConfirmations {
        outpoint: UtxoOutpoint,
        confirmations: u32,
        required: u32,
    },
    DailyLimitExceeded {
        limit: u128,
        attempted: u128,
    },
}
