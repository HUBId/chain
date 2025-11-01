use std::collections::BTreeMap;

use rpp_consensus::rewards::distribute_rewards;
use rpp_consensus::state::{TreasuryAccounts, WitnessPoolWeights};
use rpp_consensus::validator::{Validator, ValidatorSet};

fn validator(id: &str) -> Validator {
    Validator {
        id: id.to_string(),
        reputation_tier: 5,
        reputation_score: 0.9,
        stake: 1_000,
        timetoken_balance: 0,
        vrf_output: [0u8; 32],
        weight: 1,
    }
}

#[test]
fn witness_rewards_split_between_treasury_and_fees() {
    let validators = vec![validator("leader"), validator("witness")];
    let validator_set = ValidatorSet::new(validators.clone());
    let leader = validators[0].clone();

    let accounts = TreasuryAccounts::new(
        "treasury-validator".into(),
        "treasury-witness".into(),
        "treasury-fees".into(),
    );
    let weights = WitnessPoolWeights::new(0.7, 0.3);

    let mut distribution =
        distribute_rewards(&validator_set, &leader, 10, 100, 0.2, &accounts, &weights);

    let mut witness = BTreeMap::new();
    witness.insert(validators[1].id.clone(), 40);
    distribution.apply_witness_rewards(witness);

    let validator_total = distribution.validator_total();
    assert_eq!(distribution.validator_treasury_debit, validator_total);

    assert_eq!(distribution.witness_treasury_debit, 28);
    assert_eq!(distribution.witness_fee_debit, 12);

    let expected_total = validator_total + 40;
    assert_eq!(distribution.total_reward, expected_total);
    assert_eq!(distribution.witness_reward_for(&validators[1].id), 40);
    assert_eq!(
        distribution.treasury_accounts.witness_account(),
        "treasury-witness"
    );
}
