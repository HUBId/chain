fn treasury_accounts() -> TreasuryAccounts {
    TreasuryAccounts::new(
        "treasury-validator".into(),
        "treasury-witness".into(),
        "fee-pool".into(),
    )
}

fn witness_weights(treasury: f64, fees: f64) -> WitnessPoolWeights {
    WitnessPoolWeights::new(treasury, fees)
}

#[test]
fn validator_rewards_debit_validator_treasury_first() {
    let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
    ledger.configure_reward_pools(treasury_accounts(), witness_weights(0.7, 0.3));

    let treasury = Account::new("treasury-validator".into(), 120, Stake::default());
    ledger.upsert_account(treasury).expect("insert treasury");
    let fee_pool = Account::new("fee-pool".into(), 50, Stake::default());
    ledger.upsert_account(fee_pool).expect("insert fee pool");

    ledger
        .reward_proposer("validator-a", 30)
        .expect("apply reward");

    assert_eq!(
        ledger.get_account("treasury-validator").unwrap().balance,
        90
    );
    assert_eq!(ledger.get_account("fee-pool").unwrap().balance, 50);
    assert_eq!(
        ledger.get_account("validator-a").unwrap().balance,
        30
    );
}

#[test]
fn witness_payouts_follow_pool_weights() {
    let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
    ledger.configure_reward_pools(treasury_accounts(), witness_weights(0.4, 0.6));

    let witness_treasury = Account::new("treasury-witness".into(), 80, Stake::default());
    ledger
        .upsert_account(witness_treasury)
        .expect("insert witness treasury");
    let fee_pool = Account::new("fee-pool".into(), 100, Stake::default());
    ledger.upsert_account(fee_pool).expect("insert fee pool");

    let mut payouts = BTreeMap::new();
    payouts.insert("witness-1".into(), 50u64);

    ledger
        .distribute_witness_payouts(&payouts)
        .expect("distribute witness rewards");

    // 40% of 50 = 20 from treasury, 30 from fees.
    assert_eq!(
        ledger.get_account("treasury-witness").unwrap().balance,
        60
    );
    assert_eq!(ledger.get_account("fee-pool").unwrap().balance, 70);
    assert_eq!(ledger.get_account("witness-1").unwrap().balance, 50);
    assert_eq!(ledger.reward_shortfall(), 0);
}

#[test]
fn reward_shortfall_records_uncovered_amounts() {
    let ledger = Ledger::new(DEFAULT_EPOCH_LENGTH);
    ledger.configure_reward_pools(treasury_accounts(), witness_weights(0.5, 0.5));

    let validator_treasury = Account::new("treasury-validator".into(), 5, Stake::default());
    ledger
        .upsert_account(validator_treasury)
        .expect("insert validator treasury");
    let fee_pool = Account::new("fee-pool".into(), 3, Stake::default());
    ledger.upsert_account(fee_pool).expect("insert fee pool");

    ledger
        .reward_proposer("validator-b", 10)
        .expect("apply partial reward");

    // Only 8 units available -> shortfall of 2.
    assert_eq!(ledger.get_account("treasury-validator").unwrap().balance, 0);
    assert_eq!(ledger.get_account("fee-pool").unwrap().balance, 0);
    assert_eq!(ledger.reward_shortfall(), 2);
    assert_eq!(ledger.get_account("validator-b").unwrap().balance, 8);
}
