use rpp_consensus::{distribute_timetoke_rewards, TimetokeRecord, TimetokeRewardGovernance};

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
fn timetoke_rewards_follow_governance_weights() {
    let governance = TimetokeRewardGovernance::new(true, 0.6, 0.3, 2);
    governance
        .validate()
        .expect("governance configuration should be valid");

    let leaders = vec![record("leader-a", 10), record("leader-b", 20)];
    let witnesses = vec![
        record("witness-a", 5),
        record("witness-b", 10),
        record("witness-c", 1),
    ];
    let rewards = distribute_timetoke_rewards(&governance, 1_000, &leaders, &witnesses);

    assert_eq!(rewards.leader.budget, 600);
    assert_eq!(rewards.leader.total_allocated(), 600);
    assert_eq!(rewards.leader.reward_for("leader-a"), 200);
    assert_eq!(rewards.leader.reward_for("leader-b"), 400);

    assert_eq!(rewards.witness.budget, 300);
    assert_eq!(rewards.witness.total_allocated(), 300);
    assert_eq!(rewards.witness.reward_for("witness-a"), 100);
    assert_eq!(rewards.witness.reward_for("witness-b"), 200);
    assert_eq!(rewards.witness.reward_for("witness-c"), 0);

    assert_eq!(rewards.remainder, 100);
}

#[test]
fn timetoke_rewards_disabled_yields_empty_distribution() {
    let governance = TimetokeRewardGovernance::new(false, 0.5, 0.4, 2);
    let rewards = distribute_timetoke_rewards(&governance, 1_000, &[], &[]);

    assert!(rewards.leader.is_empty());
    assert!(rewards.witness.is_empty());
    assert_eq!(rewards.leader.total_allocated(), 0);
    assert_eq!(rewards.witness.total_allocated(), 0);
    assert_eq!(rewards.remainder, 0);
}
