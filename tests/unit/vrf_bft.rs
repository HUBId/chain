use std::collections::BTreeMap;

use rpp_consensus::evidence::{
    CensorshipStage, EvidenceKind, EvidencePipeline, EvidenceRecord, EvidenceType,
};
use rpp_consensus::validator::{
    select_leader, StakeInfo, Validator, ValidatorLedgerEntry, ValidatorSet,
};

#[test]
fn leader_selection_prefers_highest_tier_then_output() {
    let validators = vec![
        Validator {
            id: "validator-a".into(),
            reputation_tier: 3,
            reputation_score: 1.0,
            stake: 100,
            timetoken_balance: 1_000_000,
            vrf_output: [5; 32],
            weight: 0,
        },
        Validator {
            id: "validator-b".into(),
            reputation_tier: 4,
            reputation_score: 1.0,
            stake: 100,
            timetoken_balance: 1_000_000,
            vrf_output: [4; 32],
            weight: 0,
        },
    ];

    let ledger = BTreeMap::from([
        (
            "validator-a".into(),
            ValidatorLedgerEntry {
                stake: 100,
                reputation_tier: 3,
                reputation_score: 1.0,
            },
        ),
        (
            "validator-b".into(),
            ValidatorLedgerEntry {
                stake: 100,
                reputation_tier: 4,
                reputation_score: 1.0,
            },
        ),
    ]);

    let set = ValidatorSet::with_stake_lookup(validators, |id| {
        ledger.get(id).cloned().map(|entry| StakeInfo::from(&entry))
    });
    assert_eq!(set.validators.len(), 2);

    let leader = select_leader(&set).expect("leader");
    assert_eq!(leader.id, "validator-b");
    assert!(leader.vrf_output <= [5; 32]);
}

#[test]
fn evidence_pipeline_prioritises_double_signs() {
    let mut pipeline = EvidencePipeline::default();
    let double_sign = EvidenceRecord {
        reporter: "alice".into(),
        accused: "bob".into(),
        evidence: EvidenceType::DoubleSign { height: 42 },
    };
    let censorship = EvidenceRecord {
        reporter: "alice".into(),
        accused: "carol".into(),
        evidence: EvidenceType::Censorship {
            round: 1,
            stage: CensorshipStage::Prevote,
            consecutive_misses: 2,
        },
    };
    let inactivity = EvidenceRecord {
        reporter: "dave".into(),
        accused: "erin".into(),
        evidence: EvidenceType::Inactivity {
            round: 3,
            consecutive_misses: 5,
        },
    };

    pipeline.push(censorship.clone());
    pipeline.push(double_sign.clone());
    pipeline.push(inactivity.clone());

    let first = pipeline.pop().expect("first record");
    assert_eq!(first.evidence.kind(), EvidenceKind::DoubleSign);
    let second = pipeline.pop().expect("second record");
    assert_eq!(second.evidence.kind(), EvidenceKind::Censorship);
    let third = pipeline.pop().expect("third record");
    assert_eq!(third.evidence.kind(), EvidenceKind::Inactivity);
    assert!(pipeline.is_empty());
}

#[test]
fn validator_weights_follow_ledger_updates() {
    let validators = vec![
        Validator {
            id: "node-1".into(),
            reputation_tier: 3,
            reputation_score: 1.2,
            stake: 50,
            timetoken_balance: 2_000_000,
            vrf_output: [7; 32],
            weight: 0,
        },
        Validator {
            id: "node-2".into(),
            reputation_tier: 3,
            reputation_score: 1.2,
            stake: 75,
            timetoken_balance: 2_000_000,
            vrf_output: [8; 32],
            weight: 0,
        },
    ];

    let ledger = BTreeMap::from([
        (
            "node-1".into(),
            ValidatorLedgerEntry {
                stake: 50,
                reputation_tier: 3,
                reputation_score: 1.2,
            },
        ),
        (
            "node-2".into(),
            ValidatorLedgerEntry {
                stake: 500,
                reputation_tier: 3,
                reputation_score: 1.2,
            },
        ),
    ]);

    let set = ValidatorSet::with_stake_lookup(validators, |id| {
        ledger.get(id).cloned().map(|entry| StakeInfo::from(&entry))
    });

    let weight_node1 = set.voting_power(&"node-1".into());
    let weight_node2 = set.voting_power(&"node-2".into());
    assert!(weight_node2 > weight_node1);
}
