use std::borrow::Cow;
use std::sync::Arc;

use tempfile::tempdir;

use super::addresses::{AddressError, AddressManager};
use super::builder::{BuildPlan, BuilderError, TransactionBuilder};
use super::policies::{PolicyEngine, PolicyViolation};
use super::utxo_sel::{
    select_coins, CandidateUtxo, SelectionError, SelectionRequest, SelectionStrategy,
};
use super::{DraftOutput, SpendModel};
use crate::config::wallet::WalletPolicyConfig;
use crate::db::{AddressKind, PendingLockMetadata, UtxoOutpoint, UtxoRecord, WalletStore};

fn seeded_store() -> Arc<WalletStore> {
    let dir = tempdir().expect("tempdir");
    Arc::new(WalletStore::open(dir.path()).expect("open store"))
}

#[test]
fn address_manager_respects_gap_limit_until_usage_recorded() {
    let store = seeded_store();
    let manager = AddressManager::new(Arc::clone(&store), [7u8; 32], 2, 2).expect("manager");
    let first = manager.next_external_address().expect("first");
    let second = manager.next_external_address().expect("second");
    assert_ne!(first.address, second.address);
    let third = manager.next_external_address();
    assert!(matches!(third, Err(AddressError::GapLimit { .. })));
    manager
        .mark_address_used(AddressKind::External, 0, None)
        .expect("mark used");
    let third = manager.next_external_address().expect("third after usage");
    assert_ne!(third.address, second.address);
}

#[test]
fn address_manager_tracks_and_releases_locks() {
    let store = seeded_store();
    let manager = AddressManager::new(Arc::clone(&store), [3u8; 32], 2, 2).expect("manager");
    let outpoint = UtxoOutpoint::new([1u8; 32], 0);
    manager
        .lock_inputs([&outpoint], None, 1_000, None)
        .expect("lock inputs");
    assert!(manager.is_outpoint_pending(&outpoint));
    let locks = manager.pending_locks().expect("pending locks");
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].outpoint, outpoint);

    let metadata = PendingLockMetadata::new(
        "mock".into(),
        16,
        8,
        false,
        false,
        Some(256),
        None,
        None,
        None,
    );
    manager
        .attach_lock_txid([&outpoint], [9u8; 32], Some(metadata.clone()))
        .expect("attach txid");
    let updated = manager.pending_locks().expect("locks after attach");
    assert_eq!(updated[0].spending_txid, Some([9u8; 32]));
    assert_eq!(updated[0].metadata, metadata);

    let expired = manager
        .release_expired_locks(2_500, 1)
        .expect("release expired");
    assert_eq!(expired.len(), 1);
    assert!(manager.pending_locks().expect("locks").is_empty());

    manager
        .lock_inputs([&outpoint], Some([4u8; 32]), 5_000, None)
        .expect("lock again");
    let released = manager.release_inputs([&outpoint]).expect("release inputs");
    assert_eq!(released.len(), 1);
    assert!(manager.pending_locks().expect("locks").is_empty());
}

#[test]
fn coin_selection_prefers_confirmed_and_falls_back_to_unconfirmed() {
    let candidates = vec![
        CandidateUtxo::new(mock_utxo(1, 0, 30_000), 5, false),
        CandidateUtxo::new(mock_utxo(2, 0, 25_000), 2, false),
        CandidateUtxo::new(mock_utxo(3, 0, 40_000), 0, false),
        CandidateUtxo::new(mock_utxo(4, 0, 20_000), 8, true),
    ];
    let request = SelectionRequest {
        candidates: &candidates,
        amount: 40_000,
        min_confirmations: 1,
        strategy: SelectionStrategy::PreferConfirmed,
    };
    let selection = select_coins(request).expect("selection");
    assert_eq!(selection.inputs.len(), 2);
    assert_eq!(selection.inputs[0].record.outpoint.txid[0], 1);
    assert_eq!(selection.inputs[0].record.value, 30_000);
    assert_eq!(selection.inputs[1].record.value, 25_000);
    assert!(!selection.metadata.used_unconfirmed);

    let request_with_fallback = SelectionRequest {
        amount: 70_000,
        ..request
    };
    let selection_with_unconfirmed = select_coins(request_with_fallback).expect("fallback");
    assert_eq!(selection_with_unconfirmed.inputs.len(), 3);
    assert!(selection_with_unconfirmed.metadata.used_unconfirmed);

    let insufficient = SelectionRequest {
        amount: 120_000,
        ..request
    };
    assert!(matches!(
        select_coins(insufficient),
        Err(SelectionError::InsufficientFunds { .. })
    ));
}

#[test]
fn coin_selection_largest_first_prefers_high_values() {
    let candidates = vec![
        CandidateUtxo::new(mock_utxo(5, 0, 10_000), 3, false),
        CandidateUtxo::new(mock_utxo(6, 0, 50_000), 6, false),
        CandidateUtxo::new(mock_utxo(7, 0, 20_000), 4, false),
    ];
    let request = SelectionRequest {
        candidates: &candidates,
        amount: 45_000,
        min_confirmations: 1,
        strategy: SelectionStrategy::LargestFirst,
    };
    let selection = select_coins(request).expect("largest first");
    assert_eq!(selection.inputs.len(), 2);
    assert_eq!(selection.inputs[0].record.value, 50_000);
    assert_eq!(selection.inputs[1].record.value, 20_000);
}

#[test]
fn coin_selection_branch_and_bound_finds_tight_combination() {
    let candidates = vec![
        CandidateUtxo::new(mock_utxo(8, 0, 25_000), 4, false),
        CandidateUtxo::new(mock_utxo(9, 0, 15_000), 4, false),
        CandidateUtxo::new(mock_utxo(10, 0, 5_000), 4, false),
        CandidateUtxo::new(mock_utxo(11, 0, 30_000), 4, false),
    ];
    let request = SelectionRequest {
        candidates: &candidates,
        amount: 35_000,
        min_confirmations: 1,
        strategy: SelectionStrategy::BranchAndBoundLight,
    };
    let selection = select_coins(request).expect("branch and bound");
    let total: u128 = selection
        .inputs
        .iter()
        .map(|candidate| candidate.record.value)
        .sum();
    assert_eq!(total, 35_000);
    assert_eq!(selection.inputs.len(), 2);
}

#[test]
fn policy_engine_reports_violations() {
    let mut engine = PolicyEngine::new(2, 1_000, 1, Some(50_000));
    let outputs = vec![
        DraftOutput::new("dest", 100, false),
        DraftOutput::new("change-a", 200, true),
        DraftOutput::new("change-b", 200, true),
    ];
    let utxos = vec![CandidateUtxo::new(mock_utxo(9, 0, 10_000), 0, false)];
    let mut violations = engine.evaluate_outputs(&outputs);
    violations.extend(engine.evaluate_selection(&utxos));
    if let Some(limit) = engine.evaluate_daily_limit(60_000) {
        violations.push(limit);
    }
    assert!(violations
        .iter()
        .any(|violation| matches!(violation, PolicyViolation::DustOutput { .. })));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation, PolicyViolation::ChangeOutputDust { .. })));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation, PolicyViolation::ChangeOutputLimit { .. })));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation, PolicyViolation::InsufficientConfirmations { .. })));
    assert!(violations
        .iter()
        .any(|violation| matches!(violation, PolicyViolation::DailyLimitExceeded { .. })));
}

#[test]
fn policy_engine_enforces_dust_threshold_from_config() {
    let config = WalletPolicyConfig {
        dust_limit: 10_000,
        ..WalletPolicyConfig::default()
    };
    let engine = PolicyEngine::from_config(&config);
    let outputs = vec![DraftOutput::new("recipient", 5_000, false)];
    let violations = engine.evaluate_outputs(&outputs);
    assert!(violations
        .iter()
        .any(|violation| matches!(violation, PolicyViolation::DustOutput { threshold, .. } if *threshold == 10_000)));
}

#[test]
fn policy_engine_limits_change_outputs() {
    let mut engine = PolicyEngine::new(1, 1_000, 1, None);
    let outputs = vec![
        DraftOutput::new("dest", 2_000, false),
        DraftOutput::new("change-a", 1_100, true),
        DraftOutput::new("change-b", 1_100, true),
    ];
    let violations = engine.evaluate_outputs(&outputs);
    assert!(violations
        .iter()
        .any(|violation| matches!(violation, PolicyViolation::ChangeOutputLimit { limit, observed } if *limit == 1 && *observed == 2)));
}

#[test]
fn policy_engine_daily_limit_enforced() {
    let engine = PolicyEngine::new(1, 500, 1, Some(10_000));
    let violation = engine.evaluate_daily_limit(20_000);
    assert!(
        matches!(violation, Some(PolicyViolation::DailyLimitExceeded { limit, attempted }) if limit == 10_000 && attempted == 20_000)
    );
}

#[test]
fn builder_emits_change_when_above_dust_threshold() {
    let builder = TransactionBuilder::new(500, 2);
    let candidates = vec![
        CandidateUtxo::new(mock_utxo(5, 0, 15_000), 4, false),
        CandidateUtxo::new(mock_utxo(6, 0, 10_000), 3, false),
    ];
    let selection = select_coins(SelectionRequest {
        candidates: &candidates,
        amount: 12_000,
        min_confirmations: 1,
        strategy: SelectionStrategy::LargestFirst,
    })
    .expect("selection");
    let spend_model = SpendModel::Exact { amount: 12_000 };
    let mut outputs = vec![DraftOutput::new("recipient", 12_000, false)];
    let plan = builder
        .plan(Some(&selection), &outputs, 2, &spend_model)
        .expect("plan");
    let BuildPlan {
        fee,
        change_values,
        metadata,
    } = plan;
    assert_eq!(change_values.len(), 1);
    assert!(change_values[0] >= builder.dust_limit());
    for value in &change_values {
        outputs.push(DraftOutput::new("change", *value, true));
    }
    let built = builder
        .finalize(Some(selection), outputs, 2, fee, spend_model, metadata)
        .expect("finalize");
    assert_eq!(built.transaction.outputs.len(), 2);
    assert_eq!(built.metadata.change_outputs, 1);
    assert!(!built.metadata.change_folded_into_fee);
}

#[test]
fn builder_folds_change_when_under_dust_or_limit() {
    let builder = TransactionBuilder::new(10_000, 0);
    let candidates = vec![CandidateUtxo::new(mock_utxo(12, 0, 25_000), 5, false)];
    let selection = select_coins(SelectionRequest {
        candidates: &candidates,
        amount: 12_000,
        min_confirmations: 1,
        strategy: SelectionStrategy::LargestFirst,
    })
    .expect("selection");
    let spend_model = SpendModel::Exact { amount: 12_000 };
    let outputs = vec![DraftOutput::new("recipient", 12_000, false)];
    let plan = builder
        .plan(Some(&selection), &outputs, 2, &spend_model)
        .expect("plan");
    assert!(plan.change_values.is_empty());
    assert!(plan.metadata.change_folded_into_fee);
    assert_eq!(plan.metadata.change_outputs, 0);
}

#[test]
fn builder_rejects_insufficient_funds() {
    let builder = TransactionBuilder::new(500, 1);
    let candidates = vec![CandidateUtxo::new(mock_utxo(13, 0, 5_000), 2, false)];
    let selection = select_coins(SelectionRequest {
        candidates: &candidates,
        amount: 5_000,
        min_confirmations: 1,
        strategy: SelectionStrategy::LargestFirst,
    })
    .expect("selection");
    let outputs = vec![DraftOutput::new("recipient", 5_000, false)];
    let spend_model = SpendModel::Exact { amount: 5_000 };
    let error = builder
        .plan(Some(&selection), &outputs, 10, &spend_model)
        .expect_err("insufficient");
    assert!(matches!(error, BuilderError::InsufficientFunds { .. }));
}

fn mock_utxo(seed: u8, index: u32, value: u128) -> UtxoRecord<'static> {
    let mut txid = [0u8; 32];
    txid[0] = seed;
    UtxoRecord::new(
        UtxoOutpoint::new(txid, index),
        format!("owner-{seed}"),
        value,
        Cow::Owned(vec![0u8; 32]),
        None,
    )
}
