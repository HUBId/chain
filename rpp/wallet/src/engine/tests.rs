use std::borrow::Cow;
use std::sync::Arc;

use tempfile::tempdir;

use super::addresses::{AddressError, AddressManager};
use super::builder::TransactionBuilder;
use super::policies::{PolicyEngine, PolicyViolation};
use super::utxo_sel::{select_coins, CandidateUtxo, SelectionError};
use super::{DraftOutput, SpendModel};
use crate::config::wallet::WalletPolicyConfig;
use crate::db::{AddressKind, UtxoOutpoint, UtxoRecord, WalletStore};

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
        .mark_address_used(AddressKind::External, 0)
        .expect("mark used");
    let third = manager.next_external_address().expect("third after usage");
    assert_ne!(third.address, second.address);
}

#[test]
fn coin_selection_prefers_confirmed_and_skips_pending() {
    let candidates = vec![
        CandidateUtxo::new(mock_utxo(1, 0, 30_000), 5, false),
        CandidateUtxo::new(mock_utxo(2, 0, 25_000), 2, false),
        CandidateUtxo::new(mock_utxo(3, 0, 40_000), 0, false),
        CandidateUtxo::new(mock_utxo(4, 0, 20_000), 8, true),
    ];
    let selection = select_coins(&candidates, 40_000, 1).expect("selection");
    assert_eq!(selection.len(), 2);
    assert_eq!(selection[0].record.outpoint.txid[0], 1);
    assert_eq!(selection[0].record.value, 30_000);
    assert_eq!(selection[1].record.value, 25_000);
    assert!(matches!(
        select_coins(&candidates, 70_000, 6),
        Err(SelectionError::InsufficientFunds { .. })
    ));
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
    let builder = TransactionBuilder::new(500);
    let selection = vec![
        CandidateUtxo::new(mock_utxo(5, 0, 15_000), 4, false),
        CandidateUtxo::new(mock_utxo(6, 0, 10_000), 3, false),
    ];
    let mut outputs = vec![DraftOutput::new("recipient", 12_000, false)];
    let total_in: u128 = selection
        .iter()
        .map(|candidate| candidate.record.value)
        .sum();
    let fee_with_change = builder.estimate_fee(selection.len(), outputs.len() + 1, 2);
    let change_value = total_in - outputs[0].value - fee_with_change;
    assert!(change_value >= builder.dust_limit());
    outputs.push(DraftOutput::new("change", change_value, true));
    let draft = builder.assemble(
        selection,
        outputs,
        2,
        fee_with_change,
        SpendModel::Exact { amount: 12_000 },
    );
    assert_eq!(draft.outputs.len(), 2);
    assert!(draft.outputs.iter().any(|output| output.change));
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
