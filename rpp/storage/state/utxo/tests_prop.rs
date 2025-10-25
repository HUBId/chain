use super::*;
use proptest::prelude::*;
use std::collections::BTreeMap;

fn proptest_config() -> ProptestConfig {
    let cases = std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(48);
    ProptestConfig {
        cases,
        ..ProptestConfig::default()
    }
}

prop_compose! {
    fn arb_owner()(suffix in 0u32..10_000u32) -> Address {
        format!("owner-{suffix}")
    }
}

prop_compose! {
    fn arb_utxo_entries()(entries in prop::collection::btree_map(
            (prop::array::uniform32(any::<u8>()), any::<u32>()),
            (1u128..1_000_000u128, any::<bool>()),
            1..8)) -> Vec<(UtxoOutpoint, u128, bool)> {
        entries
            .into_iter()
            .map(|((tx, index), (amount, spent))| {
                (
                    UtxoOutpoint { tx_id: tx, index },
                    amount,
                    spent,
                )
            })
            .collect()
    }
}

fn collect_balances(records: &[UtxoRecord]) -> u128 {
    records.iter().map(|record| record.value).sum()
}

fn records_are_sorted(records: &[UtxoRecord]) -> bool {
    records
        .windows(2)
        .all(|window| window[0].outpoint.index <= window[1].outpoint.index)
}

proptest! {
    #![proptest_config(proptest_config())]
    fn utxo_state_preserves_order_and_balances(owner in arb_owner(), entries in arb_utxo_entries()) {
        let state = UtxoState::new();
        let mut expected_total = 0u128;
        let mut expected_pairs = BTreeMap::new();

        for (outpoint, amount, spent) in entries.iter().cloned() {
            state.insert(outpoint.clone(), StoredUtxo::new(owner.clone(), amount));
            expected_pairs.insert(outpoint.clone(), (amount, spent));
            if spent {
                assert!(state.remove_spent(&outpoint));
            }
        }

        for (outpoint, (amount, spent)) in expected_pairs.iter() {
            if !spent {
                expected_total = expected_total.saturating_add(*amount);
            }
            if *spent {
                assert!(state.get(outpoint).is_none());
            }
        }

        let records = state.get_for_account(&owner);
        let snapshot = state.snapshot_for_account(&owner);
        let inputs = state.select_inputs_for_owner(&owner);
        let outputs = state.unspent_outputs_for_owner(&owner);

        assert!(records_are_sorted(&records));
        assert!(records.iter().all(|record| record.value > 0));
        assert_eq!(collect_balances(&records), expected_total);
        assert_eq!(records, outputs);

        let snapshot_pairs: Vec<_> = snapshot.iter().map(|(outpoint, stored)| (outpoint.clone(), stored.clone())).collect();
        let input_pairs: Vec<_> = inputs.iter().map(|(outpoint, stored)| (outpoint.clone(), stored.clone())).collect();
        assert_eq!(snapshot_pairs, input_pairs);

        for (_, stored) in snapshot.iter() {
            assert!(!stored.is_spent());
        }
    }
}
