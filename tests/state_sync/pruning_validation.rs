use std::collections::HashMap;

use serde_json::from_str;
use storage::snapshots::{known_snapshot_sets, SnapshotEntry};
use storage_firewood::pruning::{PersistedPrunerSnapshot, PersistedPrunerState};

fn load_recorded_receipts() -> PersistedPrunerState {
    let raw = include_str!("fixtures/pruning_receipts.json");
    from_str(raw).expect("decode pruning receipts fixture")
}

fn snapshot_map(receipts: &[PersistedPrunerSnapshot]) -> HashMap<u64, [u8; 32]> {
    receipts
        .iter()
        .map(|snapshot| (snapshot.block_height(), snapshot.state_commitment()))
        .collect()
}

fn assert_snapshot_present(expected: &SnapshotEntry, recorded: &mut HashMap<u64, [u8; 32]>) {
    let actual = recorded.remove(&expected.block_height).unwrap_or_else(|| {
        panic!(
            "missing pruning receipt for block {}",
            expected.block_height
        )
    });
    assert_eq!(
        actual, expected.state_commitment,
        "state commitment mismatch for block {}",
        expected.block_height
    );
}

#[test]
fn pruning_receipts_align_with_snapshot_metadata() {
    let receipts = load_recorded_receipts();
    let mut recorded_snapshots = snapshot_map(&receipts.snapshots);

    let metadata_sets = known_snapshot_sets();
    assert!(
        !metadata_sets.is_empty(),
        "snapshot metadata must define at least one dataset"
    );

    let matching_set = metadata_sets
        .iter()
        .find(|set| {
            set.schema_digest == receipts.schema_digest
                && set.parameter_digest == receipts.parameter_digest
        })
        .expect("recorded receipts must match a known snapshot dataset");

    assert_eq!(
        matching_set.layout_version, receipts.layout_version,
        "layout versions diverged"
    );
    assert!(
        receipts.retain >= matching_set.snapshots.len(),
        "pruner retention is insufficient for advertised snapshots"
    );
    assert_eq!(
        matching_set.snapshots.len(),
        receipts.snapshots.len(),
        "snapshot count mismatch between metadata and receipts"
    );

    for snapshot in matching_set.snapshots {
        assert_snapshot_present(snapshot, &mut recorded_snapshots);
    }

    assert!(
        recorded_snapshots.is_empty(),
        "unexpected pruning receipts discovered for unknown block heights"
    );
}
