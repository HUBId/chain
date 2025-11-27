use std::collections::{HashMap, HashSet};
use std::panic;

use serde_json::from_str;
use storage::snapshots::{known_snapshot_sets, CrossShardLink, SnapshotEntry};
use storage_firewood::pruning::{
    CrossShardReference, PersistedPrunerSnapshot, PersistedPrunerState,
};

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

fn cross_reference_map(
    receipts: &[PersistedPrunerSnapshot],
) -> HashMap<u64, Vec<CrossShardReference>> {
    receipts
        .iter()
        .map(|snapshot| {
            (
                snapshot.block_height(),
                snapshot.cross_references().to_vec(),
            )
        })
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

fn assert_cross_links_present(
    expected_height: u64,
    expected: &[CrossShardLink],
    recorded: Vec<CrossShardReference>,
) {
    let mut recorded_set: HashSet<(String, String, u64)> = recorded
        .into_iter()
        .map(|link| (link.shard, link.partition, link.block_height))
        .collect();
    for link in expected {
        let expected_tuple = (
            link.shard.to_string(),
            link.partition.to_string(),
            link.block_height,
        );
        if !recorded_set.remove(&expected_tuple) {
            panic!(
                "missing cross-shard reference {}:{} at {} for snapshot {}",
                link.shard, link.partition, link.block_height, expected_height
            );
        }
    }

    assert!(
        recorded_set.is_empty(),
        "unexpected cross-shard references recorded for snapshot {}: {:?}",
        expected_height,
        recorded_set
    );
}

fn assert_receipts_match_metadata(receipts: PersistedPrunerState) {
    let mut recorded_snapshots = snapshot_map(&receipts.snapshots);
    let mut recorded_references = cross_reference_map(&receipts.snapshots);

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
        let recorded_links = recorded_references
            .remove(&snapshot.block_height)
            .unwrap_or_default();
        assert_cross_links_present(
            snapshot.block_height,
            snapshot.cross_shard_links,
            recorded_links,
        );
    }

    assert!(
        recorded_snapshots.is_empty(),
        "unexpected pruning receipts discovered for unknown block heights"
    );
    assert!(
        recorded_references.is_empty(),
        "unexpected cross-shard references discovered for unknown block heights"
    );
}

#[test]
fn pruning_receipts_align_with_snapshot_metadata() {
    let receipts = load_recorded_receipts();
    assert_receipts_match_metadata(receipts);
}

#[test]
fn pruning_rejects_dangling_cross_shard_references() {
    let mut receipts = load_recorded_receipts();
    receipts
        .snapshots
        .get_mut(0)
        .expect("first snapshot present")
        .cross_references_mut()
        .push(CrossShardReference {
            shard: "archive-c".to_string(),
            partition: "partition-9".to_string(),
            block_height: 99_999,
        });

    let result = panic::catch_unwind(|| assert_receipts_match_metadata(receipts));
    assert!(
        result.is_err(),
        "dangling cross-shard references should fail validation"
    );
}
