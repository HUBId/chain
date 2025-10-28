use std::fs;

use serde_json::from_slice;
use storage_firewood::state::{FirewoodState, StateError};
use storage_firewood::STORAGE_LAYOUT_VERSION;
use tempfile::tempdir;

#[test]
fn migration_dry_run_detects_pending_changes() {
    let base = tempdir().expect("temp dir");
    let storage_root = base.path().join("firewood");
    fs::create_dir_all(&storage_root).expect("create storage");

    std::env::set_var("FIREWOOD_MIGRATION_DRY_RUN", "1");
    let result = FirewoodState::open(storage_root.to_str().unwrap());
    match result {
        Err(StateError::MigrationRequired { from, to }) => {
            assert_eq!(from, 0);
            assert_eq!(to, STORAGE_LAYOUT_VERSION);
        }
        other => panic!("expected migration required, got {other:?}"),
    }
    std::env::remove_var("FIREWOOD_MIGRATION_DRY_RUN");

    let state = FirewoodState::open(storage_root.to_str().unwrap()).expect("open storage");
    drop(state);

    let layout_bytes =
        fs::read(storage_root.join("cf_meta/layout_version.json")).expect("layout bytes");
    let layout: u32 = from_slice(&layout_bytes).expect("parse layout");
    assert_eq!(layout, STORAGE_LAYOUT_VERSION);
}
