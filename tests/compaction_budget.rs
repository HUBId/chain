use std::fs;

use serde_json::Value;
use storage_firewood::{Storage, StorageOptions, SyncPolicy};
use tempfile::tempdir;

#[test]
fn telemetry_records_budgets() {
    let base = tempdir().expect("temp dir");
    let storage_root = base.path().join("firewood");
    fs::create_dir_all(&storage_root).expect("create storage");

    let mut options = StorageOptions::default();
    options.commit_io_budget_bytes = 1024;
    options.compaction_io_budget_bytes = 2048;
    options.sync_policy = SyncPolicy::Deferred;

    let state = Storage::open_with_options(storage_root.to_str().unwrap(), options.clone())
        .expect("open storage");
    state.put(b"alpha".to_vec(), vec![42]);
    let _ = state.commit_block(1).expect("commit block");

    let telemetry_path = storage_root.join("cf_meta/telemetry.json");
    let telemetry_bytes = fs::read(&telemetry_path).expect("telemetry bytes");
    let telemetry: Value = serde_json::from_slice(&telemetry_bytes).expect("parse telemetry");

    assert_eq!(
        telemetry["commit_budget_bytes"].as_u64().expect("commit budget"),
        options.commit_io_budget_bytes,
    );
    assert_eq!(
        telemetry["compaction_budget_bytes"].as_u64().expect("compaction budget"),
        options.compaction_io_budget_bytes,
    );
    assert!(telemetry["snapshot_bytes"].as_u64().expect("snapshot bytes") > 0);
    assert!(telemetry["proof_bytes"].as_u64().expect("proof bytes") > 0);
}
