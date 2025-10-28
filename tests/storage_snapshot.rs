use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::from_slice;
use storage_firewood::{SnapshotManifest, Storage, StorageOptions, SyncPolicy, STORAGE_LAYOUT_VERSION};
use storage_firewood::pruning::FirewoodPruner;
use tempfile::tempdir;

fn script_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts").join(name)
}

#[test]
fn backup_and_restore_workflow() {
    let base = tempdir().expect("temp dir");
    let storage_root = base.path().join("firewood");
    fs::create_dir_all(&storage_root).expect("create storage root");

    let mut options = StorageOptions::default();
    options.retain_snapshots = 2;
    options.sync_policy = SyncPolicy::Deferred;

    let state = Storage::open_with_options(storage_root.to_str().unwrap(), options.clone())
        .expect("open storage");
    state.put(b"alpha".to_vec(), vec![1]);
    let (root1, proof1) = state.commit_block(1).expect("commit block 1");
    assert!(FirewoodPruner::verify_pruned_state(root1, proof1.as_ref()));
    state.put(b"beta".to_vec(), vec![2]);
    let (root2, proof2) = state.commit_block(2).expect("commit block 2");
    assert!(FirewoodPruner::verify_pruned_state(root2, proof2.as_ref()));
    drop(state);

    let manifest_path = storage_root.join("cf_pruning_snapshots/00000000000000000002.json");
    let manifest_bytes = fs::read(&manifest_path).expect("manifest bytes");
    let manifest: SnapshotManifest = from_slice(&manifest_bytes).expect("parse manifest");
    assert_eq!(manifest.block_height, 2);
    assert_eq!(manifest.layout_version, STORAGE_LAYOUT_VERSION);

    let proof_bytes = fs::read(storage_root.join("cf_pruning_proofs/00000000000000000002.bin"))
        .expect("proof bytes");
    assert!(manifest.checksum_matches(&proof_bytes));

    let backup_dir = base.path().join("backup");
    let status = Command::new("bash")
        .arg(script_path("backup_snapshot.sh"))
        .arg(&storage_root)
        .arg(&backup_dir)
        .status()
        .expect("run backup");
    assert!(status.success());

    fs::remove_dir_all(&storage_root).expect("clear storage");
    fs::create_dir_all(&storage_root).expect("recreate storage");

    let status = Command::new("bash")
        .arg(script_path("restore_snapshot.sh"))
        .arg(&backup_dir)
        .arg(&storage_root)
        .status()
        .expect("run restore");
    assert!(status.success());

    let state = Storage::open_with_options(storage_root.to_str().unwrap(), options)
        .expect("reopen storage");
    state.put(b"gamma".to_vec(), vec![3]);
    let (root3, proof3) = state.commit_block(3).expect("commit block 3");
    assert!(FirewoodPruner::verify_pruned_state(root3, proof3.as_ref()));

    let snapshot_files: Vec<String> = fs::read_dir(storage_root.join("cf_pruning_snapshots"))
        .expect("list manifests")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert!(snapshot_files.iter().any(|name| name.contains("00000000000000000002")));
    assert!(snapshot_files.iter().any(|name| name.contains("00000000000000000003")));
    assert!(snapshot_files
        .iter()
        .all(|name| !name.contains("00000000000000000001")));
}
