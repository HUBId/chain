use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::json;
use storage_firewood::pruning::FirewoodPruner;
use storage_firewood::{
    FirewoodLifecycle, LifecycleError, SnapshotManifest, Storage, StorageOptions, SyncPolicy,
    STORAGE_LAYOUT_VERSION,
};
use tempfile::TempDir;

fn decode_hex(value: &str) -> [u8; 32] {
    let bytes = hex::decode(value).expect("valid hex");
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    array
}

struct SnapshotCase {
    manifest_path: PathBuf,
    proof_path: PathBuf,
    manifest: SnapshotManifest,
    root: [u8; 32],
}

struct SnapshotFixture {
    _dir: TempDir,
    cases: Vec<SnapshotCase>,
}

impl SnapshotFixture {
    fn new() -> Self {
        let dir = TempDir::new().expect("temp dir");
        let source_dir = dir.path().join("source");
        fs::create_dir_all(&source_dir).expect("source dir");

        let mut options = StorageOptions::default();
        options.retain_snapshots = 4;
        options.sync_policy = SyncPolicy::Deferred;

        let state = Storage::open_with_options(source_dir.to_str().unwrap(), options)
            .expect("open storage");

        stage_block(
            &state,
            1,
            &[(b"accounts/alice", Some(&[1, 2, 3][..])), (b"accounts/bob", Some(&[4, 5][..]))],
        );
        stage_block(
            &state,
            2,
            &[(b"accounts/alice", None), (b"accounts/bob", Some(&[6, 7, 8][..]))],
        );
        stage_block(
            &state,
            3,
            &[(b"accounts/carol", Some(&[9][..]))],
        );

        let cases = (1..=3)
            .map(|height| capture_snapshot(&source_dir, height))
            .collect();

        Self { _dir: dir, cases }
    }
}

fn stage_block(state: &Arc<Storage>, height: u64, updates: &[(&[u8], Option<&[u8]>)] ) {
    for (key, value) in updates {
        match value {
            Some(bytes) => state.put(key.to_vec(), bytes.to_vec()),
            None => state.delete(key),
        }
    }
    let (root, proof) = state.commit_block(height).expect("commit block");
    assert!(FirewoodPruner::verify_pruned_state(root, proof.as_ref()));
}

fn capture_snapshot(base: &Path, height: u64) -> SnapshotCase {
    let id = format!("{height:020}");
    let manifest_path = base
        .join("cf_pruning_snapshots")
        .join(format!("{id}.json"));
    let proof_path = base
        .join("cf_pruning_proofs")
        .join(format!("{id}.bin"));
    let manifest_bytes = fs::read(&manifest_path).expect("manifest bytes");
    let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes).expect("parse manifest");
    let root = decode_hex(&manifest.state_root);
    SnapshotCase {
        manifest_path,
        proof_path,
        manifest,
        root,
    }
}

fn firewood_dir() -> (TempDir, PathBuf, Arc<Storage>) {
    let temp = TempDir::new().expect("temp dir");
    let path = temp.path().join("firewood");
    fs::create_dir_all(&path).expect("firewood dir");
    let storage = Storage::open(path.to_str().unwrap()).expect("open target storage");
    (temp, path, storage)
}

#[test]
fn block_ingestion_tracks_snapshots() {
    let fixture = SnapshotFixture::new();
    let (_dir, target_path, storage) = firewood_dir();
    let lifecycle = FirewoodLifecycle::new(storage.clone()).expect("lifecycle");

    for case in &fixture.cases {
        let receipt = lifecycle
            .ingest_snapshot(&case.manifest_path)
            .expect("ingest snapshot");
        assert_eq!(receipt.new_height, case.manifest.block_height);
        assert_eq!(receipt.new_root, case.root);
    }

    let status = lifecycle.status();
    let last = fixture.cases.last().expect("last case");
    assert_eq!(status.height, Some(last.manifest.block_height));
    assert_eq!(status.root, Some(last.root));

    let manifest_files: Vec<String> = fs::read_dir(target_path.join("cf_pruning_snapshots"))
        .expect("manifest dir")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    for case in &fixture.cases {
        let expected = format!("{:020}.json", case.manifest.block_height);
        assert!(manifest_files.contains(&expected));
    }
}

#[test]
fn rollback_truncates_newer_snapshots() {
    let fixture = SnapshotFixture::new();
    let (_dir, target_path, storage) = firewood_dir();
    let lifecycle = FirewoodLifecycle::new(storage.clone()).expect("lifecycle");

    for case in &fixture.cases {
        lifecycle
            .ingest_snapshot(&case.manifest_path)
            .expect("ingest snapshot");
    }

    let rollback_target = &fixture.cases[1];
    let receipt = lifecycle
        .rollback_to_snapshot(&rollback_target.manifest_path)
        .expect("rollback");
    assert_eq!(receipt.new_height, rollback_target.manifest.block_height);
    assert_eq!(receipt.new_root, rollback_target.root);

    let manifest_files: Vec<String> = fs::read_dir(target_path.join("cf_pruning_snapshots"))
        .expect("manifest dir")
        .map(|entry| entry.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();

    assert!(manifest_files.contains(&format!(
        "{:020}.json",
        fixture.cases[0].manifest.block_height
    )));
    assert!(manifest_files.contains(&format!(
        "{:020}.json",
        rollback_target.manifest.block_height
    )));
    assert!(!manifest_files.contains(&format!(
        "{:020}.json",
        fixture.cases[2].manifest.block_height
    )));
}

#[test]
fn schema_bump_is_rejected() {
    let fixture = SnapshotFixture::new();
    let first = &fixture.cases[0];

    let temp_manifest_dir = TempDir::new().expect("manifest dir");
    let manifest_copy_path = temp_manifest_dir.path().join("bumped.json");
    let mut manifest_json = serde_json::to_value(&first.manifest).expect("manifest value");
    manifest_json["layout_version"] = json!(STORAGE_LAYOUT_VERSION + 1);
    fs::write(
        &manifest_copy_path,
        serde_json::to_string_pretty(&manifest_json).expect("manifest json"),
    )
    .expect("write manifest");
    let proof_copy_path = manifest_copy_path
        .parent()
        .expect("parent")
        .join(&first.manifest.proof_file);
    fs::copy(&first.proof_path, &proof_copy_path).expect("copy proof");

    let (_dir, _target_path, storage) = firewood_dir();
    let lifecycle = FirewoodLifecycle::new(storage).expect("lifecycle");
    let err = lifecycle
        .ingest_snapshot(&manifest_copy_path)
        .expect_err("schema bump rejected");
    assert!(matches!(err, LifecycleError::LayoutVersionMismatch { .. }));
}
