//! Regression coverage for snapshot integrity failures during state sync.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use blake3::Hash;
use ed25519_dalek::Signer;
use parking_lot::RwLock;
use rpp_chain::config::SnapshotSigningKey;
use rpp_chain::runtime::node::{StateSyncChunkError, StateSyncSessionCache};
use rpp_p2p::SnapshotStore;
use sha2::{Digest, Sha256};

#[path = "support/mod.rs"]
mod support;

use support::StateSyncFixture;

fn configure_snapshot_session(
    handle: &rpp_chain::node::NodeHandle,
    expected_root: Hash,
    chunk_size: usize,
    total_chunks: usize,
) {
    let store = SnapshotStore::new(chunk_size);
    let cache = StateSyncSessionCache::verified_for_tests(
        expected_root,
        chunk_size,
        total_chunks,
        Arc::new(RwLock::new(store)),
    );
    handle.install_state_sync_session_cache_for_tests(cache);

    let bogus_root = blake3::hash(b"bogus-state-sync-root");
    handle.configure_state_sync_session_cache(None, None, Some(bogus_root));
    handle.configure_state_sync_session_cache(
        Some(chunk_size),
        Some(total_chunks),
        Some(expected_root),
    );
}

#[derive(Debug)]
struct SnapshotManifestFiles {
    manifest_path: PathBuf,
    signature_path: PathBuf,
    chunk_path: PathBuf,
    manifest_bytes: Vec<u8>,
    root: Hash,
}

fn write_signature(signature_path: &Path, signing_key: &SnapshotSigningKey, payload: &[u8]) {
    write_signature_with_version(signature_path, signing_key, payload, signing_key.version);
}

fn write_signature_with_version(
    signature_path: &Path,
    signing_key: &SnapshotSigningKey,
    payload: &[u8],
    version: u32,
) {
    let signature = signing_key.signing_key.sign(payload);
    let encoded = BASE64.encode(signature.to_bytes());
    let versioned = format!("{version}:{encoded}");
    fs::write(signature_path, versioned).expect("write snapshot signature");
}

fn write_snapshot_manifest_with_version(
    snapshot_dir: &Path,
    chunk_name: &str,
    chunk_bytes: &[u8],
    version: u32,
) -> SnapshotManifestFiles {
    let chunk_dir = snapshot_dir.join("chunks");
    fs::create_dir_all(&chunk_dir).expect("chunk directory");
    let chunk_path = chunk_dir.join(chunk_name);
    fs::write(&chunk_path, chunk_bytes).expect("write snapshot chunk");

    let mut hasher = Sha256::new();
    hasher.update(chunk_bytes);
    let checksum = hex::encode(hasher.finalize());

    let manifest = serde_json::json!({
        "version": version,
        "generated_at": "1970-01-01T00:00:00Z",
        "segments": [
            {
                "segment_name": chunk_name,
                "size_bytes": chunk_bytes.len(),
                "sha256": checksum,
                "status": "available",
            }
        ],
    });

    let manifest_dir = snapshot_dir.join("manifest");
    fs::create_dir_all(&manifest_dir).expect("manifest directory");
    let manifest_path = manifest_dir.join("chunks.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).expect("encode manifest");
    fs::write(&manifest_path, &manifest_bytes).expect("write snapshot manifest");

    let mut signature_path = manifest_path.clone();
    let mut sig_name = manifest_path
        .file_name()
        .expect("manifest file name")
        .to_os_string();
    sig_name.push(".sig");
    signature_path.set_file_name(sig_name);

    let root = blake3::hash(&manifest_bytes);

    SnapshotManifestFiles {
        manifest_path,
        signature_path,
        chunk_path,
        manifest_bytes,
        root,
    }
}

fn write_snapshot_manifest(
    snapshot_dir: &Path,
    chunk_name: &str,
    chunk_bytes: &[u8],
) -> SnapshotManifestFiles {
    write_snapshot_manifest_with_version(snapshot_dir, chunk_name, chunk_bytes, 1)
}

#[test]
fn corrupted_snapshot_payload_yields_explicit_failure() {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();
    let signing_key = fixture.snapshot_signing_key();

    let chunk_size = fixture.chunk_size();
    let total_chunks = fixture.chunk_count();
    assert!(
        total_chunks > 0,
        "state sync fixture must produce at least one chunk"
    );

    let snapshot_dir = fixture.snapshot_dir();
    let files = write_snapshot_manifest(
        snapshot_dir,
        "fixture-snapshot.bin",
        b"state-sync-snapshot-fixture",
    );
    configure_snapshot_session(&handle, files.root, chunk_size, total_chunks);

    write_signature(&files.signature_path, &signing_key, &files.manifest_bytes);

    fs::write(&files.manifest_path, b"corrupted-snapshot-payload")
        .expect("overwrite snapshot payload with corruption");

    let result = handle.state_sync_session_chunk(0);
    let err = result.expect_err("corrupted snapshot should not produce a chunk");
    let message = format!("{err:?}");
    assert!(
        message.contains("snapshot payload for root"),
        "unexpected error message: {message}"
    );
    assert!(
        !message.contains("ProofError::Empty"),
        "corruption should not surface as ProofError::Empty: {message}"
    );
}

#[test]
fn state_sync_rejects_snapshot_without_signature() {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();

    let chunk_size = fixture.chunk_size();
    let total_chunks = fixture.chunk_count();
    assert!(
        total_chunks > 0,
        "state sync fixture must produce at least one chunk"
    );

    let snapshot_dir = fixture.snapshot_dir();
    let files = write_snapshot_manifest(
        snapshot_dir,
        "legacy-snapshot.bin",
        b"legacy-state-sync-snapshot",
    );
    configure_snapshot_session(&handle, files.root, chunk_size, total_chunks);

    if files.signature_path.exists() {
        fs::remove_file(&files.signature_path).expect("remove pre-existing signature");
    }

    let result = handle.state_sync_session_chunk(0);
    let err = result.expect_err("missing signature should error");
    match err {
        StateSyncChunkError::Io(inner) => {
            let message = inner.to_string();
            assert!(
                message.contains("snapshot signature missing"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn state_sync_rejects_snapshot_with_invalid_signature() {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();

    let chunk_size = fixture.chunk_size();
    let total_chunks = fixture.chunk_count();
    assert!(
        total_chunks > 0,
        "state sync fixture must produce at least one chunk"
    );

    let snapshot_dir = fixture.snapshot_dir();
    let files = write_snapshot_manifest(
        snapshot_dir,
        "invalid-signature-snapshot.bin",
        b"invalid-signature-state-sync-snapshot",
    );
    configure_snapshot_session(&handle, files.root, chunk_size, total_chunks);

    fs::write(&files.signature_path, "not-base64").expect("write invalid signature");

    let result = handle.state_sync_session_chunk(0);
    let err = result.expect_err("invalid signature should error");
    match err {
        StateSyncChunkError::Io(inner) => {
            let message = inner.to_string();
            assert!(
                message.contains("invalid snapshot signature encoding"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn state_sync_normalizes_snapshot_signature_files() {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();
    let signing_key = fixture.snapshot_signing_key();

    let chunk_size = fixture.chunk_size();
    let total_chunks = fixture.chunk_count();
    assert!(
        total_chunks > 0,
        "state sync fixture must produce at least one chunk"
    );

    let snapshot_dir = fixture.snapshot_dir();
    let files = write_snapshot_manifest(
        snapshot_dir,
        "signed-snapshot.bin",
        b"signed-state-sync-snapshot",
    );
    configure_snapshot_session(&handle, files.root, chunk_size, total_chunks);
    let expected_root = files.root;
    let payload = files.manifest_bytes.clone();
    let signature_base64 = BASE64.encode(signing_key.signing_key.sign(&payload).to_bytes());

    write_signature(&files.signature_path, &signing_key, &payload);
    let versioned = fs::read_to_string(&files.signature_path).expect("read signature");
    fs::write(&files.signature_path, format!("{versioned}\n"))
        .expect("write snapshot signature payload");

    let chunk = handle
        .state_sync_session_chunk(0)
        .expect("chunk served with signature");
    assert_eq!(chunk.root, expected_root);
    assert_eq!(chunk.index, 0);
    let expected_total = if payload.is_empty() {
        0
    } else {
        ((payload.len() - 1) / chunk_size + 1) as u64
    };
    assert_eq!(chunk.total, expected_total);

    let snapshot_cache = handle.state_sync_session_snapshot();
    let store = snapshot_cache.snapshot_store.expect("store cached");
    let signature = store
        .read()
        .signature(&expected_root)
        .expect("signature lookup succeeds");
    assert_eq!(signature.as_deref(), Some(signature_base64.as_str()));
}

#[test]
fn state_sync_rejects_stale_snapshot_signature_version() {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();
    let signing_key = fixture.snapshot_signing_key();

    let chunk_size = fixture.chunk_size();
    let total_chunks = fixture.chunk_count();
    assert!(
        total_chunks > 0,
        "state sync fixture must produce at least one chunk"
    );

    let snapshot_dir = fixture.snapshot_dir();
    let files = write_snapshot_manifest(
        snapshot_dir,
        "stale-signature-snapshot.bin",
        b"stale-signature-snapshot",
    );
    configure_snapshot_session(&handle, files.root, chunk_size, total_chunks);

    let stale_version = signing_key.version.saturating_sub(1);
    let mismatched_version = if stale_version == signing_key.version {
        signing_key.version.saturating_add(1)
    } else {
        stale_version
    };
    write_signature_with_version(
        &files.signature_path,
        &signing_key,
        &files.manifest_bytes,
        mismatched_version,
    );

    let result = handle.state_sync_session_chunk(0);
    let err = result.expect_err("stale signature version should fail");
    match err {
        StateSyncChunkError::Io(inner) => {
            let message = inner.to_string();
            assert!(
                message.contains("version"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    write_signature(&files.signature_path, &signing_key, &files.manifest_bytes);

    let chunk = handle
        .state_sync_session_chunk(0)
        .expect("chunk served with rotated signature");
    assert_eq!(chunk.root, files.root);
    assert_eq!(chunk.index, 0);
}

#[test]
fn state_sync_rejects_manifest_with_chunk_checksum_mismatch() {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();
    let signing_key = fixture.snapshot_signing_key();

    let chunk_size = fixture.chunk_size();
    let total_chunks = fixture.chunk_count();
    assert!(
        total_chunks > 0,
        "state sync fixture must produce at least one chunk"
    );

    let snapshot_dir = fixture.snapshot_dir();
    let files = write_snapshot_manifest(
        snapshot_dir,
        "tampered-snapshot.bin",
        b"validator-snapshot-chunk",
    );
    configure_snapshot_session(&handle, files.root, chunk_size, total_chunks);

    write_signature(&files.signature_path, &signing_key, &files.manifest_bytes);

    fs::write(&files.chunk_path, b"tampered-chunk").expect("tamper snapshot chunk");

    let result = handle.state_sync_session_chunk(0);
    let err = result.expect_err("tampered manifest should fail");
    match err {
        StateSyncChunkError::ManifestViolation { reason } => {
            assert!(
                reason.contains("size mismatch") || reason.contains("checksum mismatch"),
                "unexpected manifest validation message: {reason}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn state_sync_rejects_manifest_with_version_mismatch() {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();
    let signing_key = fixture.snapshot_signing_key();

    let chunk_size = fixture.chunk_size();
    let total_chunks = fixture.chunk_count();
    assert!(
        total_chunks > 0,
        "state sync fixture must produce at least one chunk",
    );

    let snapshot_dir = fixture.snapshot_dir();
    let files = write_snapshot_manifest_with_version(
        snapshot_dir,
        "version-mismatch.bin",
        b"versioned-chunk",
        2,
    );
    configure_snapshot_session(&handle, files.root, chunk_size, total_chunks);

    write_signature(&files.signature_path, &signing_key, &files.manifest_bytes);

    let result = handle.state_sync_session_chunk(0);
    let err = result.expect_err("manifest version mismatch should fail");
    match err {
        StateSyncChunkError::ManifestViolation { reason } => {
            assert!(
                reason.contains("version"),
                "unexpected manifest validation message: {reason}",
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn state_sync_rejects_manifest_with_missing_chunk() {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();
    let signing_key = fixture.snapshot_signing_key();

    let chunk_size = fixture.chunk_size();
    let total_chunks = fixture.chunk_count();
    assert!(
        total_chunks > 0,
        "state sync fixture must produce at least one chunk"
    );

    let snapshot_dir = fixture.snapshot_dir();
    let files = write_snapshot_manifest(
        snapshot_dir,
        "missing-snapshot.bin",
        b"missing-snapshot-chunk",
    );
    configure_snapshot_session(&handle, files.root, chunk_size, total_chunks);

    write_signature(&files.signature_path, &signing_key, &files.manifest_bytes);

    fs::remove_file(&files.chunk_path).expect("remove snapshot chunk");

    let result = handle.state_sync_session_chunk(0);
    let err = result.expect_err("missing chunk should fail");
    match err {
        StateSyncChunkError::ManifestViolation { reason } => {
            assert!(
                reason.contains("missing"),
                "unexpected manifest validation message: {reason}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}
