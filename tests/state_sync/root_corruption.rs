//! Regression coverage for snapshot integrity failures during state sync.

use std::fs;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use parking_lot::RwLock;
use rpp_chain::runtime::node::{StateSyncChunkError, StateSyncSessionCache};
use rpp_p2p::SnapshotStore;

#[path = "support/mod.rs"]
mod support;

use support::StateSyncFixture;

#[test]
fn corrupted_snapshot_payload_yields_explicit_failure() {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();

    let chunk_size = fixture.chunk_size();
    let total_chunks = fixture.chunk_count();
    assert!(
        total_chunks > 0,
        "state sync fixture must produce at least one chunk"
    );

    let valid_payload = b"state-sync-snapshot-fixture";
    let expected_root = blake3::hash(valid_payload);

    let mut store = SnapshotStore::new(chunk_size);
    let signature = BASE64.encode([0x11u8; 64]);
    store.insert(valid_payload.to_vec(), Some(signature));
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

    let snapshot_dir = fixture.snapshot_dir();
    fs::create_dir_all(snapshot_dir).expect("snapshot directory");
    let snapshot_path = snapshot_dir.join("fixture-snapshot.bin");
    fs::write(&snapshot_path, valid_payload).expect("write original snapshot payload");

    let mut signature_path = snapshot_path.clone();
    let mut sig_name = snapshot_path
        .file_name()
        .expect("payload file name")
        .to_os_string();
    sig_name.push(".sig");
    signature_path.set_file_name(sig_name);
    let signature_bytes = [0x24u8; 64];
    let signature_base64 = BASE64.encode(signature_bytes);
    fs::write(&signature_path, &signature_base64).expect("write snapshot signature");

    let corrupted_payload = b"corrupted-snapshot-payload";
    fs::write(&snapshot_path, corrupted_payload)
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

    let payload = b"legacy-state-sync-snapshot";
    let expected_root = blake3::hash(payload);

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

    let snapshot_dir = fixture.snapshot_dir();
    fs::create_dir_all(snapshot_dir).expect("snapshot directory");
    let payload_path = snapshot_dir.join("legacy-snapshot.bin");
    fs::write(&payload_path, payload).expect("write snapshot payload");

    let mut signature_path = payload_path.clone();
    let mut sig_name = payload_path
        .file_name()
        .expect("payload file name")
        .to_os_string();
    sig_name.push(".sig");
    signature_path.set_file_name(sig_name);
    if signature_path.exists() {
        fs::remove_file(&signature_path).expect("remove pre-existing signature");
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

    let payload = b"invalid-signature-state-sync-snapshot";
    let expected_root = blake3::hash(payload);

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

    let snapshot_dir = fixture.snapshot_dir();
    fs::create_dir_all(snapshot_dir).expect("snapshot directory");
    let payload_path = snapshot_dir.join("invalid-signature-snapshot.bin");
    fs::write(&payload_path, payload).expect("write snapshot payload");

    let mut signature_path = payload_path.clone();
    let mut sig_name = payload_path
        .file_name()
        .expect("payload file name")
        .to_os_string();
    sig_name.push(".sig");
    signature_path.set_file_name(sig_name);
    fs::write(&signature_path, "not-base64").expect("write invalid signature");

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

    let chunk_size = fixture.chunk_size();
    let total_chunks = fixture.chunk_count();
    assert!(
        total_chunks > 0,
        "state sync fixture must produce at least one chunk"
    );

    let payload = b"signed-state-sync-snapshot";
    let expected_root = blake3::hash(payload);

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

    let snapshot_dir = fixture.snapshot_dir();
    fs::create_dir_all(snapshot_dir).expect("snapshot directory");
    let payload_path = snapshot_dir.join("signed-snapshot.bin");
    fs::write(&payload_path, payload).expect("write snapshot payload");

    let mut signature_path = payload_path.clone();
    let mut sig_name = payload_path
        .file_name()
        .expect("payload file name")
        .to_os_string();
    sig_name.push(".sig");
    signature_path.set_file_name(sig_name);
    let signature_bytes = [0xA5u8; 64];
    let signature_base64 = BASE64.encode(signature_bytes);
    fs::write(&signature_path, format!("{signature_base64}\n"))
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
