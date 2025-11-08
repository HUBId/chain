//! Regression coverage for snapshot integrity failures during state sync.

use std::fs;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::SigningKey;
use parking_lot::RwLock;
use rpp_chain::runtime::node::StateSyncSessionCache;
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
    store.insert(valid_payload.to_vec(), Some(BASE64.encode([0u8; 64])));
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
fn legacy_snapshot_without_signature_streams_payload() {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();
    let chunk_size = fixture.chunk_size();

    let payload = b"legacy-manifest".to_vec();
    assert!(
        payload.len() < chunk_size,
        "payload should fit in a single chunk"
    );
    let expected_root = blake3::hash(&payload);

    let cache = StateSyncSessionCache::verified_for_tests(
        expected_root,
        chunk_size,
        1,
        Arc::new(RwLock::new(SnapshotStore::new(chunk_size))),
    );
    handle.install_state_sync_session_cache_for_tests(cache);
    handle.configure_state_sync_session_cache(Some(chunk_size + 1), None, None);
    handle.configure_state_sync_session_cache(Some(chunk_size), Some(1), Some(expected_root));

    let manifest_path = fixture.snapshot_dir().join("legacy-manifest.json");
    fs::write(&manifest_path, &payload).expect("write legacy manifest");

    let chunk = handle
        .state_sync_session_chunk(0)
        .expect("stream chunk without signature");
    assert_eq!(chunk.data, payload);
    assert_eq!(chunk.total, 1);
}

#[test]
fn snapshot_with_signature_is_served() {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();
    let chunk_size = fixture.chunk_size();

    let payload = b"signed-manifest".to_vec();
    assert!(
        payload.len() < chunk_size,
        "payload should fit in a single chunk"
    );
    let expected_root = blake3::hash(&payload);

    let cache = StateSyncSessionCache::verified_for_tests(
        expected_root,
        chunk_size,
        1,
        Arc::new(RwLock::new(SnapshotStore::new(chunk_size))),
    );
    handle.install_state_sync_session_cache_for_tests(cache);
    handle.configure_state_sync_session_cache(Some(chunk_size + 1), None, None);
    handle.configure_state_sync_session_cache(Some(chunk_size), Some(1), Some(expected_root));

    let manifest_path = fixture.snapshot_dir().join("signed-manifest.json");
    fs::write(&manifest_path, &payload).expect("write signed manifest");
    let signature_path = manifest_path.with_extension("json.sig");
    let signing_key = SigningKey::from_bytes(&[0xAA; 32]);
    let signature = signing_key.sign(&payload);
    fs::write(&signature_path, BASE64.encode(signature.to_bytes()))
        .expect("write manifest signature");

    let chunk = handle
        .state_sync_session_chunk(0)
        .expect("stream chunk with signature");
    assert_eq!(chunk.data, payload);
    assert_eq!(chunk.total, 1);
}
