//! Regression coverage for snapshot integrity failures during state sync.

use std::fs;
use std::sync::Arc;

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
    store.insert(valid_payload.to_vec(), vec![0; 64]);
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
