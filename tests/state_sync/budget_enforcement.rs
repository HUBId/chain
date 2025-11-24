use std::time::Duration;

use futures::StreamExt;
use rpp_chain::runtime::node::StateSyncChunkError;

mod support;
use support::StateSyncFixture;

#[tokio::test]
async fn snapshot_stream_flags_slow_downloads() {
    let fixture = StateSyncFixture::with_config(|config| {
        config.snapshot_download.timetoke_budget_secs = 1;
        config.snapshot_download.uptime_budget_secs = 2;
        config.snapshot_sizing.default_chunk_size = 1;
        config.snapshot_sizing.min_chunk_size = 1;
        config.snapshot_sizing.max_chunk_size = 1;
    });

    let chunk_count = fixture.chunk_count();
    assert!(chunk_count > 1, "budget guard requires multiple chunks");

    let handle = fixture.handle();
    let server = handle.state_sync_server().expect("state sync server");
    let mut stream = server
        .stream_session()
        .await
        .expect("stream session available");

    // Consume the first chunk quickly, then delay past the timetoke budget before
    // requesting the next payload to simulate a slow download.
    let first = stream.next().await.expect("first chunk available");
    first.expect("first chunk must succeed");

    tokio::time::sleep(Duration::from_millis(1200)).await;

    let budget_error = stream.next().await.expect("stream should emit budget failure");
    match budget_error {
        Err(StateSyncChunkError::BudgetExceeded { budget, .. }) => {
            assert_eq!(budget, "timetoke");
        }
        other => panic!("unexpected stream result after delay: {other:?}"),
    }
}
