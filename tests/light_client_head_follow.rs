#![cfg(feature = "it_state_sync")]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::{routing::get, Router};
use base64::engine::general_purpose::STANDARD as BASE64_ENGINE;
use base64::Engine as _;
use blake3::Hash as Blake3Hash;
use futures::{StreamExt, TryStreamExt};
use rpp_chain::api::{
    routes, ApiContext, ErrorResponse, RpcMetricsLayer, StateSyncChunkResponse,
    StateSyncStatusResponse,
};
use rpp_chain::runtime::metrics::RuntimeMetrics;
use rpp_chain::runtime::node::StateSyncSessionCache;
use rpp_chain::runtime::sync::RuntimeRecursiveProofVerifier;
use rpp_chain::runtime::RuntimeMode;
use rpp_p2p::{LightClientSync, SnapshotStore};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[path = "state_sync/support/mod.rs"]
mod support;

use support::StateSyncFixture;

const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn light_client_head_follow_streams_chunks() -> Result<()> {
    let fixture = StateSyncFixture::new();
    let handle = fixture.handle();
    let chunk_size = fixture.chunk_size();
    let total_chunks = fixture.chunk_count();
    assert!(total_chunks > 0, "state sync fixture must produce chunks");

    let snapshot_root = Blake3Hash::from(fixture.snapshot_root());
    let store = Arc::new(parking_lot::RwLock::new(SnapshotStore::new(chunk_size)));
    let cache = StateSyncSessionCache::verified_for_tests(
        snapshot_root,
        chunk_size,
        total_chunks,
        store.clone(),
    );
    handle.install_state_sync_session_cache_for_tests(cache);

    let metrics = RuntimeMetrics::noop();
    let context = ApiContext::new(
        Arc::new(parking_lot::RwLock::new(RuntimeMode::Node)),
        Some(handle.clone()),
        None,
        None,
        None,
        false,
        None,
        None,
        false,
    )
    .with_metrics(metrics.clone())
    .with_state_sync_api(Arc::new(handle.clone()))
    .with_state_sync_server(
        handle
            .state_sync_server()
            .expect("state sync server available"),
    );

    let app = Router::new()
        .route("/state-sync/plan", get(routes::state_sync_plan))
        .route(
            "/state-sync/session",
            get(routes::state_sync::session_status),
        )
        .route(
            "/state-sync/session/stream",
            get(routes::state_sync::session_stream),
        )
        .route(
            "/state-sync/head/stream",
            get(routes::state_sync::head_stream),
        )
        .layer(RpcMetricsLayer::new(metrics))
        .with_state(context);

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .context("bind test listener")?;
    let addr = listener.local_addr().context("retrieve listener address")?;
    let server = axum::serve(listener, app.into_make_service());
    let server_handle = tokio::spawn(server);

    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .build()
        .context("build client")?;

    let base = format!("http://{addr}");
    let plan: rpp_p2p::NetworkStateSyncPlan = client
        .get(format!("{base}/state-sync/plan"))
        .send()
        .await
        .context("request state sync plan")?
        .error_for_status()
        .context("state sync plan status")?
        .json()
        .await
        .context("decode state sync plan")?;

    let verifier = Arc::new(RuntimeRecursiveProofVerifier::default());
    let mut light_client = LightClientSync::new(verifier);
    let mut head_rx = light_client.subscribe_light_client_heads();
    assert!(head_rx.borrow().is_none(), "head subscription starts empty");

    let plan_bytes = serde_json::to_vec(&plan).context("encode plan")?;
    light_client
        .ingest_plan(&plan_bytes)
        .context("ingest plan payload")?;

    let stream_response = client
        .get(format!("{base}/state-sync/session/stream"))
        .send()
        .await
        .context("open session stream")?
        .error_for_status()
        .context("session stream status")?;

    let mut stream = stream_response.bytes_stream().map_err(anyhow::Error::from);
    let mut buffer = Vec::new();
    let mut received_chunks = 0usize;
    let expected_chunks = total_chunks;
    while let Some(chunk) = stream.try_next().await? {
        buffer.extend_from_slice(&chunk);

        while let Some((event, data)) = next_sse_event(&mut buffer)? {
            match event.as_deref() {
                Some("status") => {
                    let status: StateSyncStatusResponse =
                        serde_json::from_str(&data).context("decode status event")?;
                    assert_eq!(
                        status.total_chunks.unwrap_or_default() as usize,
                        expected_chunks,
                        "status should report expected chunk count",
                    );
                }
                Some("chunk") => {
                    let payload: StateSyncChunkResponse =
                        serde_json::from_str(&data).context("decode chunk event")?;
                    let bytes = BASE64_ENGINE
                        .decode(payload.chunk.payload.as_bytes())
                        .context("decode chunk payload")?;
                    light_client
                        .ingest_chunk(&bytes)
                        .context("ingest streamed chunk")?;
                    received_chunks += 1;
                    if received_chunks == expected_chunks {
                        break;
                    }
                }
                Some("error") => {
                    let error: ErrorResponse =
                        serde_json::from_str(&data).context("decode error event")?;
                    anyhow::bail!("state sync stream error: {}", error.error);
                }
                _ => {}
            }
        }

        if received_chunks == expected_chunks {
            break;
        }
    }

    assert_eq!(received_chunks, expected_chunks, "all chunks streamed");

    let updates = fixture
        .state_sync_plan()
        .light_client_messages()
        .context("collect light client updates")?;
    for update in updates.iter() {
        let bytes = serde_json::to_vec(update).context("encode light client update")?;
        light_client
            .ingest_light_client_update(&bytes)
            .context("ingest light client update")?;
    }

    timeout(REQUEST_TIMEOUT, head_rx.changed())
        .await
        .context("await head update")??;
    let latest = head_rx
        .borrow()
        .clone()
        .context("head should be available")?;
    let expected_height = updates
        .last()
        .map(|update| update.height)
        .expect("updates available");
    assert_eq!(latest.height, expected_height, "head height should advance");

    let verified = light_client.verify().context("verify snapshot")?;
    assert!(verified, "light client verification should succeed");

    server_handle.abort();
    Ok(())
}

fn next_sse_event(buffer: &mut Vec<u8>) -> Result<Option<(Option<String>, String)>> {
    if let Some(position) = find_event_boundary(buffer) {
        let mut segment: Vec<u8> = buffer.drain(..position).collect();
        // Remove trailing newline separators.
        while segment
            .last()
            .map(|b| *b == b'\n' || *b == b'\r')
            .unwrap_or(false)
        {
            segment.pop();
        }
        let text = String::from_utf8(segment).context("invalid SSE frame")?;
        let mut event = None;
        let mut data = VecDeque::new();
        for line in text.lines() {
            if line.starts_with(':') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("event:") {
                event = Some(rest.trim().to_owned());
            } else if let Some(rest) = line.strip_prefix("data:") {
                data.push_back(rest.trim_end().to_owned());
            }
        }
        let payload = data.into_iter().collect::<Vec<_>>().join("\n");
        return Ok(Some((event, payload)));
    }
    Ok(None)
}

fn find_event_boundary(buffer: &mut Vec<u8>) -> Option<usize> {
    let mut index = 0;
    while index + 1 < buffer.len() {
        if buffer[index] == b'\n' && buffer[index + 1] == b'\n' {
            // Drain boundary on subsequent call by including both newlines.
            return Some(index + 2);
        }
        if index + 3 < buffer.len() && buffer[index..index + 4] == [b'\r', b'\n', b'\r', b'\n'] {
            return Some(index + 4);
        }
        index += 1;
    }
    None
}
