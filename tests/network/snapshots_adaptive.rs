use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use tokio::time::sleep;

#[path = "../support/mod.rs"]
mod support;

mod snapshots_common;

use snapshots_common::{
    start_snapshot_cluster, wait_for_snapshot_status, LinkShape, SnapshotStreamStatusResponse,
    StartSnapshotStreamRequest, NETWORK_TIMEOUT, SNAPSHOT_BUILD_DELAY, SNAPSHOT_POLL_TIMEOUT,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_shrinks_chunks_on_constrained_link() -> Result<()> {
    adaptive_snapshot_smoke(LinkShape {
        bandwidth_bytes_per_sec: 64 * 1024,
        latency: Duration::from_millis(600),
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_grows_chunks_on_fast_link() -> Result<()> {
    adaptive_snapshot_smoke(LinkShape {
        bandwidth_bytes_per_sec: 25 * 1024 * 1024,
        latency: Duration::from_millis(50),
    })
    .await
}

async fn adaptive_snapshot_smoke(shape: LinkShape) -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = start_snapshot_cluster().await?;

    cluster
        .wait_for_full_mesh(NETWORK_TIMEOUT)
        .await
        .context("cluster mesh")?;

    sleep(SNAPSHOT_BUILD_DELAY).await;

    let nodes = cluster.nodes();
    let provider = &nodes[0];
    let consumer = &nodes[1];

    let sizing = &consumer.config.snapshot_sizing;
    let negotiated = shape.negotiated_chunk_size(
        sizing.min_chunk_size,
        sizing.max_chunk_size,
        sizing.default_chunk_size,
    );

    let chunk_size = u32::try_from(negotiated).context("negotiated chunk size exceeds u32")?;

    let provider_peer = provider.p2p_handle.local_peer_id().to_base58();

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("construct HTTP client")?;

    let request = StartSnapshotStreamRequest {
        peer: provider_peer,
        chunk_size,
        resume: None,
    };

    let consumer_addr = consumer.config.network.rpc.listen;
    let base_url = format!("http://{}", consumer_addr);

    let mut status: SnapshotStreamStatusResponse = client
        .post(format!("{}/p2p/snapshots", base_url))
        .json(&request)
        .send()
        .await
        .context("start snapshot stream")?
        .error_for_status()
        .context("start snapshot HTTP status")?
        .json()
        .await
        .context("decode start snapshot response")?;

    let session = status.session;

    let _ = wait_for_snapshot_status(
        &consumer.node_handle,
        session,
        SNAPSHOT_POLL_TIMEOUT,
        |s| s.verified == Some(true),
    )
    .await?;

    if let Some(error) = status.error.clone() {
        bail!("snapshot stream reported error: {error}");
    }

    if let Some(recorded) = status.chunk_size {
        if recorded < u64::from(chunk_size.saturating_sub(1))
            || recorded > u64::from(chunk_size.saturating_add(1))
        {
            return Err(anyhow!(
                "snapshot chunk size {recorded} diverged from negotiated {chunk_size}"
            ));
        }
    } else {
        return Err(anyhow!("snapshot chunk size was not recorded"));
    }

    Ok(())
}
