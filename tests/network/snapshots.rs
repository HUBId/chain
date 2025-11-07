use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use tokio::time::sleep;

use rpp_chain::node::NodeHandle;
use rpp_p2p::SnapshotSessionId;

#[path = "../support/mod.rs"]
mod support;

mod snapshots_common;

#[path = "../observability/metrics_utils.rs"]
mod metrics_utils;

use metrics_utils::{fetch_metrics, metric_value};

use snapshots_common::{
    default_chunk_size, start_snapshot_cluster, SnapshotStreamStatusResponse,
    StartSnapshotStreamRequest, NETWORK_TIMEOUT, POLL_INTERVAL, SNAPSHOT_BUILD_DELAY,
    SNAPSHOT_POLL_TIMEOUT,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_streams_verify_via_network_rpc() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = start_snapshot_cluster().await?;

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        // Allow the cluster to produce a couple of blocks so that the provider
        // can build snapshot metadata before the consumer requests it.
        sleep(SNAPSHOT_BUILD_DELAY).await;

        let nodes = cluster.nodes();
        let provider = &nodes[0];
        let consumer = &nodes[1];

        let provider_peer = provider.p2p_handle.local_peer_id().to_base58();

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("construct HTTP client")?;

        let request = StartSnapshotStreamRequest {
            peer: provider_peer,
            chunk_size: default_chunk_size(),
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
        let poll_url = format!("{}/p2p/snapshots/{}", base_url, session);
        let deadline = Instant::now() + SNAPSHOT_POLL_TIMEOUT;

        loop {
            if let Some(ref error) = status.error {
                bail!("snapshot stream reported error: {error}");
            }
            match status.verified {
                Some(true) => break,
                Some(false) => {
                    tracing::info!(?status, "snapshot not yet verified");
                }
                None => {}
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for snapshot verification");
            }

            sleep(POLL_INTERVAL).await;
            status = client
                .get(&poll_url)
                .send()
                .await
                .context("poll snapshot status")?
                .error_for_status()
                .context("poll snapshot HTTP status")?
                .json()
                .await
                .context("decode snapshot status response")?;
        }

        let last_update_height = status
            .last_update_height
            .context("missing last update height")?;

        let consumer_head = latest_light_client_head(&consumer.node_handle)
            .context("fetch consumer light client head")?
            .context("consumer light client head unavailable")?;

        if consumer_head.height != last_update_height {
            return Err(anyhow!(
                "light client head height {} does not match snapshot status {}",
                consumer_head.height,
                last_update_height
            ));
        }

        let provider_metrics_addr = provider
            .config
            .rollout
            .telemetry
            .metrics
            .listen
            .context("provider metrics listen address")?;
        let consumer_metrics_addr = consumer
            .config
            .rollout
            .telemetry
            .metrics
            .listen
            .context("consumer metrics listen address")?;

        let metrics_deadline = Instant::now() + Duration::from_secs(30);
        let (provider_metrics, consumer_metrics) = loop {
            let provider_metrics = fetch_metrics(&client, provider_metrics_addr).await;
            let consumer_metrics = fetch_metrics(&client, consumer_metrics_addr).await;

            if let (Ok(provider_metrics), Ok(consumer_metrics)) =
                (provider_metrics, consumer_metrics)
            {
                let outbound_chunk_bytes = metric_value(
                    &provider_metrics,
                    "snapshot_bytes_sent_total",
                    &[("direction", "outbound"), ("kind", "chunk")],
                )
                .unwrap_or_default();
                let inbound_chunk_bytes = metric_value(
                    &consumer_metrics,
                    "snapshot_bytes_sent_total",
                    &[("direction", "inbound"), ("kind", "chunk")],
                )
                .unwrap_or_default();
                if outbound_chunk_bytes > 0.0 && inbound_chunk_bytes > 0.0 {
                    break (provider_metrics, consumer_metrics);
                }
            }

            if Instant::now() >= metrics_deadline {
                bail!("snapshot metrics did not report bytes transferred in time");
            }

            sleep(POLL_INTERVAL).await;
        };

        let outbound_chunk_bytes = metric_value(
            &provider_metrics,
            "snapshot_bytes_sent_total",
            &[("direction", "outbound"), ("kind", "chunk")],
        )
        .context("missing outbound chunk metric")?;
        if outbound_chunk_bytes <= 0.0 {
            bail!("expected outbound snapshot chunk bytes to be greater than zero");
        }

        let inbound_chunk_bytes = metric_value(
            &consumer_metrics,
            "snapshot_bytes_sent_total",
            &[("direction", "inbound"), ("kind", "chunk")],
        )
        .context("missing inbound chunk metric")?;
        if inbound_chunk_bytes <= 0.0 {
            bail!("expected inbound snapshot chunk bytes to be greater than zero");
        }

        let lag_seconds = metric_value(&consumer_metrics, "snapshot_stream_lag_seconds", &[])
            .context("missing snapshot stream lag metric")?;
        if lag_seconds < 0.0 {
            bail!("snapshot stream lag reported a negative value");
        }

        let outbound_chunk_failures = metric_value(
            &provider_metrics,
            "light_client_chunk_failures_total",
            &[("direction", "outbound"), ("kind", "chunk")],
        )
        .unwrap_or_default();
        if outbound_chunk_failures > 0.0 {
            bail!("expected zero outbound snapshot chunk failures, got {outbound_chunk_failures}");
        }

        let inbound_update_failures = metric_value(
            &consumer_metrics,
            "light_client_chunk_failures_total",
            &[("direction", "inbound"), ("kind", "light_client_update")],
        )
        .unwrap_or_default();
        if inbound_update_failures > 0.0 {
            bail!(
                "expected zero inbound light client update failures, got {inbound_update_failures}"
            );
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_sessions_persist_across_provider_restart() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = start_snapshot_cluster().await?;

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        sleep(SNAPSHOT_BUILD_DELAY).await;

        let session = SnapshotSessionId::new(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
        );

        {
            let nodes = cluster.nodes();
            let provider = &nodes[0];
            let consumer = &nodes[1];
            let provider_peer = provider.p2p_handle.local_peer_id();
            consumer
                .node_handle
                .start_snapshot_stream(session, provider_peer, String::new())
                .await
                .context("start snapshot stream")?;
        }

        let mut initial_chunk = None;
        let mut initial_update = None;
        let poll_deadline = Instant::now() + SNAPSHOT_POLL_TIMEOUT;
        loop {
            if Instant::now() >= poll_deadline {
                bail!("timed out waiting for snapshot progress before restart");
            }
            let status = cluster.nodes()[1]
                .node_handle
                .snapshot_stream_status(session);
            if let Some(status) = status {
                if let Some(ref error) = status.error {
                    bail!("snapshot stream reported error before restart: {error}");
                }
                if status.verified == Some(true) {
                    bail!("snapshot stream completed before restart");
                }
                if status.last_chunk_index.is_some() || status.last_update_index.is_some() {
                    initial_chunk = status.last_chunk_index;
                    initial_update = status.last_update_index;
                    break;
                }
            }
            sleep(POLL_INTERVAL).await;
        }

        {
            let nodes = cluster.nodes_mut();
            nodes[0].restart().await.context("restart provider node")?;
        }

        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh after restart")?;

        {
            let nodes = cluster.nodes();
            let plan_id = nodes[1]
                .node_handle
                .snapshot_stream_status(session)
                .and_then(|status| {
                    status.plan_id.clone().or_else(|| {
                        if status.root.is_empty() {
                            None
                        } else {
                            Some(status.root)
                        }
                    })
                })
                .context("missing snapshot plan identifier before resume")?;
            nodes[1]
                .node_handle
                .resume_snapshot_stream(session, plan_id)
                .await
                .context("resume snapshot stream")?;
        }

        let mut final_status = None;
        let poll_deadline = Instant::now() + SNAPSHOT_POLL_TIMEOUT;
        loop {
            if Instant::now() >= poll_deadline {
                bail!("timed out waiting for snapshot verification after resume");
            }
            let status = cluster.nodes()[1]
                .node_handle
                .snapshot_stream_status(session);
            if let Some(status) = status {
                if let Some(ref error) = status.error {
                    bail!("snapshot stream reported error after resume: {error}");
                }
                if status.verified == Some(true) {
                    final_status = Some(status);
                    break;
                }
            }
            sleep(POLL_INTERVAL).await;
        }

        let status = final_status.context("missing final snapshot status")?;
        if let Some(chunk) = initial_chunk {
            let resumed_chunk = status
                .last_chunk_index
                .context("missing final chunk index")?;
            if resumed_chunk < chunk {
                bail!("resumed chunk index {resumed_chunk} smaller than initial {chunk}");
            }
        }
        if let Some(update) = initial_update {
            let resumed_update = status
                .last_update_index
                .context("missing final update index")?;
            if resumed_update < update {
                bail!("resumed update index {resumed_update} smaller than initial {update}");
            }
        }
        if let Some(height) = status.last_update_height {
            let consumer = &cluster.nodes()[1];
            let head = latest_light_client_head(&consumer.node_handle)
                .context("fetch consumer head after resume")?
                .context("consumer head missing after resume")?;
            if head.height != height {
                bail!(
                    "resumed head height {} does not match status {height}",
                    head.height
                );
            }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}

fn latest_light_client_head(handle: &NodeHandle) -> Result<Option<rpp_p2p::LightClientHead>> {
    handle
        .latest_light_client_head()
        .context("query latest light client head")
}

use metrics_utils::{fetch_metrics, metric_value};
