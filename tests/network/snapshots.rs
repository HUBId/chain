use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Instant};

use rpp_chain::node::{NodeHandle, DEFAULT_STATE_SYNC_CHUNK};

#[path = "../support/mod.rs"]
mod support;

use support::TestCluster;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(60);
const SNAPSHOT_POLL_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const SNAPSHOT_BUILD_DELAY: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize)]
struct StartSnapshotStreamRequest {
    peer: String,
    chunk_size: u32,
}

#[derive(Clone, Debug, Deserialize)]
struct SnapshotStreamStatusResponse {
    session: u64,
    peer: String,
    root: String,
    #[serde(default)]
    last_chunk_index: Option<u64>,
    #[serde(default)]
    last_update_index: Option<u64>,
    #[serde(default)]
    last_update_height: Option<u64>,
    #[serde(default)]
    verified: Option<bool>,
    #[serde(default)]
    error: Option<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_streams_verify_via_network_rpc() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = TestCluster::start_with(2, |cfg, idx| {
        let metrics_listener = TcpListener::bind("127.0.0.1:0").context("bind metrics listener")?;
        let metrics_addr = metrics_listener
            .local_addr()
            .context("resolve metrics listener address")?;
        drop(metrics_listener);

        cfg.rollout.feature_gates.reconstruction = true;
        cfg.rollout.feature_gates.recursive_proofs = true;
        cfg.rollout.telemetry.enabled = true;
        cfg.rollout.telemetry.metrics.listen = Some(metrics_addr);
        if idx == 0 {
            cfg.network.p2p.bootstrap_peers.clear();
        }
        Ok(())
    })
    .await?;

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
            chunk_size: DEFAULT_STATE_SYNC_CHUNK as u32,
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

fn latest_light_client_head(handle: &NodeHandle) -> Result<Option<rpp_p2p::LightClientHead>> {
    handle
        .latest_light_client_head()
        .context("query latest light client head")
}

async fn fetch_metrics(client: &Client, addr: SocketAddr) -> Result<String> {
    let response = client
        .get(format!("http://{addr}/metrics"))
        .send()
        .await
        .with_context(|| format!("fetch metrics from {addr}"))?
        .error_for_status()
        .with_context(|| format!("metrics endpoint at {addr} returned error status"))?;
    response
        .text()
        .await
        .with_context(|| format!("decode metrics body from {addr}"))
}

fn metric_value(metrics: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    metrics.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || !line.starts_with(name) {
            return None;
        }

        if !labels
            .iter()
            .all(|(key, value)| line.contains(&format!("{key}=\"{value}\"")))
        {
            return None;
        }

        line.split_whitespace()
            .last()
            .and_then(|value| value.parse::<f64>().ok())
    })
}
