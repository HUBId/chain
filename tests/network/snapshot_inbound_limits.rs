use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use reqwest::Client;

#[path = "../support/mod.rs"]
mod support;

mod snapshots_common;

use rpp_p2p::SnapshotSessionId;

use snapshots_common::{
    default_chunk_size, start_snapshot_cluster_with_limit, wait_for_snapshot_status,
    SnapshotStreamStatusResponse, StartSnapshotStreamRequest, NETWORK_TIMEOUT, POLL_INTERVAL,
    SNAPSHOT_BUILD_DELAY, SNAPSHOT_POLL_TIMEOUT,
};

#[path = "../observability/metrics_utils.rs"]
mod metrics_utils;

use metrics_utils::{fetch_metrics, metric_value};

const MAX_SESSIONS: usize = 1;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_provider_rejects_requests_over_inbound_limit() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = start_snapshot_cluster_with_limit(3, Some(MAX_SESSIONS)).await?;

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        // Allow the provider to build snapshot metadata before consumers issue requests.
        tokio::time::sleep(SNAPSHOT_BUILD_DELAY).await;

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("construct HTTP client")?;

        let provider = &cluster.nodes()[0];
        let primary_consumer = &cluster.nodes()[1];
        let saturated_consumer = &cluster.nodes()[2];

        let provider_peer = provider.p2p_handle.local_peer_id().to_base58();
        let primary_base_url = format!("http://{}", primary_consumer.config.network.rpc.listen);
        let saturated_base_url =
            format!("http://{}", saturated_consumer.config.network.rpc.listen);

        let initial_error_bytes = {
            let metrics_addr = provider
                .config
                .rollout
                .telemetry
                .metrics
                .listen
                .context("provider metrics listen address")?;
            let scraped = fetch_metrics(&client, metrics_addr).await?;
            metric_value(
                &scraped,
                "snapshot_message_bytes_total",
                &[
                    ("direction", "inbound"),
                    ("flow", "sent"),
                    ("kind", "error"),
                ],
            )
            .unwrap_or_default()
        };

        // Start the initial consumer to hold the only available inbound slot.
        let primary_request = StartSnapshotStreamRequest {
            peer: provider_peer.clone(),
            chunk_size: default_chunk_size(),
            resume: None,
        };

        let primary_status: SnapshotStreamStatusResponse = client
            .post(format!("{}/p2p/snapshots", primary_base_url))
            .json(&primary_request)
            .send()
            .await
            .context("start primary snapshot stream")?
            .error_for_status()
            .context("primary snapshot start status")?
            .json()
            .await
            .context("decode primary snapshot response")?;

        if primary_status.session == 0 {
            bail!("primary consumer did not receive a snapshot session id");
        }

        let primary_handle = primary_consumer.node_handle.clone();
        wait_for_snapshot_status(
            &primary_handle,
            SnapshotSessionId::new(primary_status.session),
            SNAPSHOT_POLL_TIMEOUT,
            |status| status.last_chunk_index.is_some() || status.last_update_index.is_some(),
        )
        .await
        .context("wait for primary snapshot to start streaming")?;

        // Attempt a second snapshot and expect the provider to reject the new session.
        let saturated_request = StartSnapshotStreamRequest {
            peer: provider_peer,
            chunk_size: default_chunk_size(),
            resume: None,
        };

        let mut saturated_status: SnapshotStreamStatusResponse = client
            .post(format!("{}/p2p/snapshots", saturated_base_url))
            .json(&saturated_request)
            .send()
            .await
            .context("start saturated snapshot stream")?
            .error_for_status()
            .context("saturated snapshot start status")?
            .json()
            .await
            .context("decode saturated snapshot response")?;

        let saturated_poll_url = format!(
            "{}/p2p/snapshots/{}",
            saturated_base_url, saturated_status.session
        );
        let poll_deadline = Instant::now() + NETWORK_TIMEOUT;
        loop {
            if let Some(ref error) = saturated_status.error {
                if !error.to_ascii_lowercase().contains("saturated") {
                    bail!("unexpected saturation error: {error}");
                }
                if saturated_status.error_code
                    != Some(rpp_chain::runtime::node_runtime::node::SnapshotDownloadErrorCode::Network)
                {
                    bail!("unexpected saturation error code: {:?}", saturated_status.error_code);
                }
                break;
            }

            if Instant::now() >= poll_deadline {
                bail!("timed out waiting for saturation error");
            }

            tokio::time::sleep(POLL_INTERVAL).await;
            saturated_status = client
                .get(&saturated_poll_url)
                .send()
                .await
                .context("poll saturated snapshot status")?
                .error_for_status()
                .context("saturated snapshot poll status")?
                .json()
                .await
                .context("decode saturated snapshot status")?;
        }

        // Confirm the provider exported an error response metric for the denied session.
        let metrics_addr = provider
            .config
            .rollout
            .telemetry
            .metrics
            .listen
            .context("provider metrics listen address")?;
        let provider_metrics = fetch_metrics(&client, metrics_addr).await?;
        let error_bytes = metric_value(
            &provider_metrics,
            "snapshot_message_bytes_total",
            &[
                ("direction", "inbound"),
                ("flow", "sent"),
                ("kind", "error"),
            ],
        )
        .unwrap_or_default();

        if error_bytes <= initial_error_bytes {
            bail!("provider metrics did not record denied snapshot response");
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}
