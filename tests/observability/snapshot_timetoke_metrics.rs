#[path = "../support/mod.rs"]
mod support;

#[path = "../network/snapshots_common.rs"]
mod snapshots_common;

#[path = "metrics_utils.rs"]
mod metrics_utils;

use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use rpp_consensus::TimetokeRecord;
use serde::Serialize;
use tokio::time::sleep;

use metrics_utils::{fetch_metrics, metric_value};
use snapshots_common::{
    default_chunk_size, start_snapshot_cluster, SnapshotStreamStatusResponse,
    StartSnapshotStreamRequest, NETWORK_TIMEOUT, POLL_INTERVAL, SNAPSHOT_BUILD_DELAY,
    SNAPSHOT_POLL_TIMEOUT,
};

#[derive(Serialize)]
struct TimetokeSyncRequest {
    records: Vec<TimetokeRecord>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_and_timetoke_metrics_reach_prometheus() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = start_snapshot_cluster().await?;

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        sleep(SNAPSHOT_BUILD_DELAY).await;

        let nodes = cluster.nodes();
        let provider = &nodes[0];
        let consumer = &nodes[1];

        let provider_peer = provider.p2p_handle.local_peer_id().to_base58();
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

        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("construct HTTP client")?;

        let initial_provider_metrics = fetch_metrics(&client, provider_metrics_addr)
            .await
            .context("initial provider metrics scrape")?;
        let initial_consumer_metrics = fetch_metrics(&client, consumer_metrics_addr)
            .await
            .context("initial consumer metrics scrape")?;
        let initial_lag = metric_value(
            &initial_consumer_metrics,
            "snapshot_stream_lag_seconds",
            &[],
        );
        let initial_replay_duration = metric_value(
            &initial_consumer_metrics,
            "timetoke_replay_duration_ms",
            &[],
        );

        let request = StartSnapshotStreamRequest {
            peer: provider_peer,
            chunk_size: default_chunk_size(),
        };

        let consumer_addr = consumer.config.network.rpc.listen;
        let consumer_base_url = format!("http://{}", consumer_addr);

        let mut status: SnapshotStreamStatusResponse = client
            .post(format!("{}/p2p/snapshots", consumer_base_url))
            .json(&request)
            .send()
            .await
            .context("start snapshot stream")?
            .error_for_status()
            .context("snapshot HTTP status")?
            .json()
            .await
            .context("decode snapshot response")?;

        let poll_url = format!("{}/p2p/snapshots/{}", consumer_base_url, status.session);
        let verification_deadline = Instant::now() + SNAPSHOT_POLL_TIMEOUT;
        let mut observed_lag_values = Vec::new();

        loop {
            if let Some(ref error) = status.error {
                bail!("snapshot stream reported error: {error}");
            }
            if matches!(status.verified, Some(true)) {
                break;
            }

            let consumer_metrics = fetch_metrics(&client, consumer_metrics_addr)
                .await
                .context("consumer metrics scrape during snapshot")?;
            if let Some(value) = metric_value(&consumer_metrics, "snapshot_stream_lag_seconds", &[]) {
                if value < 0.0 {
                    bail!("snapshot stream lag reported a negative value");
                }
                if observed_lag_values.last().copied() != Some(value) {
                    observed_lag_values.push(value);
                }
            }

            if Instant::now() >= verification_deadline {
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

        let mut distinct_lag = HashSet::new();
        if let Some(value) = initial_lag {
            distinct_lag.insert(value);
        }
        for value in &observed_lag_values {
            distinct_lag.insert(*value);
        }
        if distinct_lag.len() < 2 {
            bail!(
                "expected snapshot_stream_lag_seconds to change, observed {:?} (initial {:?})",
                observed_lag_values, initial_lag
            );
        }

        let provider_metrics = fetch_metrics(&client, provider_metrics_addr)
            .await
            .context("provider metrics after snapshot")?;
        let consumer_metrics = fetch_metrics(&client, consumer_metrics_addr)
            .await
            .context("consumer metrics after snapshot")?;
        let provider_bytes = metric_value(
            &provider_metrics,
            "snapshot_bytes_sent_total",
            &[("direction", "outbound"), ("kind", "chunk")],
        )
        .unwrap_or_default();
        let consumer_bytes = metric_value(
            &consumer_metrics,
            "snapshot_bytes_sent_total",
            &[("direction", "inbound"), ("kind", "chunk")],
        )
        .unwrap_or_default();
        if provider_bytes <= 0.0 || consumer_bytes <= 0.0 {
            bail!("expected snapshot chunk counters to increase");
        }

        let provider_rpc_addr = provider.config.network.rpc.listen;
        let provider_base_url = format!("http://{}", provider_rpc_addr);

        let records: Vec<TimetokeRecord> = client
            .get(format!("{}/ledger/timetoke", provider_base_url))
            .send()
            .await
            .context("fetch timetoke snapshot")?
            .error_for_status()
            .context("timetoke snapshot HTTP status")?
            .json()
            .await
            .context("decode timetoke records")?;
        if records.is_empty() {
            return Err(anyhow!("timetoke snapshot did not return any records"));
        }

        let sync_request = TimetokeSyncRequest { records };

        client
            .post(format!("{}/ledger/timetoke/sync", consumer_base_url))
            .json(&sync_request)
            .send()
            .await
            .context("sync timetoke records")?
            .error_for_status()
            .context("timetoke sync HTTP status")?;

        let replay_deadline = Instant::now() + Duration::from_secs(60);
        let baseline_replay = initial_replay_duration.unwrap_or(-1.0);
        let mut observed_replay = None;
        let mut replay_increase = None;
        while Instant::now() < replay_deadline {
            let metrics = fetch_metrics(&client, consumer_metrics_addr)
                .await
                .context("consumer metrics during timetoke replay")?;
            if let Some(value) = metric_value(&metrics, "timetoke_replay_duration_ms", &[]) {
                if value < 0.0 {
                    bail!("timetoke replay duration reported a negative value");
                }
                if observed_replay.is_none() {
                    observed_replay = Some(value);
                }
                if value > baseline_replay {
                    replay_increase = Some(value);
                    break;
                }
            }
            sleep(POLL_INTERVAL).await;
        }

        let Some(replay_value) = replay_increase else {
            bail!(
                "timetoke_replay_duration_ms did not increase (baseline {:?}, first {:?})",
                initial_replay_duration, observed_replay
            );
        };
        if replay_value <= baseline_replay {
            bail!(
                "timetoke_replay_duration_ms {replay_value} did not exceed baseline {baseline_replay}"
            );
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}
