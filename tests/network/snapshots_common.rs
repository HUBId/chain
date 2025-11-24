use std::net::TcpListener;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rpp_chain::node::{NodeHandle, DEFAULT_STATE_SYNC_CHUNK};
use rpp_chain::runtime::node_runtime::node::SnapshotDownloadErrorCode;
use rpp_p2p::pipeline::chunk_sizing::ChunkSizingStrategy;
use rpp_p2p::SnapshotSessionId;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use super::support::TestCluster;

pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(60);
pub const SNAPSHOT_POLL_TIMEOUT: Duration = Duration::from_secs(60);
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);
pub const SNAPSHOT_BUILD_DELAY: Duration = Duration::from_secs(10);

#[derive(Debug, Serialize)]
pub struct StartSnapshotStreamRequest {
    pub peer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunk_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume: Option<ResumeMarker>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ResumeMarker {
    pub session: u64,
    pub plan_id: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SnapshotStreamStatusResponse {
    pub session: u64,
    pub peer: String,
    pub root: String,
    #[serde(default)]
    pub chunk_size: Option<u64>,
    #[serde(default)]
    pub plan_id: Option<String>,
    #[serde(default)]
    pub last_chunk_index: Option<u64>,
    #[serde(default)]
    pub last_update_index: Option<u64>,
    #[serde(default)]
    pub last_update_height: Option<u64>,
    #[serde(default)]
    pub verified: Option<bool>,
    #[serde(default)]
    pub error_code: Option<SnapshotDownloadErrorCode>,
    #[serde(default)]
    pub error: Option<String>,
}

pub async fn start_snapshot_cluster() -> Result<TestCluster> {
    start_snapshot_cluster_with_limit(2, None).await
}

pub async fn start_snapshot_cluster_with_limit(
    count: usize,
    max_inbound_sessions: Option<usize>,
) -> Result<TestCluster> {
    let cluster = TestCluster::start_with(count, |cfg, idx| {
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
            cfg.network.p2p.snapshot_max_inbound_sessions = max_inbound_sessions;
        }
        if idx == 0 {
            cfg.network.p2p.bootstrap_peers.clear();
        }
        Ok(())
    })
    .await?;

    Ok(cluster)
}

pub async fn wait_for_snapshot_status<F>(
    handle: &NodeHandle,
    session: SnapshotSessionId,
    timeout: Duration,
    mut predicate: F,
) -> Result<rpp_chain::runtime::node_runtime::node::SnapshotStreamStatus>
where
    F: FnMut(&rpp_chain::runtime::node_runtime::node::SnapshotStreamStatus) -> bool,
{
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = handle.snapshot_stream_status(session) {
            if let Some(error) = status.error.clone() {
                bail!("snapshot stream reported error: {error}");
            }
            if predicate(&status) {
                return Ok(status);
            }
        }

        if Instant::now() >= deadline {
            return Err(anyhow!("timed out waiting for snapshot status update"));
        }

        sleep(POLL_INTERVAL).await;
    }
}

pub fn default_chunk_size() -> u32 {
    DEFAULT_STATE_SYNC_CHUNK as u32
}

#[derive(Clone, Copy, Debug)]
pub struct LinkShape {
    pub bandwidth_bytes_per_sec: u64,
    pub latency: Duration,
}

impl LinkShape {
    pub fn negotiated_chunk_size(&self, min: usize, max: usize, initial: usize) -> u64 {
        let mut strategy =
            ChunkSizingStrategy::new(min.max(1), max.max(min), initial.max(min), self.latency);

        let bytes_for_latency = ((self.bandwidth_bytes_per_sec as f64)
            * self.latency.as_secs_f64())
        .clamp(1.0, max as f64);

        strategy.record_sample(bytes_for_latency as usize, self.latency);
        strategy.next_chunk_size() as u64
    }
}
