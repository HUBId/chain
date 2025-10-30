use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Instant};

use rpp_p2p::LightClientHead;

#[path = "../support/mod.rs"]
mod support;

use support::TestCluster;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
const HEIGHT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const SNAPSHOT_POLL_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(250);
const REQUIRED_HEIGHT: u64 = 3;
const SNAPSHOT_CHUNK_SIZE: u32 = 16;

#[derive(Debug, Serialize)]
struct StartSnapshotStreamRequest {
    peer: String,
    chunk_size: u32,
}

#[derive(Debug, Deserialize)]
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

    let mut cluster = match TestCluster::start_with(2, |config, _| {
        config.rollout.feature_gates.reconstruction = true;
        config.rollout.feature_gates.witness_network = true;
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping snapshot stream test: {err:?}");
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let nodes = cluster.nodes();
        let provider = &nodes[0];
        let consumer = &nodes[1];

        wait_for_height(&provider.node_handle, REQUIRED_HEIGHT).await?;
        wait_for_height(&consumer.node_handle, REQUIRED_HEIGHT).await?;

        provider
            .node_handle
            .run_pruning_cycle(SNAPSHOT_CHUNK_SIZE as usize, 0)
            .context("run pruning cycle")?
            .context("missing pruning status")?;

        let provider_peer = provider.p2p_handle.local_peer_id();
        let consumer_addr = consumer.config.network.rpc.listen;
        let base_url = format!("http://{}", consumer_addr);
        let client = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("construct HTTP client")?;

        let request = StartSnapshotStreamRequest {
            peer: provider_peer.to_string(),
            chunk_size: SNAPSHOT_CHUNK_SIZE,
        };

        let start_response: SnapshotStreamStatusResponse = client
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

        let session = start_response.session;
        let poll_url = format!("{}/p2p/snapshots/{}", base_url, session);
        let deadline = Instant::now() + SNAPSHOT_POLL_TIMEOUT;
        let mut final_status = start_response;

        loop {
            if let Some(ref error) = final_status.error {
                bail!("snapshot stream reported error: {error}");
            }
            if matches!(final_status.verified, Some(true)) {
                break;
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for snapshot verification");
            }
            sleep(POLL_INTERVAL).await;
            final_status = client
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

        let last_update_height = final_status
            .last_update_height
            .context("missing last update height")?;

        let head = wait_for_light_client_head(&consumer.p2p_handle).await?;
        assert_eq!(head.height, last_update_height);

        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Err(err) = cluster.shutdown().await {
        eprintln!("cluster shutdown failed: {err:?}");
    }

    result
}

async fn wait_for_height(node: &rpp_chain::node::NodeHandle, target: u64) -> Result<()> {
    let deadline = Instant::now() + HEIGHT_WAIT_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            bail!("node height did not reach {} in time", target);
        }
        if let Some(block) = node
            .latest_block()
            .context("fetch latest block")?
        {
            if block.header.height >= target {
                return Ok(());
            }
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_light_client_head(
    handle: &rpp_chain::runtime::node_runtime::NodeHandle,
) -> Result<LightClientHead> {
    let deadline = Instant::now() + SNAPSHOT_POLL_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            bail!("light client head did not update in time");
        }
        if let Some(head) = handle.latest_light_client_head() {
            return Ok(head);
        }
        sleep(POLL_INTERVAL).await;
    }
}
