use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::time::sleep;

use rpp_chain::orchestration::PipelineStage;
use rpp_chain::runtime::types::block::Block;

mod support;

use support::cluster::TestCluster;
use support::consensus::consensus_round_for_block;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MAX_ATTEMPTS: usize = 150;
const SAMPLE_BLOCKS: usize = 3;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vrf_leader_matches_block_proposer() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping VRF selection test: {err:?}");
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let primary = &cluster.nodes()[0];
        wait_for_minimum_height(primary, SAMPLE_BLOCKS as u64)
            .await
            .context("wait for baseline blocks")?;

        let blocks = recent_blocks(primary, SAMPLE_BLOCKS)
            .await
            .context("collect recent blocks")?;
        let participants = cluster.nodes();

        for block in &blocks {
            let mut round = consensus_round_for_block(primary, block, participants)
                .with_context(|| format!("rebuild consensus round for height {}", block.header.height))?;
            let selection = round
                .select_proposer()
                .ok_or_else(|| anyhow!("failed to derive proposer selection for block"))?;
            anyhow::ensure!(
                selection.proposer == block.header.proposer,
                "VRF selection proposer {} did not match block proposer {}",
                selection.proposer,
                block.header.proposer
            );
            anyhow::ensure!(
                selection.randomness == block.header.randomness,
                "VRF randomness mismatch for block {}",
                block.header.height
            );
        }

        let telemetry = primary
            .orchestrator
            .telemetry_summary()
            .await
            .context("fetch pipeline telemetry")?;
        anyhow::ensure!(
            telemetry
                .stage_latency_ms
                .get(&PipelineStage::LeaderElected)
                .map(|summary| summary.count > 0)
                .unwrap_or(false),
            "leader election stage telemetry missing"
        );
        anyhow::ensure!(
            telemetry.leader_observations > 0,
            "pipeline telemetry missing leader observations"
        );

        let status = primary
            .node_handle
            .consensus_status()
            .context("fetch consensus status")?;
        anyhow::ensure!(
            !status.round_latencies_ms.is_empty(),
            "round latency samples missing after VRF selection"
        );
        anyhow::ensure!(status.quorum_reached, "consensus quorum not reached");

        Ok(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}

async fn wait_for_minimum_height(
    node: &support::cluster::TestClusterNode,
    target: u64,
) -> Result<()> {
    let mut attempts = 0usize;
    loop {
        if attempts >= MAX_ATTEMPTS {
            return Err(anyhow!("timed out waiting for target height"));
        }
        if let Some(block) = node
            .node_handle
            .latest_block()
            .context("poll latest block for height")?
        {
            if block.header.height >= target {
                return Ok(());
            }
        }
        attempts += 1;
        sleep(POLL_INTERVAL).await;
    }
}

async fn recent_blocks(
    node: &support::cluster::TestClusterNode,
    count: usize,
) -> Result<Vec<Block>> {
    let tip = node
        .node_handle
        .latest_block()
        .context("fetch tip block")?
        .ok_or_else(|| anyhow!("validator tip missing"))?;
    let start_height = tip.header.height.saturating_sub((count as u64).saturating_sub(1));
    let mut blocks = Vec::new();
    for height in start_height..=tip.header.height {
        let block = node
            .node_handle
            .get_block(height)
            .with_context(|| format!("fetch block at height {height}"))?
            .ok_or_else(|| anyhow!("missing block at height {height}"))?;
        blocks.push(block);
    }
    Ok(blocks)
}
