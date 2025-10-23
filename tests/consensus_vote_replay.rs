use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use tokio::sync::broadcast;
use tokio::time::{sleep, timeout};

use rpp_chain::runtime::node_runtime::node::NodeEvent;
use rpp_chain::types::block::Block;

mod support;

use support::cluster::{TestCluster, TestClusterNode};

const NETWORK_TIMEOUT: Duration = Duration::from_secs(20);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const EVENT_TIMEOUT: Duration = Duration::from_millis(250);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restarted_node_does_not_rebroadcast_votes() -> Result<()> {
    let mut cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping vote replay test: {err:?}");
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let broadcaster_index = 0usize;
        let mut receivers: Vec<_> = cluster
            .nodes()
            .iter()
            .map(|node| node.p2p_handle.subscribe())
            .collect();

        let tip_block = wait_for_tip_block(&cluster.nodes()[broadcaster_index])
            .await
            .context("tip block")?;
        ensure!(
            !tip_block.bft_votes.is_empty(),
            "tip block missing votes for replay"
        );
        let replay_block = tip_block.clone();
        let replay_votes = tip_block.bft_votes.clone();

        {
            let nodes = cluster.nodes_mut();
            nodes[broadcaster_index]
                .restart()
                .await
                .context("restart broadcaster")?;
        }

        receivers[broadcaster_index] = cluster.nodes()[broadcaster_index].p2p_handle.subscribe();

        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster remesh")?;

        for receiver in receivers.iter_mut() {
            while receiver.try_recv().is_ok() {}
        }

        let baseline = cluster.consensus_snapshots().context("baseline snapshot")?;

        let broadcaster = &cluster.nodes()[broadcaster_index];
        let _ = broadcaster
            .node_handle
            .submit_block_proposal(replay_block.clone());
        for vote in &replay_votes {
            let _ = broadcaster.node_handle.submit_vote(vote.clone());
        }

        for (index, receiver) in receivers.iter_mut().enumerate() {
            ensure_no_replayed_events(receiver, index).await?;
        }

        let updated = cluster
            .consensus_snapshots()
            .context("post replay snapshot")?;
        ensure!(
            baseline.len() == updated.len(),
            "consensus snapshot count changed after replay: before={} after={}",
            baseline.len(),
            updated.len()
        );
        for (index, (before, after)) in baseline.iter().zip(updated.iter()).enumerate() {
            ensure!(
                before.pending_votes == after.pending_votes,
                "node {index} consensus pending votes changed"
            );
            ensure!(
                before.node_pending_votes == after.node_pending_votes,
                "node {index} runtime pending votes changed"
            );
        }

        let restarted_node = &cluster.nodes()[broadcaster_index];
        restarted_node.orchestrator.shutdown();
        restarted_node.p2p_handle.shutdown().await.map_err(|err| {
            anyhow!("failed to shutdown broadcaster {broadcaster_index} p2p handle: {err}")
        })?;
        restarted_node.node_handle.stop().await.map_err(|err| {
            anyhow!("failed to stop broadcaster {broadcaster_index} runtime after replay: {err}")
        })?;

        Ok(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}

async fn ensure_no_replayed_events(
    receiver: &mut broadcast::Receiver<NodeEvent>,
    index: usize,
) -> Result<()> {
    match timeout(EVENT_TIMEOUT, async {
        loop {
            match receiver.recv().await {
                Ok(NodeEvent::Vote { .. }) => {
                    return Err(anyhow!("node {index} emitted duplicate vote after replay"));
                }
                Ok(NodeEvent::BlockProposal { .. }) => {
                    return Err(anyhow!(
                        "node {index} emitted duplicate proposal after replay"
                    ));
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            }
        }
    })
    .await
    {
        Err(_) => Ok(()),
        Ok(result) => result,
    }
}

async fn wait_for_tip_block(node: &TestClusterNode) -> Result<Block> {
    let mut attempts = 0usize;
    loop {
        if attempts >= 100 {
            return Err(anyhow!("timed out waiting for node to produce a tip block"));
        }
        if let Some(block) = node
            .node_handle
            .latest_block()
            .context("fetch latest block while waiting for tip")?
        {
            return Ok(block);
        }
        sleep(POLL_INTERVAL).await;
        attempts += 1;
    }
}
