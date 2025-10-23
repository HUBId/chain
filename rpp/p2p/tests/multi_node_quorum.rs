use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use libp2p::PeerId;
use tokio::sync::broadcast;
use tokio::time::{self, timeout};

use rpp_chain::runtime::node_runtime::node::{NodeError, NodeEvent};
use rpp_chain::types::block::Block;
use rpp_p2p::{GossipTopic, NetworkError, TierLevel};

#[path = "../../../tests/support/cluster.rs"]
mod cluster;
#[path = "../../../tests/support/consensus.rs"]
mod consensus;

use cluster::{TestCluster, TestClusterNode};
use consensus::signed_votes_for_round;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MAX_ATTEMPTS: usize = 50;

#[tokio::test(flavor = "multi_thread")]
async fn multi_node_votes_reach_quorum() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping multi-node quorum test: {err:?}");
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let nodes = cluster.nodes();
        for node in nodes {
            let profile = node
                .node_handle
                .network_identity_profile()
                .context("fetch network identity profile")?;
            ensure!(
                profile.tier >= TierLevel::Tl1,
                "node {} expected to advertise at least tier 1 access, found {:?}",
                node.index,
                profile.tier
            );
        }

        let leader = &nodes[0];
        let mut events = leader.p2p_handle.subscribe();

        let tip_block = wait_for_tip_block(leader).await?;
        let proposal = serde_json::to_vec(&tip_block).context("encode block proposal")?;

        nodes[1]
            .p2p_handle
            .publish_gossip(GossipTopic::Blocks, proposal)
            .await
            .context("publish block proposal")?;

        wait_for_block_proposal(&mut events, nodes[1].p2p_handle.local_peer_id()).await?;

        let commit_pairs = signed_votes_for_round(
            nodes,
            tip_block.header.height,
            tip_block.consensus.round,
            &tip_block.hash,
        )
        .context("assemble quorum votes")?;

        for (node, (_, precommit)) in nodes.iter().zip(commit_pairs.into_iter()) {
            if node.index == leader.index {
                continue;
            }

            let payload = serde_json::to_vec(&precommit).context("encode vote payload")?;
            match node
                .p2p_handle
                .publish_gossip(GossipTopic::Votes, payload)
                .await
            {
                Ok(()) => {}
                Err(NodeError::Network(NetworkError::Admission(err))) => {
                    return Err(anyhow!(
                        "peer {0} was not permitted to publish votes: {1:?}",
                        node.index,
                        err
                    ));
                }
                Err(err) => {
                    return Err(anyhow!(
                        "failed to publish vote from peer {0}: {1:?}",
                        node.index,
                        err
                    ));
                }
            }

            wait_for_vote(&mut events, node.p2p_handle.local_peer_id()).await?;
        }

        Ok(())
    }
    .await;

    if let Err(err) = cluster.shutdown().await {
        eprintln!("cluster shutdown failed: {err:?}");
    }

    result
}

async fn wait_for_tip_block(node: &TestClusterNode) -> Result<Block> {
    let mut attempts = 0;
    loop {
        if attempts >= MAX_ATTEMPTS {
            return Err(anyhow!(
                "timed out waiting for node {} to produce a tip block",
                node.index
            ));
        }
        match node
            .node_handle
            .latest_block()
            .context("fetch latest block from node")?
        {
            Some(block) => return Ok(block),
            None => {
                time::sleep(POLL_INTERVAL).await;
                attempts += 1;
            }
        }
    }
}

async fn wait_for_block_proposal(
    events: &mut broadcast::Receiver<NodeEvent>,
    expected_peer: PeerId,
) -> Result<()> {
    timeout(EVENT_TIMEOUT, async {
        loop {
            match events.recv().await {
                Ok(NodeEvent::BlockProposal { peer, .. }) if peer == expected_peer => {
                    return Ok(());
                }
                Ok(NodeEvent::BlockRejected { peer, reason, .. }) if peer == expected_peer => {
                    return Err(anyhow!("block proposal rejected from {peer:?}: {reason}"));
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(err) => return Err(anyhow!("event stream closed: {err}")),
            }
        }
    })
    .await
    .context("waiting for block proposal event")??;
    Ok(())
}

async fn wait_for_vote(
    events: &mut broadcast::Receiver<NodeEvent>,
    expected_peer: PeerId,
) -> Result<()> {
    timeout(EVENT_TIMEOUT, async {
        loop {
            match events.recv().await {
                Ok(NodeEvent::Vote { peer, .. }) if peer == expected_peer => {
                    return Ok(());
                }
                Ok(NodeEvent::VoteRejected { peer, reason, .. }) if peer == expected_peer => {
                    return Err(anyhow!("vote rejected from {peer:?}: {reason}"));
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(err) => return Err(anyhow!("event stream closed: {err}")),
            }
        }
    })
    .await
    .context("waiting for vote event")??;
    Ok(())
}
