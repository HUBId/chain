use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use libp2p::PeerId;
use tokio::sync::broadcast;
use tokio::time::{self, timeout};

use rpp_chain::consensus::BftVoteKind;
use rpp_chain::runtime::node_runtime::node::{NodeError, NodeEvent};
use rpp_chain::types::block::Block;
use rpp_p2p::{GossipTopic, NetworkError, TierLevel};

#[path = "../../../tests/support/cluster.rs"]
mod cluster;
#[path = "../../../tests/support/consensus.rs"]
mod consensus;

use cluster::{TestCluster, TestClusterNode};
use consensus::{consensus_round_for_block, signed_votes_for_round};

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

        let mut subscriptions: Vec<(usize, PeerId, broadcast::Receiver<NodeEvent>)> = nodes
            .iter()
            .map(|node| {
                (
                    node.index,
                    node.p2p_handle.local_peer_id(),
                    node.p2p_handle.subscribe(),
                )
            })
            .collect();

        let leader = &nodes[0];
        let broadcaster = &nodes[1];
        let broadcaster_peer = broadcaster.p2p_handle.local_peer_id();

        let tip_block = wait_for_tip_block(leader).await?;
        let round = consensus_round_for_block(leader, &tip_block, nodes)
            .context("rebuild consensus round for block")?;
        ensure!(
            round.round() == tip_block.consensus.round,
            "rebuilt round {} did not match block round {}",
            round.round(),
            tip_block.consensus.round
        );
        ensure!(
            round.height() == tip_block.header.height,
            "rebuilt height {} did not match block height {}",
            round.height(),
            tip_block.header.height
        );

        let proposal = serde_json::to_vec(&tip_block).context("encode block proposal")?;

        broadcaster
            .p2p_handle
            .publish_gossip(GossipTopic::Blocks, proposal)
            .await
            .context("publish block proposal")?;

        for (node_index, _, events) in subscriptions.iter_mut() {
            wait_for_block_proposal(*node_index, events, broadcaster_peer, &tip_block.hash).await?;
        }

        let vote_pairs =
            signed_votes_for_round(nodes, round.height(), round.round(), &tip_block.hash)
                .context("assemble quorum votes")?;

        let expected_vote_counts: HashMap<PeerId, usize> = nodes
            .iter()
            .map(|node| (node.p2p_handle.local_peer_id(), 2))
            .collect();

        for (node, (prevote, precommit)) in nodes.iter().zip(vote_pairs.into_iter()) {
            for vote in [prevote, precommit] {
                let payload = serde_json::to_vec(&vote).context("encode vote payload")?;
                let vote_kind = match &vote.vote.kind {
                    BftVoteKind::PreVote => "prevote",
                    BftVoteKind::PreCommit => "precommit",
                };
                match node
                    .p2p_handle
                    .publish_gossip(GossipTopic::Votes, payload)
                    .await
                {
                    Ok(()) => {}
                    Err(NodeError::Network(NetworkError::Admission(err))) => {
                        return Err(anyhow!(
                            "peer {0} was not permitted to publish {1} votes: {2:?}",
                            node.index,
                            vote_kind,
                            err
                        ));
                    }
                    Err(err) => {
                        return Err(anyhow!(
                            "failed to publish {0} vote from peer {1}: {2:?}",
                            vote_kind,
                            node.index,
                            err
                        ));
                    }
                }
            }
        }

        for (node_index, peer_id, events) in subscriptions.iter_mut() {
            wait_for_votes(*node_index, events, &tip_block.hash, &expected_vote_counts)
                .await
                .with_context(|| {
                    format!("node {node_index} (peer {peer_id:?}) waiting for votes")
                })?;
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
    node_index: usize,
    events: &mut broadcast::Receiver<NodeEvent>,
    expected_peer: PeerId,
    expected_hash: &str,
) -> Result<()> {
    timeout(EVENT_TIMEOUT, async {
        loop {
            match events.recv().await {
                Ok(NodeEvent::BlockProposal { peer, block }) if peer == expected_peer => {
                    if block.hash == expected_hash {
                        return Ok(());
                    }
                }
                Ok(NodeEvent::BlockRejected { peer, block, reason })
                    if peer == expected_peer && block.hash == expected_hash =>
                {
                    return Err(anyhow!(
                        "node {node_index} observed block proposal rejection from {peer:?}: {reason}"
                    ));
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

async fn wait_for_votes(
    node_index: usize,
    events: &mut broadcast::Receiver<NodeEvent>,
    expected_hash: &str,
    expected_counts: &HashMap<PeerId, usize>,
) -> Result<()> {
    timeout(EVENT_TIMEOUT, async {
        let mut remaining: HashMap<PeerId, usize> = expected_counts
            .iter()
            .map(|(peer, count)| (peer.clone(), *count))
            .collect();

        loop {
            if remaining.values().all(|count| *count == 0) {
                return Ok(());
            }

            match events.recv().await {
                Ok(NodeEvent::Vote { peer, vote }) => {
                    if vote.vote.block_hash != expected_hash {
                        continue;
                    }

                    match remaining.get_mut(&peer) {
                        Some(count) if *count > 0 => {
                            *count -= 1;
                            if remaining.values().all(|count| *count == 0) {
                                return Ok(());
                            }
                        }
                        Some(_) => {}
                        None => {
                            return Err(anyhow!(
                                "node {node_index} observed unexpected vote sender {peer:?} for block {expected_hash}"
                            ));
                        }
                    }
                }
                Ok(NodeEvent::VoteRejected { peer, vote, reason })
                    if vote.vote.block_hash == expected_hash =>
                {
                    return Err(anyhow!(
                        "node {node_index} observed vote rejection from {peer:?}: {reason}"
                    ));
                }
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(err) => return Err(anyhow!("event stream closed: {err}")),
            }
        }
    })
    .await
    .context("waiting for vote events")??;
    Ok(())
}
