use std::time::Duration;

use anyhow::{anyhow, ensure, Context, Result};
use tokio::time::sleep;

use rpp_chain::runtime::node_runtime::node::{IdentityProfile, NodeError};
use rpp_chain::storage::ledger::SlashingReason;
use rpp_p2p::admission::AdmissionError;
use rpp_p2p::{GossipTopic, NetworkError, TierLevel};

mod support;

use support::cluster::TestCluster;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);
const POLL_INTERVAL: Duration = Duration::from_millis(200);
const MAX_ATTEMPTS: usize = 50;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slashed_peer_cannot_publish_consensus_gossip() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping admission control test: {err:?}");
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let nodes = cluster.nodes();
        let target = &nodes[1];

        let initial_profile = target
            .node_handle
            .network_identity_profile()
            .context("fetch initial identity profile")?;
        ensure!(
            initial_profile.tier >= TierLevel::Tl1,
            "expected validator tier before slashing, found {:?}",
            initial_profile.tier
        );

        target
            .p2p_handle
            .publish_gossip(GossipTopic::Blocks, b"pre-slash".to_vec())
            .await
            .context("pre-slash consensus gossip publish")?;

        target
            .node_handle
            .slash_validator(target.node_handle.address(), SlashingReason::ConsensusFault)
            .context("apply local slashing")?;

        let mut attempts = 0;
        loop {
            let profile = target
                .node_handle
                .network_identity_profile()
                .context("refresh identity profile")?;
            if profile.tier == TierLevel::Tl0 {
                break;
            }
            if attempts >= MAX_ATTEMPTS {
                return Err(anyhow!("timed out waiting for tier downgrade"));
            }
            attempts += 1;
            sleep(POLL_INTERVAL).await;
        }

        let publish_result = target
            .p2p_handle
            .publish_gossip(GossipTopic::Blocks, b"post-slash".to_vec())
            .await;

        match publish_result {
            Err(NodeError::Network(NetworkError::Admission(
                AdmissionError::TierInsufficient { .. },
            ))) => {}
            Err(other @ NodeError::Network(NetworkError::Admission(_))) => {
                return Err(anyhow!("unexpected admission error: {other:?}"));
            }
            Err(other) => {
                return Err(anyhow!("unexpected publish error: {other:?}"));
            }
            Ok(()) => return Err(anyhow!("expected consensus gossip publish to be rejected")),
        }

        Ok(())
    }
    .await;

    cluster.shutdown().await?;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tier_two_identity_cannot_publish_votes_gossip() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping admission control test: {err:?}");
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let nodes = cluster.nodes();
        let node = &nodes[0];

        let mut profile: IdentityProfile = node
            .node_handle
            .network_identity_profile()
            .context("fetch identity profile")?
            .into();
        profile.tier = TierLevel::Tl2;

        node
            .p2p_handle
            .update_identity(profile)
            .await
            .context("apply tier downgrade")?;

        let publish_result = node
            .p2p_handle
            .publish_gossip(GossipTopic::Votes, b"tier-check".to_vec())
            .await;

        assert!(
            matches!(
                publish_result,
                Err(NodeError::Network(NetworkError::Admission(_)))
            ),
            "expected tier 2 node to be rejected from publishing votes gossip, got {publish_result:?}"
        );

        Ok(())
    }
    .await;

    cluster.shutdown().await?;
    result
}
