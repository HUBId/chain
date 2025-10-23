use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{from_slice, to_vec};
use tokio::time::timeout;

use rpp_chain::consensus::{EvidenceKind, EvidenceRecord};
use rpp_chain::runtime::node_runtime::node::NodeEvent;
use rpp_p2p::GossipTopic;

#[path = "../../../tests/support/cluster.rs"]
mod cluster;

use cluster::TestCluster;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

#[test]
fn evidence_payload_roundtrip() -> Result<()> {
    let record = EvidenceRecord {
        address: "validator-0".to_string(),
        height: 42,
        round: 7,
        kind: EvidenceKind::InvalidProposal,
        vote_kind: None,
        block_hashes: vec!["0xdeadbeef".to_string()],
    };

    let bytes = to_vec(&record).context("encode evidence payload")?;
    let decoded: EvidenceRecord = from_slice(&bytes).context("decode evidence payload")?;
    assert_eq!(decoded, record);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn gossip_pipeline_forwards_evidence_payloads() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping meta evidence gossip test: {err:?}");
            return Ok(());
        }
    };

    cluster
        .wait_for_full_mesh(NETWORK_TIMEOUT)
        .await
        .context("cluster mesh formation")?;

    let nodes = cluster.nodes();
    let publisher = &nodes[0];
    let subscriber = &nodes[1];
    let publisher_peer = publisher.p2p_handle.local_peer_id();

    let evidence = EvidenceRecord {
        address: "validator-0".to_string(),
        height: 99,
        round: 3,
        kind: EvidenceKind::InvalidProposal,
        vote_kind: None,
        block_hashes: vec!["0xabc".to_string(), "0xdef".to_string()],
    };
    let payload = to_vec(&evidence).context("encode evidence payload")?;

    publisher
        .p2p_handle
        .publish_gossip(GossipTopic::Meta, payload)
        .await
        .context("publish meta evidence")?;

    let mut events = subscriber.p2p_handle.subscribe();
    let observed = timeout(EVENT_TIMEOUT, async {
        loop {
            match events.recv().await {
                Ok(NodeEvent::Evidence { peer, evidence }) => break Ok((peer, evidence)),
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(err) => break Err(err),
            }
        }
    })
    .await
    .context("await evidence gossip")??;

    assert_eq!(observed.0, publisher_peer, "evidence peer mismatch");
    assert_eq!(observed.1, evidence, "evidence payload mismatch");

    cluster.shutdown().await.context("cluster shutdown")?;
    Ok(())
}
