use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::to_vec;
use tokio::time::timeout;

use rpp_chain::rpp::TimetokeRecord;
use rpp_chain::runtime::node_runtime::node::{NodeEvent, TimetokeDeltaBroadcast};
use rpp_chain::types::Address;

#[path = "../../../tests/support/cluster.rs"]
mod cluster;

use cluster::TestCluster;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);
const EVENT_TIMEOUT: Duration = Duration::from_secs(10);

fn build_timetoke_record(identity: Address) -> TimetokeRecord {
    TimetokeRecord {
        identity,
        balance: 48,
        epoch_accrual: 0,
        decay_rate: 1.0,
        last_update: 1_680_300_000,
        last_sync: 1_680_300_000,
        last_decay: 1_680_299_000,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn timetoke_delta_gossip_updates_remote_ledger() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match TestCluster::start(2).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping meta timetoke gossip test: {err:?}");
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

    let identity = publisher.node_handle.address().to_string();
    let record = build_timetoke_record(identity.clone());

    let updated = publisher
        .node_handle
        .sync_timetoke_records(vec![record.clone()])
        .context("apply local timetoke delta")?;
    assert!(
        updated.contains(&identity),
        "local timetoke update missing identity"
    );

    let mut events = subscriber.p2p_handle.subscribe();
    let (peer, delta) = timeout(EVENT_TIMEOUT, async {
        loop {
            match events.recv().await {
                Ok(NodeEvent::TimetokeDelta { peer, delta }) => break Ok((peer, delta)),
                Ok(_) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(err) => break Err(err),
            }
        }
    })
    .await
    .context("await timetoke delta event")??;

    assert_eq!(peer, publisher_peer, "timetoke delta peer mismatch");
    assert_eq!(delta.records.len(), 1, "unexpected timetoke record count");
    assert_eq!(
        delta.records[0].identity, record.identity,
        "identity mismatch"
    );
    assert_eq!(delta.records[0].balance, record.balance, "balance mismatch");
    assert_eq!(
        delta.records[0].last_update, record.last_update,
        "last update mismatch"
    );
    assert_eq!(
        delta.records[0].last_sync, record.last_sync,
        "last sync mismatch"
    );
    assert_eq!(
        delta.records[0].last_decay, record.last_decay,
        "last decay mismatch"
    );
    assert_eq!(delta.timetoke_root.len(), 64, "timetoke root length");

    let remote_account = subscriber
        .node_handle
        .get_account(&identity)
        .context("fetch remote account")?
        .expect("remote validator account");
    assert_eq!(
        remote_account.reputation.timetokes.hours_online, record.balance as u64,
        "remote hours_online mismatch"
    );
    assert_eq!(
        remote_account.reputation.timetokes.last_sync_timestamp, record.last_sync,
        "remote last_sync mismatch"
    );
    assert_eq!(
        remote_account.reputation.timetokes.last_proof_timestamp, record.last_update,
        "remote last_update mismatch"
    );

    // Ensure the delta payload can be re-encoded for witness subscribers.
    let encoded = to_vec(&TimetokeDeltaBroadcast {
        timetoke_root: delta.timetoke_root.clone(),
        records: delta.records.clone(),
    })
    .context("re-encode timetoke delta")?;
    assert!(
        !encoded.is_empty(),
        "encoded timetoke delta must not be empty"
    );

    cluster.shutdown().await.context("cluster shutdown")?;
    Ok(())
}
