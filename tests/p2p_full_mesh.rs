use std::time::Duration;

use anyhow::Result;

mod support;

use support::cluster::TestCluster;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(15);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cluster_forms_full_mesh() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = TestCluster::start(3).await?;

    cluster
        .wait_for_full_mesh(NETWORK_TIMEOUT)
        .await?;

    let nodes = cluster.nodes();

    assert_eq!(nodes.len(), 3, "expected three nodes in the cluster");

    cluster.shutdown().await?;

    Ok(())
}
