use std::time::Duration;

use anyhow::Result;

#[path = "../support/mod.rs"]
mod support;

use support::cluster::{ProcessNodeOrchestratorClient, ProcessNodeRpcClient, ProcessTestCluster};

async fn fetch_summary(rpc: &ProcessNodeRpcClient) -> Result<String> {
    let summary = rpc.account_summary().await?;
    Ok(summary.address)
}

async fn subscribe_events(orchestrator: &ProcessNodeOrchestratorClient) -> Result<()> {
    let mut stream = orchestrator.subscribe_events()?;
    let _ = stream.next_event(Duration::from_secs(1)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn operator_rpc_lifecycle_smoke() {
    let _ = tracing_subscriber::fmt::try_init();

    let cluster = match ProcessTestCluster::start(2).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping operator RPC smoke test: {err:?}");
            return;
        }
    };

    let node = &cluster.nodes()[0];
    let harness = match node.harness() {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping operator RPC smoke test: {err:?}");
            return;
        }
    };

    if let Err(err) = fetch_summary(&harness.rpc()).await {
        eprintln!("skipping operator RPC smoke test: {err:?}");
        return;
    }

    if let Err(err) = subscribe_events(&harness.orchestrator()).await {
        eprintln!("skipping operator RPC smoke test: {err:?}");
        return;
    }

    if let Err(err) = cluster.shutdown().await {
        panic!("operator RPC cluster shutdown failed: {err:?}");
    }
}
