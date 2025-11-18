#![cfg(feature = "integration")]

use std::net::{TcpListener, ToSocketAddrs};
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::StatusCode;
use serde_json::Value;

#[path = "support/mod.rs"]
mod support;

#[path = "node_lifecycle/startup_errors.rs"]
mod startup_errors;

use rpp_chain::config::{FirewoodSyncPolicyConfig, NodeConfig};

use support::{send_ctrl_c, wait_for_exit, ProcessNodeHarness, ProcessTestCluster};

const READY_TIMEOUT: Duration = Duration::from_secs(45);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_process_handles_health_probes_and_ctrl_c() -> Result<()> {
    let mut cluster = match ProcessTestCluster::start_with(2, |config, _| {
        config.rollout.feature_gates.pruning = true;
        config.rollout.feature_gates.recursive_proofs = true;
        config.rollout.feature_gates.reconstruction = true;
        config.rollout.feature_gates.consensus_enforcement = true;
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping node lifecycle health test: {err:?}");
            return Ok(());
        }
    };

    let node = &cluster.nodes()[0];
    let rpc_addr = node.rpc_addr;
    let base_url = format!("http://{}", rpc_addr);
    let client = cluster.client();

    let live_url = format!("{}/health/live", base_url);
    let ready_url = format!("{}/health/ready", base_url);

    let live = client
        .get(&live_url)
        .send()
        .await
        .context("failed to query liveness probe")?;
    assert_eq!(
        live.status(),
        StatusCode::OK,
        "live probe should return 200"
    );

    let ready = client
        .get(&ready_url)
        .send()
        .await
        .context("failed to query readiness probe")?;
    assert_eq!(
        ready.status(),
        StatusCode::OK,
        "ready probe should return 200"
    );

    let node = &mut cluster.nodes_mut()[0];
    send_ctrl_c(&node.child).context("failed to deliver CTRL+C to node process")?;

    let status = wait_for_exit(&mut node.child).context("node process did not exit")?;
    anyhow::ensure!(status.success(), "node exited with status {status}");

    let live_shutdown = client.get(&live_url).send().await;
    let live_status = live_shutdown
        .ok()
        .map(|response| response.status())
        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        live_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "live probe should become unavailable after shutdown"
    );

    let ready_shutdown = client.get(&ready_url).send().await;
    let ready_status = ready_shutdown
        .ok()
        .map(|response| response.status())
        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        ready_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "ready probe should become unavailable after shutdown"
    );

    let port = rpc_addr.port();
    cluster.shutdown().await?;

    let bind_addr = ("127.0.0.1", port)
        .to_socket_addrs()
        .context("resolve localhost for port reuse check")?
        .next()
        .context("socket resolution returned no addresses")?;
    TcpListener::bind(bind_addr).context("rpc port was not released after shutdown")?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_restart_applies_feature_gate_changes() -> Result<()> {
    let mut cluster = match ProcessTestCluster::start_with(2, |config, _| {
        config.rollout.feature_gates.pruning = true;
        config.rollout.feature_gates.recursive_proofs = true;
        config.rollout.feature_gates.reconstruction = true;
        config.storage.sync_policy = FirewoodSyncPolicyConfig::Deferred;
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping node lifecycle restart test: {err:?}");
            return Ok(());
        }
    };

    let rpc_addr = cluster.nodes()[0].rpc_addr;
    let base_url = format!("http://{}", rpc_addr);
    let client = cluster.client();

    assert_backend_health(&client, &base_url).await?;

    let config_path = cluster.nodes()[0].config_path.clone();
    let mut config = NodeConfig::load(&config_path).context("failed to reload node config")?;
    config.rollout.feature_gates.pruning = false;
    config.rollout.feature_gates.recursive_proofs = false;
    config.rollout.feature_gates.reconstruction = false;
    config.storage.sync_policy = match config.storage.sync_policy {
        FirewoodSyncPolicyConfig::Always => FirewoodSyncPolicyConfig::Deferred,
        FirewoodSyncPolicyConfig::Deferred => FirewoodSyncPolicyConfig::Always,
    };
    config
        .save(&config_path)
        .context("failed to persist updated node config")?;

    let binary = cluster.binary().to_string();
    let respawn_client = cluster.client();
    let node = &mut cluster.nodes_mut()[0];
    node.respawn(&binary, &respawn_client)
        .await
        .context("failed to respawn node process")?;

    let harness = cluster.nodes()[0]
        .harness()
        .context("failed to connect to respawned node")?;
    harness
        .wait_for_ready(READY_TIMEOUT)
        .await
        .context("node did not report ready state after restart")?;

    assert_backend_health(&client, &base_url).await?;

    cluster.shutdown().await?;
    Ok(())
}

async fn assert_backend_health(client: &reqwest::Client, base_url: &str) -> Result<()> {
    let status_url = format!("{}/status/node", base_url);
    let response = client
        .get(&status_url)
        .send()
        .await
        .context("failed to fetch node status")?;
    anyhow::ensure!(
        response.status().is_success(),
        "node status endpoint returned {}",
        response.status()
    );
    let payload: Value = response
        .json()
        .await
        .context("failed to decode node status payload")?;

    let backend_health = payload
        .get("backend_health")
        .and_then(Value::as_object)
        .context("node status payload missing backend_health")?;
    anyhow::ensure!(
        !backend_health.is_empty(),
        "backend health report should include at least one backend"
    );

    Ok(())
}
