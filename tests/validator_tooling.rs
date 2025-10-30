use std::fs;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use assert_cmd::Command;
use parking_lot::RwLock;
use reqwest::Client;
use serde_json::Value;
use tempfile::TempDir;
use tokio::time::{sleep, Duration};

mod support;

use support::cluster::TestCluster;

use rpp_chain::api;
use rpp_chain::runtime::config::{NetworkLimitsConfig, NetworkTlsConfig};
use rpp_chain::runtime::RuntimeMode;

#[test]
fn validator_cli_vrf_workflow() -> Result<()> {
    let temp = TempDir::new().context("create validator temp dir")?;
    let config_path = temp.path().join("validator.toml");
    let template =
        fs::read_to_string("config/validator.toml").context("load validator config template")?;
    fs::write(&config_path, template).context("write validator config copy")?;
    fs::create_dir_all(temp.path().join("keys")).context("prepare key directory")?;

    let config_arg = config_path
        .to_str()
        .context("validator config path encoding")?
        .to_string();

    let rotate_output = Command::cargo_bin("rpp-node")?
        .current_dir(temp.path())
        .args(["validator", "vrf", "rotate", "--config", &config_arg])
        .output()
        .context("execute VRF rotate command")?;
    if !rotate_output.status.success() {
        anyhow::bail!("vrf rotate exited with {:?}", rotate_output.status);
    }
    let rotate_stdout =
        String::from_utf8(rotate_output.stdout).context("decode vrf rotate output")?;
    let public_key = extract_marker(&rotate_stdout, "public_key=")?;

    assert!(
        temp.path().join("keys/vrf.toml").exists(),
        "expected vrf key file to be created"
    );

    let inspect_output = Command::cargo_bin("rpp-node")?
        .current_dir(temp.path())
        .args(["validator", "vrf", "inspect", "--config", &config_arg])
        .output()
        .context("execute VRF inspect command")?;
    if !inspect_output.status.success() {
        anyhow::bail!("vrf inspect exited with {:?}", inspect_output.status);
    }
    let inspect_stdout =
        String::from_utf8(inspect_output.stdout).context("decode vrf inspect output")?;
    assert!(
        inspect_stdout.contains(&public_key),
        "inspect output missing rotated public key"
    );

    let export_path = temp.path().join("vrf_export.json");
    let export_arg = export_path
        .to_str()
        .context("vrf export path encoding")?
        .to_string();
    let export_output = Command::cargo_bin("rpp-node")?
        .current_dir(temp.path())
        .args([
            "validator",
            "vrf",
            "export",
            "--config",
            &config_arg,
            "--output",
            &export_arg,
        ])
        .output()
        .context("execute VRF export command")?;
    if !export_output.status.success() {
        anyhow::bail!("vrf export exited with {:?}", export_output.status);
    }
    let export_payload: Value = serde_json::from_str(
        &fs::read_to_string(&export_path).context("read exported vrf payload")?,
    )
    .context("decode exported vrf payload")?;
    assert_eq!(
        export_payload
            .get("public_key")
            .and_then(|value| value.as_str()),
        Some(public_key.as_str()),
        "exported public key mismatch"
    );
    assert!(
        export_payload
            .get("secret_key")
            .and_then(|value| value.as_str())
            .is_some(),
        "export payload missing secret key"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validator_rpc_and_cli_tooling() -> Result<()> {
    let mut cluster = TestCluster::start(3)
        .await
        .context("launch validator cluster")?;
    let primary = cluster
        .nodes()
        .first()
        .context("cluster returned no nodes")?;
    let addr = primary.config.network.rpc.listen;
    let node_handle = primary.node_handle.clone();
    let wallet = primary.wallet.clone();
    let orchestrator = primary.orchestrator.clone();

    let runtime_mode = Arc::new(RwLock::new(RuntimeMode::Node));
    let context = api::ApiContext::new(
        runtime_mode,
        Some(node_handle),
        Some(wallet.clone()),
        Some(orchestrator),
        None,
        false,
        None,
        None,
        true,
    );
    let rpc_task = tokio::spawn(async move {
        api::serve(
            context,
            addr,
            None,
            None,
            NetworkLimitsConfig::default(),
            NetworkTlsConfig::default(),
        )
        .await
    });

    let client = Client::builder()
        .build()
        .context("build telemetry client")?;
    let base_url = format!("http://{}", addr);
    wait_for_server(&client, &base_url).await?;

    let vrf_initial = client
        .get(format!("{}/validator/vrf", base_url))
        .send()
        .await
        .context("request validator vrf status")?;
    assert!(
        vrf_initial.status().is_success(),
        "validator vrf status: {}",
        vrf_initial.status()
    );
    let vrf_payload: Value = vrf_initial.json().await.context("decode vrf response")?;
    assert_eq!(
        vrf_payload
            .get("available")
            .and_then(|value| value.as_bool()),
        Some(true),
        "expected vrf key to be available"
    );

    let rotate = client
        .post(format!("{}/validator/vrf/rotate", base_url))
        .send()
        .await
        .context("rotate validator vrf")?;
    assert!(
        rotate.status().is_success(),
        "validator vrf rotate status: {}",
        rotate.status()
    );
    let rotate_payload: Value = rotate.json().await.context("decode rotate response")?;
    let rotated_key = rotate_payload
        .get("public_key")
        .and_then(|value| value.as_str())
        .context("rotate response missing public key")?;
    assert!(!rotated_key.is_empty(), "rotate returned empty public key");

    let telemetry = client
        .get(format!("{}/validator/telemetry", base_url))
        .send()
        .await
        .context("request validator telemetry")?;
    assert!(
        telemetry.status().is_success(),
        "validator telemetry status: {}",
        telemetry.status()
    );
    let telemetry_payload: Value = telemetry
        .json()
        .await
        .context("decode validator telemetry response")?;
    assert!(
        telemetry_payload
            .get("node")
            .and_then(|value| value.get("height"))
            .and_then(|value| value.as_u64())
            .is_some(),
        "telemetry payload missing node height"
    );
    assert!(
        telemetry_payload
            .get("mempool")
            .and_then(|value| value.get("uptime_proofs"))
            .and_then(|value| value.as_u64())
            .is_some(),
        "telemetry payload missing mempool uptime proofs"
    );

    let cli_output = tokio::task::spawn_blocking({
        let base = base_url.clone();
        move || -> Result<String> {
            let output = Command::cargo_bin("rpp-node")?
                .args(["validator", "telemetry", "--rpc-url", &base])
                .output()
                .context("execute telemetry CLI command")?;
            if !output.status.success() {
                return Err(anyhow!("telemetry CLI failed with {:?}", output.status));
            }
            String::from_utf8(output.stdout).context("decode telemetry CLI output")
        }
    })
    .await??;
    let cli_payload: Value =
        serde_json::from_str(cli_output.trim()).context("decode telemetry CLI JSON")?;
    assert!(
        cli_payload
            .get("consensus")
            .and_then(|value| value.get("leader_changes"))
            .and_then(|value| value.as_u64())
            .is_some(),
        "CLI telemetry payload missing consensus leader changes"
    );

    rpc_task.abort();
    let _ = rpc_task.await;
    cluster.shutdown().await.context("shutdown cluster")?;

    Ok(())
}

fn extract_marker(output: &str, marker: &str) -> Result<String> {
    let segment = output
        .split(marker)
        .nth(1)
        .with_context(|| format!("output missing `{marker}`: {output}"))?;
    let value = segment
        .split_whitespace()
        .next()
        .with_context(|| format!("output missing value for `{marker}`: {output}"))?;
    Ok(value.to_string())
}

async fn wait_for_server(client: &Client, base_url: &str) -> Result<()> {
    let health_url = format!("{}/health", base_url);
    for _ in 0..50 {
        match client.get(&health_url).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            _ => sleep(Duration::from_millis(100)).await,
        }
    }
    anyhow::bail!("RPC server failed to become ready");
}
