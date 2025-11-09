#![cfg(feature = "integration")]

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use reqwest::{Client, StatusCode};
use serde_json::json;
use tempfile::TempDir;
use tokio::time::sleep;

use rpp_chain::config::{
    NetworkAdmissionWormConfig, WormExportTargetConfig, WormRetentionModeConfig,
};

#[path = "../support/mod.rs"]
mod support;

#[path = "../observability/metrics_utils.rs"]
mod metrics_utils;

use support::{
    capture_child_output, locate_binary, locate_rpp_node_binary, pick_free_tcp_port, send_ctrl_c,
    start_log_drain, wait_for_exit, wait_for_log, write_node_config_with, ChildTerminationGuard,
    PortAllocator, TelemetryExpectation,
};

const FAILURE_METRIC: &str = "worm_export_failures_total";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worm_export_failure_emits_metric_and_log() -> Result<()> {
    let temp_dir = TempDir::new().context("create temporary directory")?;
    let stub_storage = temp_dir.path().join("worm-storage");
    fs::create_dir_all(&stub_storage).with_context(|| {
        format!(
            "create stub storage directory at {}",
            stub_storage.display()
        )
    })?;
    let _storage_guard = ReadonlyDirGuard::new(stub_storage.clone())?;

    let stub_binary =
        locate_binary("worm-export-stub").context("locate worm-export-stub binary")?;
    let stub_port = pick_free_tcp_port().context("allocate stub listen port")?;
    let mut stub_command = Command::new(&stub_binary);
    stub_command
        .arg("--listen")
        .arg(format!("127.0.0.1:{stub_port}"))
        .arg("--storage")
        .arg(&stub_storage)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut stub_child = stub_command
        .spawn()
        .context("spawn worm-export-stub process")?;
    let mut stub_guard = ChildTerminationGuard {
        child: Some(&mut stub_child),
    };
    let mut stub_logs = capture_child_output(&mut stub_child);
    wait_for_log(&mut stub_logs, "worm-export-stub listening")
        .context("wait for stub readiness log line")?;
    start_log_drain(stub_logs);
    let stub_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), stub_port);
    wait_for_tcp_ready(stub_addr).context("wait for worm-export-stub socket")?;

    let node_binary = locate_rpp_node_binary().context("locate rpp-node binary")?;
    let mut ports = PortAllocator::default();
    let rpc_port = ports.next_port().context("allocate RPC port")?;
    let metrics_port = ports.next_port().context("allocate metrics port")?;
    let rpc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpc_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), metrics_port);

    let worm_endpoint = format!("http://127.0.0.1:{stub_port}");
    let node_config = write_node_config_with(
        temp_dir.path(),
        Some(TelemetryExpectation::Disabled),
        &mut ports,
        |config| {
            config.network.rpc.listen = rpc_addr;
            config.rollout.telemetry.enabled = true;
            config.rollout.telemetry.endpoint = None;
            config.rollout.telemetry.http_endpoint = None;
            config.rollout.telemetry.auth_token = None;
            config.rollout.telemetry.metrics.listen = Some(metrics_addr);
            config.rollout.telemetry.metrics.auth_token = None;
            config.rollout.telemetry.sample_interval_secs = 1;
            config.rollout.telemetry.redact_logs = false;
            config.network.p2p.bootstrap_peers.clear();
            config.genesis.chain_id = "worm-export-failure".to_string();

            let mut worm_config = NetworkAdmissionWormConfig::default();
            worm_config.enabled = true;
            worm_config.required = true;
            worm_config.retention_days = 1;
            worm_config.retention_mode = WormRetentionModeConfig::Compliance;
            worm_config.require_signatures = false;
            worm_config.target = Some(WormExportTargetConfig::S3 {
                endpoint: Some(worm_endpoint.clone()),
                region: "stub-region".to_string(),
                bucket: "worm-audit".to_string(),
                prefix: Some("admission".to_string()),
                access_key: "stub-access".to_string(),
                secret_key: "stub-secret".to_string(),
                session_token: None,
                path_style: true,
            });
            config.network.admission.worm_export = worm_config;
        },
    )
    .context("write node configuration with WORM export settings")?;

    let mut node_command = Command::new(&node_binary);
    node_command
        .arg("validator")
        .arg("--node-config")
        .arg(&node_config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(
            "RUST_LOG",
            "info,rpp_node=info,rpp_chain=info,rpp_p2p=info,rpp_node::runtime=info",
        );
    let mut node_child = node_command
        .spawn()
        .context("spawn rpp-node validator process")?;
    let mut node_guard = ChildTerminationGuard {
        child: Some(&mut node_child),
    };
    let mut node_logs = capture_child_output(&mut node_child);
    wait_for_log(&mut node_logs, "bootstrap configuration resolved")
        .context("wait for bootstrap log")?;
    wait_for_log(&mut node_logs, "node runtime started").context("wait for runtime start log")?;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("construct HTTP client")?;
    let response = client
        .post(format!("http://{}/p2p/admission/policies", rpc_addr))
        .json(&json!({
            "allowlist": [],
            "blocklist": [],
            "actor": "ops",
            "reason": "worm export failure compliance test",
            "approvals": []
        }))
        .send()
        .await
        .context("submit admission policy update")?;

    let status = response.status();
    let body = response
        .text()
        .await
        .context("read admission policy response body")?;
    assert_eq!(
        status,
        StatusCode::BAD_GATEWAY,
        "expected admission update to surface WORM export failure (got {status}, body: {body})",
    );
    assert!(
        body.contains("worm export"),
        "expected worm export error in admission response body: {body}"
    );

    wait_for_log(&mut node_logs, "failed to append admission audit log")
        .context("wait for worm export failure log message")?;

    let metric_value = wait_for_metric(&client, metrics_addr, FAILURE_METRIC, 1.0).await?;
    assert!(
        metric_value >= 1.0,
        "expected worm export failure metric to reach at least 1, observed {metric_value}"
    );

    start_log_drain(node_logs);
    send_ctrl_c(node_guard.child.as_ref().expect("node child reference"))
        .context("signal rpp-node shutdown")?;
    wait_for_exit(
        node_guard
            .child
            .as_mut()
            .expect("node child mutable reference"),
    )
    .context("wait for rpp-node process exit")?;
    node_guard.child.take();

    send_ctrl_c(stub_guard.child.as_ref().expect("stub child reference"))
        .context("signal worm-export-stub shutdown")?;
    wait_for_exit(
        stub_guard
            .child
            .as_mut()
            .expect("stub child mutable reference"),
    )
    .context("wait for worm-export-stub exit")?;
    stub_guard.child.take();

    Ok(())
}

async fn wait_for_metric(
    client: &Client,
    addr: SocketAddr,
    name: &str,
    expected: f64,
) -> Result<f64> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let metrics = metrics_utils::fetch_metrics(client, addr)
            .await
            .context("fetch Prometheus metrics")?;
        if let Some(value) = metrics_utils::metric_value(&metrics, name, &[]) {
            if value >= expected {
                return Ok(value);
            }
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "metric {name} did not reach {expected} within allotted time"
            ));
        }
        sleep(Duration::from_millis(250)).await;
    }
}

fn wait_for_tcp_ready(addr: SocketAddr) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    Err(anyhow!("timed out waiting for {addr}"))
}

struct ReadonlyDirGuard {
    path: PathBuf,
}

impl ReadonlyDirGuard {
    fn new(path: PathBuf) -> Result<Self> {
        let metadata =
            fs::metadata(&path).with_context(|| format!("read metadata for {}", path.display()))?;
        let mut permissions = metadata.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions)
            .with_context(|| format!("mark {} as read-only", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for ReadonlyDirGuard {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::metadata(&self.path) {
            let mut permissions = metadata.permissions();
            permissions.set_readonly(false);
            let _ = fs::set_permissions(&self.path, permissions);
        }
    }
}
