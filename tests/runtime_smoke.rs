#![cfg(feature = "integration")]

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use reqwest::blocking::Client;
use reqwest::StatusCode;
use tempfile::TempDir;

#[path = "support/mod.rs"]
mod support;

use rpp_chain::config::NodeConfig;

use support::{
    capture_child_output, locate_rpp_node_binary, send_ctrl_c, start_log_drain, wait_for_exit,
    write_node_config_with, ChildTerminationGuard, PortAllocator, TelemetryExpectation,
    INIT_TIMEOUT,
};

struct RuntimeSmokeSpec {
    name: &'static str,
    configure: fn(&mut NodeConfig),
}

#[test]
fn runtime_smoke_telemetry_disabled() -> Result<()> {
    run_runtime_smoke(RuntimeSmokeSpec {
        name: "telemetry-disabled",
        configure: |config| {
            config.rollout.feature_gates.consensus_enforcement = true;
            config.rollout.telemetry.enabled = false;
            config.rollout.telemetry.endpoint = None;
            config.rollout.telemetry.http_endpoint = None;
            config.rollout.telemetry.auth_token = None;
            config.rollout.telemetry.metrics.listen = None;
            config.rollout.telemetry.metrics.auth_token = None;
        },
    })
}

#[cfg(feature = "backend-rpp-stark")]
#[test]
fn runtime_smoke_alternate_consensus_backend() -> Result<()> {
    run_runtime_smoke(RuntimeSmokeSpec {
        name: "alternate-consensus-backend",
        configure: |config| {
            config.rollout.feature_gates.consensus_enforcement = true;
            config.rollout.feature_gates.malachite_consensus = true;
            config.rollout.telemetry.enabled = false;
            config.rollout.telemetry.endpoint = None;
            config.rollout.telemetry.http_endpoint = None;
            config.rollout.telemetry.auth_token = None;
            config.rollout.telemetry.metrics.listen = None;
            config.rollout.telemetry.metrics.auth_token = None;
        },
    })
}

fn run_runtime_smoke(spec: RuntimeSmokeSpec) -> Result<()> {
    let binary = locate_rpp_node_binary()
        .with_context(|| format!("failed to locate rpp-node binary for {}", spec.name))?;
    let temp_dir = TempDir::new()
        .with_context(|| format!("failed to create temporary directory for {}", spec.name))?;
    let mut ports = PortAllocator::default();

    let config_path = write_node_config_with(
        temp_dir.path(),
        Some(TelemetryExpectation::Disabled),
        &mut ports,
        |config| {
            (spec.configure)(config);
        },
    )
    .with_context(|| format!("failed to persist node config for {}", spec.name))?;

    let config = NodeConfig::load(&config_path)
        .with_context(|| format!("failed to reload node config for {}", spec.name))?;
    let base_url = format!("http://{}", config.network.rpc.listen);

    let mut command = Command::new(&binary);
    command
        .arg("node")
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .with_context(|| format!("failed to spawn rpp-node for {}", spec.name))?;
    let mut guard = ChildTerminationGuard {
        child: Some(&mut child),
    };

    let logs = capture_child_output(&mut child);
    start_log_drain(logs);

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("failed to build HTTP client for runtime smoke test")?;

    wait_for_ready(&client, &base_url)
        .with_context(|| format!("{} did not report ready state", spec.name))?;

    assert_eq!(
        client
            .get(format!("{}/health/live", base_url))
            .send()
            .with_context(|| format!("failed to query live probe for {}", spec.name))?
            .status(),
        StatusCode::OK,
        "{} live probe should return 200",
        spec.name,
    );

    assert_eq!(
        client
            .get(format!("{}/health/ready", base_url))
            .send()
            .with_context(|| format!("failed to query ready probe for {}", spec.name))?
            .status(),
        StatusCode::OK,
        "{} ready probe should return 200",
        spec.name,
    );

    send_ctrl_c(
        guard
            .child
            .as_ref()
            .ok_or_else(|| anyhow!("child handle missing for {}", spec.name))?,
    )
    .with_context(|| format!("failed to deliver CTRL+C to {}", spec.name))?;

    let status = wait_for_exit(
        guard
            .child
            .as_mut()
            .ok_or_else(|| anyhow!("child handle missing for {}", spec.name))?,
    )
    .with_context(|| format!("{} did not exit after shutdown signal", spec.name))?;

    anyhow::ensure!(
        status.success(),
        "{} exited with status {} during shutdown",
        spec.name,
        status
    );

    assert_unavailable(&client, &base_url, spec.name);

    guard.child.take();
    Ok(())
}

fn wait_for_ready(client: &Client, base_url: &str) -> Result<()> {
    let ready_url = format!("{}/health/ready", base_url);
    let deadline = Instant::now() + INIT_TIMEOUT;

    loop {
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "timed out waiting for readiness probe at {}",
                ready_url
            ));
        }

        match client.get(&ready_url).send() {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(_) => {}
            Err(_) => {}
        }

        thread::sleep(Duration::from_millis(200));
    }
}

fn assert_unavailable(client: &Client, base_url: &str, name: &str) {
    let live_url = format!("{}/health/live", base_url);
    let ready_url = format!("{}/health/ready", base_url);

    let live_status = client
        .get(&live_url)
        .send()
        .ok()
        .map(|response| response.status())
        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        live_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{} live probe should become unavailable after shutdown",
        name,
    );

    let ready_status = client
        .get(&ready_url)
        .send()
        .ok()
        .map(|response| response.status())
        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        ready_status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{} ready probe should become unavailable after shutdown",
        name,
    );
}
