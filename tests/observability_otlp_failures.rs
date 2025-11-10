#![cfg(feature = "integration")]

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use tempfile::TempDir;

use rpp_chain::runtime::config::TelemetryTlsConfig;

#[path = "support/mod.rs"]
mod support;

#[path = "observability/metrics_utils.rs"]
mod metrics_utils;

use support::{
    capture_child_output, locate_rpp_node_binary, send_ctrl_c, start_log_drain, wait_for_exit,
    wait_for_log, write_node_config_with, ChildTerminationGuard, PortAllocator,
    TelemetryExpectation,
};

const OTLP_FAILURE_METRIC: &str = "telemetry_otlp_failures_total";

#[test]
fn telemetry_otlp_exporter_failures_surface_alerts() -> Result<()> {
    let temp_dir = TempDir::new().context("create temporary directory")?;
    let binary = locate_rpp_node_binary().context("locate rpp-node binary")?;
    let mut ports = PortAllocator::default();

    let rpc_port = ports.next_port().context("allocate RPC port")?;
    let metrics_port = ports.next_port().context("allocate metrics port")?;
    let grpc_port = ports.next_port().context("allocate gRPC endpoint port")?;
    let http_port = ports.next_port().context("allocate HTTP endpoint port")?;

    let rpc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpc_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), metrics_port);
    let tls_stub = temp_dir.path().join("tls-stub");
    fs::create_dir(&tls_stub).context("create TLS stub directory")?;

    let node_config = write_node_config_with(
        temp_dir.path(),
        Some(TelemetryExpectation::Disabled),
        &mut ports,
        |config| {
            config.network.rpc.listen = rpc_addr;
            config.network.p2p.bootstrap_peers.clear();
            config.rollout.telemetry.enabled = true;
            config.rollout.telemetry.endpoint = Some(format!("http://127.0.0.1:{grpc_port}"));
            config.rollout.telemetry.http_endpoint =
                Some(format!("http://127.0.0.1:{http_port}/v1/metrics"));
            config.rollout.telemetry.sample_interval_secs = 1;
            config.rollout.telemetry.auth_token = None;
            config.rollout.telemetry.metrics.listen = Some(metrics_addr);
            config.rollout.telemetry.metrics.auth_token = None;
            config.rollout.telemetry.http_tls = Some(TelemetryTlsConfig {
                ca_certificate: Some(tls_stub.clone()),
                ..TelemetryTlsConfig::default()
            });
            config.rollout.telemetry.grpc_tls = Some(TelemetryTlsConfig {
                ca_certificate: Some(tls_stub.clone()),
                ..TelemetryTlsConfig::default()
            });
        },
    )
    .context("write node configuration")?;

    let mut command = Command::new(&binary);
    command
        .arg("validator")
        .arg("--node-config")
        .arg(&node_config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(
            "RUST_LOG",
            "info,rpp_node=info,rpp_chain=info,rpp_node::runtime=info",
        );

    let mut child = command
        .spawn()
        .context("spawn rpp-node with OTLP failure configuration")?;
    let mut guard = ChildTerminationGuard {
        child: Some(&mut child),
    };
    let mut logs = capture_child_output(&mut child);

    wait_for_log(&mut logs, "bootstrap configuration resolved")
        .context("wait for bootstrap log")?;
    wait_for_log(&mut logs, "telemetry endpoints configured")
        .context("wait for telemetry endpoint log")?;

    wait_for_log(&mut logs, "failed to initialise OTLP metric exporter")
        .context("wait for metric exporter failure log")?;
    wait_for_log(&mut logs, "failed to initialise OTLP span exporter")
        .context("wait for span exporter failure log")?;

    thread::sleep(Duration::from_secs(1));

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("build HTTP client")?;
    let metrics_body = client
        .get(format!("http://{metrics_addr}/metrics"))
        .send()
        .context("request metrics endpoint")?
        .error_for_status()
        .context("metrics endpoint returned error status")?
        .text()
        .context("read metrics body")?;

    let metrics_value = metrics_utils::metric_value(
        &metrics_body,
        OTLP_FAILURE_METRIC,
        &[("sink", "metrics"), ("phase", "init")],
    )
    .unwrap_or(0.0);
    assert!(
        metrics_value >= 1.0,
        "expected metrics exporter failures to be recorded, found {metrics_value}"
    );

    let traces_value = metrics_utils::metric_value(
        &metrics_body,
        OTLP_FAILURE_METRIC,
        &[("sink", "traces"), ("phase", "init")],
    )
    .unwrap_or(0.0);
    assert!(
        traces_value >= 1.0,
        "expected span exporter failures to be recorded, found {traces_value}"
    );

    let still_running = guard
        .child
        .as_mut()
        .expect("child reference")
        .try_wait()
        .context("poll child status")?;
    assert!(still_running.is_none(), "rpp-node terminated unexpectedly");

    start_log_drain(logs);
    send_ctrl_c(guard.child.as_ref().expect("child reference"))
        .context("signal rpp-node shutdown")?;
    wait_for_exit(guard.child.as_mut().expect("child reference"))
        .context("wait for rpp-node exit")?;
    guard.child.take();

    Ok(())
}
