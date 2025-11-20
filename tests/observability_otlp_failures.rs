#![cfg(feature = "integration")]

use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde_json::json;
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
const ARTIFACT_BASE: &str = "artifacts/telemetry-chaos";
const ARTIFACT_ENV: &str = "TELEMETRY_CHAOS_ARTIFACT_DIR";

#[test]
fn telemetry_otlp_exporter_failures_surface_alerts() -> Result<()> {
    let artifact_dir = telemetry_chaos_artifact_dir().context("prepare artifact directory")?;

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
    let log_buffer = LogBuffer::default();
    let mut logs = log_buffer.forward(capture_child_output(&mut child));

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

    let alert_payload = json!({
        "receiver": "telemetry-chaos-harness",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "OtlpExporterFailure",
                    "severity": "warning",
                    "service": "observability",
                },
                "annotations": {
                    "summary": "OTLP telemetry exporters are failing to initialise",
                    "description": "At least one OTLP exporter failed to initialise; inspect node logs, TLS material, and collector reachability before restarting the node.",
                    "runbook_url": "https://github.com/ava-labs/chain/blob/main/docs/observability.md#otlp-exporter-failure-drill",
                    "validation.metrics": metrics_value,
                    "validation.traces": traces_value,
                },
            },
        ],
    });

    TelemetryChaosArtifacts::new(artifact_dir, log_buffer)
        .with_metrics(metrics_body)
        .with_alert_payload(alert_payload)
        .persist()
        .context("write telemetry chaos artifacts")?;

    Ok(())
}

#[derive(Default, Clone)]
struct LogBuffer {
    lines: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

impl LogBuffer {
    fn forward(
        &self,
        logs: std::sync::mpsc::Receiver<String>,
    ) -> std::sync::mpsc::Receiver<String> {
        let (tx, rx) = std::sync::mpsc::channel();
        let sink = self.lines.clone();

        thread::spawn(move || {
            while let Ok(line) = logs.recv() {
                if let Ok(mut collected) = sink.lock() {
                    collected.push(line.clone());
                }

                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        rx
    }

    fn to_string(&self) -> String {
        match self.lines.lock() {
            Ok(lines) if !lines.is_empty() => lines.join("\n") + "\n",
            _ => String::new(),
        }
    }
}

struct TelemetryChaosArtifacts {
    directory: std::path::PathBuf,
    logs: LogBuffer,
    metrics: Option<String>,
    alert_payload: Option<serde_json::Value>,
}

impl TelemetryChaosArtifacts {
    fn new(directory: std::path::PathBuf, logs: LogBuffer) -> Self {
        Self {
            directory,
            logs,
            metrics: None,
            alert_payload: None,
        }
    }

    fn with_metrics(mut self, metrics: String) -> Self {
        self.metrics = Some(metrics);
        self
    }

    fn with_alert_payload(mut self, payload: serde_json::Value) -> Self {
        self.alert_payload = Some(payload);
        self
    }

    fn persist(&self) -> Result<()> {
        fs::create_dir_all(&self.directory).with_context(|| {
            format!(
                "create telemetry chaos artifact directory at {}",
                self.directory.display()
            )
        })?;

        let log_body = self.logs.to_string();
        if !log_body.is_empty() {
            fs::write(self.directory.join("node.log"), log_body)
                .context("write telemetry chaos log artifact")?;
        }

        if let Some(metrics) = &self.metrics {
            fs::write(self.directory.join("metrics.prom"), metrics)
                .context("write telemetry chaos metrics snapshot")?;
        }

        if let Some(payload) = &self.alert_payload {
            let payload = serde_json::to_vec_pretty(payload).context("encode alert payload")?;
            fs::write(self.directory.join("alert_payload.json"), payload)
                .context("write telemetry chaos alert payload")?;
        }

        Ok(())
    }
}

impl Drop for TelemetryChaosArtifacts {
    fn drop(&mut self) {
        let _ = self.persist();
    }
}

fn telemetry_chaos_artifact_dir() -> Result<std::path::PathBuf> {
    let base = env::var(ARTIFACT_ENV)
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(ARTIFACT_BASE)
        });

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX_EPOCH")?
        .as_secs();

    Ok(base.join(format!("{}", timestamp)))
}
