#![cfg(feature = "integration")]

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use opentelemetry_proto::collector::trace::v1::{
    trace_service_server::{TraceService, TraceServiceServer},
    ExportTraceServiceRequest, ExportTraceServiceResponse,
};
use reqwest::blocking::Client;
use serde_json::json;
use tempfile::TempDir;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tonic::{transport::Server, Request, Response, Status};

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
const RETENTION_ENV: &str = "TELEMETRY_CHAOS_MAX_RUNS";
const DEFAULT_RETENTION: usize = 10;

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
        .with_alert_payload("firing", alert_payload)
        .persist()
        .context("write telemetry chaos artifacts")?;

    Ok(())
}

#[test]
fn telemetry_otlp_failover_uses_secondary_endpoints() -> Result<()> {
    let artifact_dir = telemetry_chaos_artifact_dir().context("prepare artifact directory")?;
    let temp_dir = TempDir::new().context("create temporary directory")?;
    let binary = locate_rpp_node_binary().context("locate rpp-node binary")?;
    let mut ports = PortAllocator::default();

    let rpc_port = ports.next_port().context("allocate RPC port")?;
    let metrics_port = ports.next_port().context("allocate metrics port")?;
    let primary_grpc_port = ports.next_port().context("allocate primary gRPC port")?;
    let primary_http_port = ports.next_port().context("allocate primary HTTP port")?;
    let secondary_grpc_port = ports.next_port().context("allocate secondary gRPC port")?;
    let secondary_http_port = ports.next_port().context("allocate secondary HTTP port")?;

    let rpc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpc_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), metrics_port);
    let invalid_cert = temp_dir.path().join("invalid-ca.pem");
    fs::write(&invalid_cert, b"not-a-certificate").context("write invalid certificate")?;

    let node_config = write_node_config_with(
        temp_dir.path(),
        Some(TelemetryExpectation::Disabled),
        &mut ports,
        |config| {
            config.network.rpc.listen = rpc_addr;
            config.network.p2p.bootstrap_peers.clear();
            config.rollout.telemetry.enabled = true;
            config.rollout.telemetry.failover_enabled = true;
            config.rollout.telemetry.endpoint =
                Some(format!("http://127.0.0.1:{primary_grpc_port}"));
            config.rollout.telemetry.http_endpoint =
                Some(format!("http://127.0.0.1:{primary_http_port}/v1/metrics"));
            config.rollout.telemetry.secondary_endpoint =
                Some(format!("http://127.0.0.1:{secondary_grpc_port}"));
            config.rollout.telemetry.secondary_http_endpoint =
                Some(format!("http://127.0.0.1:{secondary_http_port}/v1/metrics"));
            config.rollout.telemetry.sample_interval_secs = 1;
            config.rollout.telemetry.metrics.listen = Some(metrics_addr);
            config.rollout.telemetry.metrics.auth_token = None;
            config.rollout.telemetry.grpc_tls = Some(TelemetryTlsConfig {
                ca_certificate: Some(invalid_cert.clone()),
                ..TelemetryTlsConfig::default()
            });
            config.rollout.telemetry.http_tls = Some(TelemetryTlsConfig {
                ca_certificate: Some(invalid_cert.clone()),
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
        .context("spawn rpp-node with failover configuration")?;
    let mut guard = ChildTerminationGuard {
        child: Some(&mut child),
    };
    let log_buffer = LogBuffer::default();
    let mut logs = log_buffer.forward(capture_child_output(&mut child));

    wait_for_log(&mut logs, "bootstrap configuration resolved")
        .context("wait for bootstrap log")?;
    wait_for_log(&mut logs, "telemetry endpoints configured")
        .context("wait for telemetry endpoint log")?;
    wait_for_log(&mut logs, "failed over to secondary OTLP metrics endpoint")
        .context("wait for metrics failover log")?;
    wait_for_log(&mut logs, "failed over to secondary OTLP traces endpoint")
        .context("wait for traces failover log")?;

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

    let metrics_init = metrics_utils::metric_value(
        &metrics_body,
        OTLP_FAILURE_METRIC,
        &[("sink", "metrics"), ("phase", "init")],
    )
    .unwrap_or(0.0);
    assert!(
        metrics_init >= 1.0,
        "expected primary metrics exporter failures to be recorded, found {metrics_init}"
    );

    let metrics_failover = metrics_utils::metric_value(
        &metrics_body,
        OTLP_FAILURE_METRIC,
        &[("sink", "metrics"), ("phase", "init_failover")],
    )
    .unwrap_or(0.0);
    assert!(
        metrics_failover >= 1.0,
        "expected metrics failover counter to increment, found {metrics_failover}"
    );

    let traces_init = metrics_utils::metric_value(
        &metrics_body,
        OTLP_FAILURE_METRIC,
        &[("sink", "traces"), ("phase", "init")],
    )
    .unwrap_or(0.0);
    assert!(
        traces_init >= 1.0,
        "expected primary trace exporter failures to be recorded, found {traces_init}"
    );

    let traces_failover = metrics_utils::metric_value(
        &metrics_body,
        OTLP_FAILURE_METRIC,
        &[("sink", "traces"), ("phase", "init_failover")],
    )
    .unwrap_or(0.0);
    assert!(
        traces_failover >= 1.0,
        "expected trace failover counter to increment, found {traces_failover}"
    );

    thread::sleep(Duration::from_secs(2));
    let steady_metrics_body = client
        .get(format!("http://{metrics_addr}/metrics"))
        .send()
        .context("request metrics endpoint after failover")?
        .error_for_status()
        .context("metrics endpoint returned error status after failover")?
        .text()
        .context("read metrics body after failover")?;

    let metrics_failover_after = metrics_utils::metric_value(
        &steady_metrics_body,
        OTLP_FAILURE_METRIC,
        &[("sink", "metrics"), ("phase", "init_failover")],
    )
    .unwrap_or(0.0);
    assert_eq!(
        metrics_failover, metrics_failover_after,
        "expected metrics failover counter to stay flat after recovery"
    );

    let traces_failover_after = metrics_utils::metric_value(
        &steady_metrics_body,
        OTLP_FAILURE_METRIC,
        &[("sink", "traces"), ("phase", "init_failover")],
    )
    .unwrap_or(0.0);
    assert_eq!(
        traces_failover, traces_failover_after,
        "expected trace failover counter to stay flat after recovery"
    );

    let firing_payload = json!({
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
                    "summary": "OTLP telemetry exporters failed on the primary backend",
                    "description": "The primary OTLP endpoints rejected TLS handshakes; the runtime is attempting failover.",
                    "validation.metrics": metrics_init,
                    "validation.traces": traces_init,
                },
            },
        ],
    });

    assert!(
        metrics_failover_after - metrics_failover == 0.0
            && traces_failover_after - traces_failover == 0.0,
        "failover counters should stop increasing so the alert can resolve"
    );

    let resolved_payload = json!({
        "receiver": "telemetry-chaos-harness",
        "status": "resolved",
        "alerts": [
            {
                "status": "resolved",
                "labels": {
                    "alertname": "OtlpExporterFailureCleared",
                    "severity": "info",
                    "service": "observability",
                },
                "annotations": {
                    "summary": "OTLP telemetry exporters recovered after failover",
                    "description": "Secondary OTLP endpoints are stable and failure counters stopped incrementing for the alert clear window.",
                    "validation.metrics": metrics_failover_after,
                    "validation.traces": traces_failover_after,
                },
            },
        ],
    });

    TelemetryChaosArtifacts::new(artifact_dir, log_buffer)
        .with_metrics(metrics_body)
        .with_named_metrics("metrics_after_failover.prom", steady_metrics_body)
        .with_alert_payload("firing", firing_payload)
        .with_alert_payload("resolved", resolved_payload)
        .persist()
        .context("write telemetry failover chaos artifacts")?;

    start_log_drain(logs);
    send_ctrl_c(guard.child.as_ref().expect("child reference"))
        .context("signal rpp-node shutdown")?;
    wait_for_exit(guard.child.as_mut().expect("child reference"))
        .context("wait for rpp-node exit")?;
    guard.child.take();

    Ok(())
}

#[derive(Default)]
struct EndpointStats {
    attempts: AtomicUsize,
    successes: AtomicUsize,
}

impl EndpointStats {
    fn record_attempt(&self) {
        self.attempts.fetch_add(1, Ordering::SeqCst);
    }

    fn record_success(&self) {
        self.successes.fetch_add(1, Ordering::SeqCst);
    }
}

fn wait_for_attempts(stats: &EndpointStats, min: usize, timeout: Duration) -> Result<()> {
    let start = SystemTime::now();
    while stats.attempts.load(Ordering::SeqCst) < min {
        if SystemTime::now().duration_since(start).unwrap_or_default() >= timeout {
            anyhow::bail!(
                "expected at least {min} attempts, found {}",
                stats.attempts.load(Ordering::SeqCst)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn wait_for_success(stats: &EndpointStats, timeout: Duration) -> Result<()> {
    let start = SystemTime::now();
    while stats.successes.load(Ordering::SeqCst) == 0 {
        if SystemTime::now().duration_since(start).unwrap_or_default() >= timeout {
            anyhow::bail!(
                "timed out waiting for exporter recovery; attempts={}, successes={}",
                stats.attempts.load(Ordering::SeqCst),
                stats.successes.load(Ordering::SeqCst)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

struct TraceCollectorHandle {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

impl TraceCollectorHandle {
    fn shutdown(mut self) {
        if let Some(signal) = self.shutdown.take() {
            let _ = signal.send(());
        }
        // Trigger a dummy connection to break the accept loop if needed.
        let _ = TcpStream::connect(self.addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct HttpCollectorHandle {
    addr: SocketAddr,
    running: Arc<AtomicBool>,
    join: Option<thread::JoinHandle<()>>,
}

impl HttpCollectorHandle {
    fn shutdown(mut self) {
        self.running.store(false, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn start_flaky_trace_collector(
    port: u16,
    chaos_active: Arc<AtomicBool>,
    stats: Arc<EndpointStats>,
    chaos_delay: Duration,
) -> Result<TraceCollectorHandle> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let join = thread::spawn(move || {
        let runtime = Runtime::new().expect("trace collector runtime");
        runtime.block_on(async move {
            let service = FlakyTraceService {
                chaos_active,
                stats,
                chaos_delay,
            };

            let _ = Server::builder()
                .add_service(TraceServiceServer::new(service))
                .serve_with_shutdown(addr, async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });
    });

    Ok(TraceCollectorHandle {
        addr,
        shutdown: Some(shutdown_tx),
        join: Some(join),
    })
}

fn start_flaky_http_collector(
    port: u16,
    chaos_active: Arc<AtomicBool>,
    stats: Arc<EndpointStats>,
    chaos_delay: Duration,
) -> Result<HttpCollectorHandle> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = TcpListener::bind(addr).context("bind OTLP HTTP collector")?;
    let running = Arc::new(AtomicBool::new(true));
    let running_flag = running.clone();

    let join = thread::spawn(move || {
        for stream in listener.incoming() {
            if !running_flag.load(Ordering::SeqCst) {
                break;
            }

            let Ok(mut stream) = stream else {
                continue;
            };

            stats.record_attempt();

            if chaos_active.load(Ordering::SeqCst) {
                thread::sleep(chaos_delay);
                continue;
            }

            let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));

            let mut buffer = [0u8; 1024];
            let _ = stream.read(&mut buffer);

            let response = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
            if stream.write_all(response).is_ok() {
                let _ = stream.flush();
                stats.record_success();
            }
        }
    });

    Ok(HttpCollectorHandle {
        addr,
        running,
        join: Some(join),
    })
}

#[derive(Clone)]
struct FlakyTraceService {
    chaos_active: Arc<AtomicBool>,
    stats: Arc<EndpointStats>,
    chaos_delay: Duration,
}

#[tonic::async_trait]
impl TraceService for FlakyTraceService {
    async fn export(
        &self,
        _request: Request<ExportTraceServiceRequest>,
    ) -> Result<Response<ExportTraceServiceResponse>, Status> {
        self.stats.record_attempt();

        if self.chaos_active.load(Ordering::SeqCst) {
            tokio::time::sleep(self.chaos_delay).await;
            return Err(Status::deadline_exceeded("chaos-induced timeout"));
        }

        self.stats.record_success();
        Ok(Response::new(ExportTraceServiceResponse::default()))
    }
}

#[test]
fn telemetry_otlp_timeouts_backoff_and_buffer() -> Result<()> {
    let artifact_dir = telemetry_chaos_artifact_dir().context("prepare artifact directory")?;

    let temp_dir = TempDir::new().context("create temporary directory")?;
    let binary = locate_rpp_node_binary().context("locate rpp-node binary")?;
    let mut ports = PortAllocator::default();

    let rpc_port = ports.next_port().context("allocate RPC port")?;
    let metrics_port = ports.next_port().context("allocate metrics port")?;
    let trace_port = ports
        .next_port()
        .context("allocate OTLP trace collector port")?;
    let otlp_http_port = ports
        .next_port()
        .context("allocate OTLP HTTP collector port")?;

    let rpc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), rpc_port);
    let metrics_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), metrics_port);

    let chaos_active = Arc::new(AtomicBool::new(true));
    let trace_stats = Arc::new(EndpointStats::default());
    let http_stats = Arc::new(EndpointStats::default());

    let trace_server = start_flaky_trace_collector(
        trace_port,
        chaos_active.clone(),
        trace_stats.clone(),
        Duration::from_millis(600),
    )?;
    let http_server = start_flaky_http_collector(
        otlp_http_port,
        chaos_active.clone(),
        http_stats.clone(),
        Duration::from_millis(600),
    )?;

    let node_config = write_node_config_with(
        temp_dir.path(),
        Some(TelemetryExpectation::Disabled),
        &mut ports,
        |config| {
            config.network.rpc.listen = rpc_addr;
            config.network.p2p.bootstrap_peers.clear();
            config.rollout.telemetry.enabled = true;
            config.rollout.telemetry.endpoint = Some(format!("http://127.0.0.1:{trace_port}"));
            config.rollout.telemetry.http_endpoint =
                Some(format!("http://127.0.0.1:{otlp_http_port}/v1/metrics"));
            config.rollout.telemetry.sample_interval_secs = 1;
            config.rollout.telemetry.timeout_ms = 250;
            config.rollout.telemetry.auth_token = None;
            config.rollout.telemetry.metrics.listen = Some(metrics_addr);
            config.rollout.telemetry.metrics.auth_token = None;
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
        .context("spawn rpp-node with OTLP timeout configuration")?;
    let mut guard = ChildTerminationGuard {
        child: Some(&mut child),
    };
    let log_buffer = LogBuffer::default();
    let mut logs = log_buffer.forward(capture_child_output(&mut child));

    wait_for_log(&mut logs, "bootstrap configuration resolved")
        .context("wait for bootstrap log")?;
    wait_for_log(&mut logs, "telemetry endpoints configured")
        .context("wait for telemetry endpoint log")?;
    wait_for_log(
        &mut logs,
        "telemetry exporter error; will retry with exponential backoff",
    )
    .context("wait for telemetry timeout log")?;

    thread::sleep(Duration::from_secs(2));
    chaos_active.store(false, Ordering::SeqCst);

    wait_for_attempts(&trace_stats, 1, Duration::from_secs(5))
        .context("wait for trace exporter attempts")?;
    wait_for_attempts(&http_stats, 1, Duration::from_secs(5))
        .context("wait for metric exporter attempts")?;

    wait_for_success(&trace_stats, Duration::from_secs(10))
        .context("wait for trace exporter recovery")?;
    wait_for_success(&http_stats, Duration::from_secs(10))
        .context("wait for metric exporter recovery")?;

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

    let alert_payload = json!({
        "receiver": "telemetry-chaos-harness",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "OtlpExporterTimeout",
                    "severity": "warning",
                    "service": "observability",
                },
                "annotations": {
                    "summary": "OTLP exporters are timing out and retrying",
                    "description": "The primary OTLP collectors are timing out; exporters are backing off and buffering until the collector recovers.",
                    "validation.trace_attempts": trace_stats.attempts.load(Ordering::SeqCst),
                    "validation.metric_attempts": http_stats.attempts.load(Ordering::SeqCst),
                },
            },
        ],
    });

    TelemetryChaosArtifacts::new(artifact_dir, log_buffer)
        .with_metrics(metrics_body)
        .with_alert_payload("firing", alert_payload)
        .persist()
        .context("write telemetry timeout chaos artifacts")?;

    start_log_drain(logs);
    send_ctrl_c(guard.child.as_ref().expect("child reference"))
        .context("signal rpp-node shutdown")?;
    wait_for_exit(guard.child.as_mut().expect("child reference"))
        .context("wait for rpp-node exit")?;
    guard.child.take();

    trace_server.shutdown();
    http_server.shutdown();

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
    metrics: Vec<(String, String)>,
    alert_payloads: Vec<(String, serde_json::Value)>,
}

impl TelemetryChaosArtifacts {
    fn new(directory: std::path::PathBuf, logs: LogBuffer) -> Self {
        Self {
            directory,
            logs,
            metrics: Vec::new(),
            alert_payloads: Vec::new(),
        }
    }

    fn with_metrics(mut self, metrics: String) -> Self {
        self.metrics.push(("metrics.prom".to_string(), metrics));
        self
    }

    fn with_named_metrics(mut self, name: impl Into<String>, metrics: String) -> Self {
        self.metrics.push((name.into(), metrics));
        self
    }

    fn with_alert_payload(mut self, name: impl Into<String>, payload: serde_json::Value) -> Self {
        self.alert_payloads.push((name.into(), payload));
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

        for (index, (name, metrics)) in self.metrics.iter().enumerate() {
            let filename = if index == 0 {
                "metrics.prom"
            } else {
                name.as_str()
            };
            fs::write(self.directory.join(filename), metrics)
                .with_context(|| format!("write telemetry chaos metrics snapshot to {filename}"))?;
        }

        for (name, payload) in &self.alert_payloads {
            let payload = serde_json::to_vec_pretty(payload)
                .with_context(|| format!("encode alert payload for {name}"))?;
            fs::write(
                self.directory.join(format!("{name}_alert_payload.json")),
                payload,
            )
            .with_context(|| format!("write telemetry chaos alert payload for {name}"))?;
        }

        if let Some(base_dir) = self.directory.parent() {
            prune_telemetry_chaos_artifacts(base_dir, telemetry_chaos_retention_limit())
                .context("prune telemetry chaos artifacts")?;
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

fn telemetry_chaos_retention_limit() -> usize {
    env::var(RETENTION_ENV)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|runs| *runs > 0)
        .unwrap_or(DEFAULT_RETENTION)
}

fn prune_telemetry_chaos_artifacts(base_dir: &std::path::Path, keep_latest: usize) -> Result<()> {
    if keep_latest == 0 {
        return Ok(());
    }

    let mut runs: Vec<_> = fs::read_dir(base_dir)
        .with_context(|| {
            format!(
                "scan telemetry chaos artifact directory at {}",
                base_dir.display()
            )
        })?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| match entry.file_type() {
            Ok(file_type) if file_type.is_dir() => Some(entry.path()),
            _ => None,
        })
        .collect();

    runs.sort();

    let surplus = runs.len().saturating_sub(keep_latest);
    for run in runs.into_iter().take(surplus) {
        fs::remove_dir_all(&run).with_context(|| {
            format!("remove stale telemetry chaos artifact at {}", run.display())
        })?;
    }

    Ok(())
}
