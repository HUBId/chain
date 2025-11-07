use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, ensure, Context, Result};
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::time::sleep;
use tracing_subscriber::fmt::{MakeWriter, Subscriber};
use tracing_subscriber::EnvFilter;

#[path = "../support/mod.rs"]
mod support;

mod snapshots_common;

#[path = "../observability/metrics_utils.rs"]
mod metrics_utils;

use metrics_utils::{fetch_metrics, metric_value};
use snapshots_common::{NETWORK_TIMEOUT, POLL_INTERVAL};
use support::TestCluster;

const VALIDATION_CADENCE_SECS: u64 = 5;
const VALIDATION_TIMEOUT: Duration = Duration::from_secs(30);
const LOG_PATTERN: &str = "snapshot chunk validation failed";
const METRIC_NAME: &str = "snapshot_chunk_checksum_failures_total";
const METRIC_KIND: &str = "checksum_mismatch";
const MAX_INTERVAL_SECS: u64 = VALIDATION_CADENCE_SECS * 2;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_validator_recovers_after_restart() -> Result<()> {
    let log_buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = SharedBufferWriter::new(Arc::clone(&log_buffer));
    let subscriber = Subscriber::builder()
        .with_env_filter(EnvFilter::new("snapshot_validator=debug"))
        .with_target(true)
        .with_ansi(false)
        .with_writer(writer)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let mut cluster = TestCluster::start_with(2, |cfg, idx| {
        let metrics_listener = TcpListener::bind("127.0.0.1:0").context("bind metrics listener")?;
        let metrics_addr = metrics_listener
            .local_addr()
            .context("resolve metrics listener address")?;
        drop(metrics_listener);

        cfg.rollout.feature_gates.reconstruction = true;
        cfg.rollout.feature_gates.recursive_proofs = true;
        cfg.rollout.telemetry.enabled = true;
        cfg.rollout.telemetry.metrics.listen = Some(metrics_addr);
        cfg.snapshot_validator.cadence_secs = VALIDATION_CADENCE_SECS;
        if idx == 0 {
            cfg.network.p2p.bootstrap_peers.clear();
        }
        Ok(())
    })
    .await?;

    cluster
        .wait_for_full_mesh(NETWORK_TIMEOUT)
        .await
        .context("cluster mesh")?;

    let node = &cluster.nodes()[0];
    let chunk_dir = node.config.snapshot_dir.join("chunks");
    let manifest_path = node.config.snapshot_dir.join("manifest/chunks.json");

    fs::create_dir_all(&chunk_dir)
        .await
        .with_context(|| format!("create chunk directory at {}", chunk_dir.display()))?;
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create manifest directory at {}", parent.display()))?;
    }

    let chunk_path = chunk_dir.join("chunk-000.bin");
    let original_bytes = b"validator snapshot chunk".to_vec();
    fs::write(&chunk_path, &original_bytes)
        .await
        .with_context(|| format!("write snapshot chunk to {}", chunk_path.display()))?;

    let mut hasher = Sha256::new();
    hasher.update(&original_bytes);
    let checksum = hex::encode(hasher.finalize());
    let manifest = json!({
        "version": 1,
        "generated_at": "2024-01-01T00:00:00Z",
        "segments": [
            {
                "segment_name": "chunk-000.bin",
                "size_bytes": original_bytes.len(),
                "sha256": checksum,
                "status": "available",
            }
        ],
    });
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)
        .await
        .with_context(|| format!("write manifest to {}", manifest_path.display()))?;
    let sig_name = manifest_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| anyhow!("manifest filename is not valid UTF-8"))?;
    let sig_path = manifest_path.with_file_name(format!("{sig_name}.sig"));
    let signature = "00".repeat(64);
    fs::write(&sig_path, signature.as_bytes())
        .await
        .with_context(|| format!("write manifest signature to {}", sig_path.display()))?;

    // Allow the validator to observe the clean manifest before introducing corruption.
    sleep(Duration::from_secs(1)).await;

    let corrupt_bytes = b"corrupted chunk".to_vec();
    fs::write(&chunk_path, &corrupt_bytes)
        .await
        .with_context(|| format!("corrupt snapshot chunk at {}", chunk_path.display()))?;

    let metrics_addr = node
        .config
        .rollout
        .telemetry
        .metrics
        .listen
        .context("node metrics address")?;

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("construct HTTP client")?;

    let (log_count, _) =
        wait_for_log_occurrence(Arc::clone(&log_buffer), 0, VALIDATION_TIMEOUT).await?;
    ensure!(
        log_count >= 1,
        "snapshot validator did not log a checksum failure before restart"
    );

    let failures = wait_for_metric(&client, metrics_addr, 1.0, VALIDATION_TIMEOUT).await?;
    ensure!(
        failures >= 1.0,
        "snapshot validator did not export checksum metrics before restart"
    );

    let restart_start = Instant::now();
    cluster.nodes_mut()[0]
        .restart()
        .await
        .context("restart node 0")?;

    let (post_restart_count, observed_at) =
        wait_for_log_occurrence(Arc::clone(&log_buffer), log_count, VALIDATION_TIMEOUT).await?;
    ensure!(
        post_restart_count == log_count + 1,
        "snapshot validator log count did not advance after restart"
    );

    let elapsed = observed_at.duration_since(restart_start);
    let max_interval = Duration::from_secs(MAX_INTERVAL_SECS);
    ensure!(
        elapsed <= max_interval,
        "validator took {:?} to report the next checksum failure (allowed {:?})",
        elapsed,
        max_interval
    );

    let expected_metric = failures + 1.0;
    let post_restart_failures =
        wait_for_metric(&client, metrics_addr, expected_metric, VALIDATION_TIMEOUT).await?;
    ensure!(
        post_restart_failures >= expected_metric,
        "snapshot validator metric did not increment after restart"
    );

    cluster
        .wait_for_full_mesh(NETWORK_TIMEOUT)
        .await
        .context("cluster mesh after restart")?;

    cluster.shutdown().await.context("cluster shutdown")?;

    Ok(())
}

#[derive(Clone)]
struct SharedBufferWriter {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl SharedBufferWriter {
    fn new(buffer: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { buffer }
    }
}

struct BufferGuard {
    buffer: Arc<Mutex<Vec<u8>>>,
}

impl<'a> MakeWriter<'a> for SharedBufferWriter {
    type Writer = BufferGuard;

    fn make_writer(&'a self) -> Self::Writer {
        BufferGuard {
            buffer: Arc::clone(&self.buffer),
        }
    }
}

impl Write for BufferGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .buffer
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "log buffer poisoned"))?;
        guard.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn wait_for_log_occurrence(
    buffer: Arc<Mutex<Vec<u8>>>,
    previous_count: usize,
    timeout: Duration,
) -> Result<(usize, Instant)> {
    let deadline = Instant::now() + timeout;
    loop {
        let occurrences = {
            let guard = buffer
                .lock()
                .map_err(|_| anyhow!("log buffer mutex poisoned"))?;
            let text = String::from_utf8_lossy(&guard);
            text.matches(LOG_PATTERN).count()
        };
        if occurrences > previous_count {
            return Ok((occurrences, Instant::now()));
        }
        if Instant::now() >= deadline {
            bail!(
                "snapshot validator did not emit `{LOG_PATTERN}` within {timeout:?}; observed {occurrences} occurrences"
            );
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_metric(
    client: &Client,
    addr: SocketAddr,
    expected: f64,
    timeout: Duration,
) -> Result<f64> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(metrics) = fetch_metrics(client, addr).await {
            let value =
                metric_value(&metrics, METRIC_NAME, &[("kind", METRIC_KIND)]).unwrap_or_default();
            if value >= expected {
                return Ok(value);
            }
        }
        if Instant::now() >= deadline {
            bail!(
                "snapshot validator metric `{METRIC_NAME}` with kind `{METRIC_KIND}` did not reach {expected} before timeout"
            );
        }
        sleep(POLL_INTERVAL).await;
    }
}
