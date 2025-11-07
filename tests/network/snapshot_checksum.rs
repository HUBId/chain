use std::net::TcpListener;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::fs;
use tokio::time::sleep;

#[path = "../support/mod.rs"]
mod support;

mod snapshots_common;

#[path = "../observability/metrics_utils.rs"]
mod metrics_utils;

use metrics_utils::{fetch_metrics, metric_value};
use snapshots_common::{NETWORK_TIMEOUT, POLL_INTERVAL, SNAPSHOT_BUILD_DELAY};
use support::TestCluster;

const VALIDATION_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_validator_reports_checksum_mismatch() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

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
        cfg.snapshot_validator.cadence_secs = 1;
        if idx == 0 {
            cfg.network.p2p.bootstrap_peers.clear();
        }
        Ok(())
    })
    .await?;

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        sleep(SNAPSHOT_BUILD_DELAY).await;

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
            ]
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

        // Wait for the validator to observe the clean manifest at least once.
        sleep(Duration::from_secs(2)).await;

        let corrupt_bytes = b"corrupted chunk".to_vec();
        fs::write(&chunk_path, &corrupt_bytes)
            .await
            .with_context(|| format!("corrupt snapshot chunk at {}", chunk_path.display()))?;

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .context("construct HTTP client")?;
        let metrics_addr = node
            .config
            .rollout
            .telemetry
            .metrics
            .listen
            .context("node metrics address")?;

        let deadline = Instant::now() + VALIDATION_TIMEOUT;
        loop {
            let metrics = fetch_metrics(&client, metrics_addr).await;
            if let Ok(metrics) = metrics {
                let failures = metric_value(
                    &metrics,
                    "snapshot_chunk_checksum_failures_total",
                    &[("kind", "checksum_mismatch")],
                )
                .unwrap_or_default();
                if failures > 0.0 {
                    break;
                }
            }

            if Instant::now() >= deadline {
                return Err(anyhow!(
                    "snapshot validator metric did not report a checksum failure before timeout"
                ));
            }

            sleep(POLL_INTERVAL).await;
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;
    result
}
