#[path = "../support/mod.rs"]
mod support;

#[path = "../network/snapshots_common.rs"]
mod snapshots_common;

#[path = "metrics_utils.rs"]
mod metrics_utils;

use std::{env, fs, path::PathBuf, time::{Duration, Instant}};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use tokio::time::sleep;

use rpp_chain::orchestration::PipelineStage;
use rpp_chain::wallet::WalletWorkflows;

use metrics_utils::fetch_metrics;
use snapshots_common::{
    default_chunk_size, start_snapshot_cluster, SnapshotStreamStatusResponse,
    StartSnapshotStreamRequest, NETWORK_TIMEOUT, POLL_INTERVAL, SNAPSHOT_BUILD_DELAY,
    SNAPSHOT_POLL_TIMEOUT,
};

const ARTIFACT_ENV: &str = "SNAPSHOT_RESTORE_ARTIFACT_DIR";
const DEFAULT_ARTIFACT_DIR: &str = "target/artifacts/snapshot-restore-slo";
const FINALITY_SLO_WARNING: Duration = Duration::from_secs(180);
const UPTIME_BACKLOG_SLO: usize = 8;

#[derive(Debug, Serialize)]
struct SnapshotRestoreRecord {
    snapshot_root: String,
    finality_ms: u128,
    uptime_backlog: usize,
    active_backends: Vec<String>,
    branch_factor: String,
}

#[derive(Default)]
struct SnapshotRestoreArtifacts {
    dir: PathBuf,
    records: Vec<SnapshotRestoreRecord>,
    armed: bool,
}

impl SnapshotRestoreArtifacts {
    fn new() -> Self {
        let dir = env::var(ARTIFACT_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_ARTIFACT_DIR)
            });

        Self {
            dir,
            records: Vec::new(),
            armed: true,
        }
    }

    fn record(&mut self, record: SnapshotRestoreRecord) {
        self.records.push(record);
    }

    fn persist(&self) -> Result<()> {
        if !self.armed || self.records.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(&self.dir).context("create snapshot restore artifact directory")?;
        let path = self.dir.join("summary.json");
        let body = serde_json::to_vec_pretty(&self.records).context("encode artifact payload")?;
        fs::write(&path, body).with_context(|| format!("write artifacts to {}", path.display()))?;

        Ok(())
    }
}

fn active_backends() -> Vec<String> {
    let mut backends = vec!["stwo".to_string()];
    #[cfg(feature = "backend-plonky3")]
    {
        backends.push("plonky3".to_string());
    }
    #[cfg(feature = "backend-rpp-stark")]
    {
        backends.push("rpp-stark".to_string());
    }
    backends
}

fn branch_factor_label() -> String {
    if cfg!(feature = "branch_factor_256") {
        "256".to_string()
    } else {
        "16".to_string()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_restore_respects_uptime_and_finality_slos() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut artifacts = SnapshotRestoreArtifacts::new();
    let mut cluster = start_snapshot_cluster().await?;

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        sleep(SNAPSHOT_BUILD_DELAY).await;

        let nodes = cluster.nodes();
        let provider = &nodes[0];
        let consumer = &nodes[1];
        let provider_peer = provider.p2p_handle.local_peer_id().to_base58();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("construct HTTP client")?;

        let request = StartSnapshotStreamRequest {
            peer: provider_peer,
            chunk_size: default_chunk_size(),
        };

        let consumer_addr = consumer.config.network.rpc.listen;
        let consumer_base_url = format!("http://{}", consumer_addr);

        let mut status: SnapshotStreamStatusResponse = client
            .post(format!("{}/p2p/snapshots", consumer_base_url))
            .json(&request)
            .send()
            .await
            .context("start snapshot stream")?
            .error_for_status()
            .context("snapshot HTTP status")?
            .json()
            .await
            .context("decode snapshot response")?;

        let poll_url = format!("{}/p2p/snapshots/{}", consumer_base_url, status.session);
        let verification_deadline = Instant::now() + SNAPSHOT_POLL_TIMEOUT;

        loop {
            if let Some(ref error) = status.error {
                bail!("snapshot stream reported error: {error}");
            }
            if matches!(status.verified, Some(true)) {
                break;
            }
            if Instant::now() >= verification_deadline {
                bail!("timed out waiting for snapshot verification");
            }

            sleep(POLL_INTERVAL).await;
            status = client
                .get(&poll_url)
                .send()
                .await
                .context("poll snapshot status")?
                .error_for_status()
                .context("poll snapshot HTTP status")?
                .json()
                .await
                .context("decode snapshot status response")?;
        }

        let provider_metrics = fetch_metrics(
            &client,
            provider
                .config
                .rollout
                .telemetry
                .metrics
                .listen
                .context("provider metrics listen address")?,
        )
        .await
        .context("provider metrics scrape")?;
        let consumer_metrics = fetch_metrics(
            &client,
            consumer
                .config
                .rollout
                .telemetry
                .metrics
                .listen
                .context("consumer metrics listen address")?,
        )
        .await
        .context("consumer metrics scrape")?;

        if provider_metrics.is_empty() || consumer_metrics.is_empty() {
            bail!("snapshot metrics scrape returned an empty payload");
        }

        let consumer_status = consumer
            .node_handle
            .node_status()
            .context("fetch consumer node status after restore")?;
        let uptime_backlog = consumer_status.pending_uptime_proofs;
        if uptime_backlog > UPTIME_BACKLOG_SLO {
            bail!(
                "pending uptime proofs exceeded SLO after restore: {} > {}",
                uptime_backlog, UPTIME_BACKLOG_SLO
            );
        }

        let recipient = provider.wallet.address().to_string();
        let workflows = WalletWorkflows::new(provider.wallet.as_ref());
        let workflow = workflows
            .transaction_bundle(recipient, 1_000u128, 50u64, None)
            .context("build post-restore transaction")?;
        let tx_hash = workflow.tx_hash.clone();
        let start = Instant::now();
        provider
            .orchestrator
            .submit_transaction(workflow)
            .await
            .context("submit post-restore transaction")?;

        for stage in [
            PipelineStage::GossipReceived,
            PipelineStage::MempoolAccepted,
            PipelineStage::LeaderElected,
            PipelineStage::BftFinalised,
        ] {
            provider
                .orchestrator
                .wait_for_stage(&tx_hash, stage, FINALITY_SLO_WARNING)
                .await
                .with_context(|| format!("wait for stage {stage:?} after restore"))?;
        }

        let finality_elapsed = start.elapsed();
        if finality_elapsed > FINALITY_SLO_WARNING {
            bail!(
                "time-to-finality exceeded SLO after restore: {:?} > {:?}",
                finality_elapsed, FINALITY_SLO_WARNING
            );
        }

        artifacts.record(SnapshotRestoreRecord {
            snapshot_root: status.root.clone(),
            finality_ms: finality_elapsed.as_millis(),
            uptime_backlog,
            active_backends: active_backends(),
            branch_factor: branch_factor_label(),
        });

        Ok::<(), anyhow::Error>(())
    }
    .await;

    if result.is_err() {
        artifacts.persist()?;
    }

    cluster.shutdown().await.context("cluster shutdown")?;

    result
}
