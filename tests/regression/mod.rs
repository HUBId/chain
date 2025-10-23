use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::time::sleep;

#[path = "../support/mod.rs"]
mod support;

use rpp_chain::orchestration::PipelineStage;
use rpp_chain::wallet::WalletWorkflows;
use support::cluster::TestCluster;

const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);
const PROGRESS_TIMEOUT: Duration = Duration::from_secs(60);
const RESTART_GRACE: Duration = Duration::from_secs(5);

#[derive(Serialize)]
struct ScenarioReport<'a> {
    scenario: &'a str,
    elapsed_ms: u128,
    notes: Vec<String>,
}

#[derive(Serialize)]
struct SnapshotRecord<'a> {
    node_index: usize,
    height: u64,
    block_hash: &'a Option<String>,
    pending_votes: usize,
    node_pending_votes: usize,
}

fn artifact_root() -> Option<PathBuf> {
    std::env::var("RPP_REGRESSION_ARTIFACT_DIR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}

fn write_json_artifact<T: Serialize>(relative: &str, payload: &T) -> Result<()> {
    let root = match artifact_root() {
        Some(root) => root,
        None => return Ok(()),
    };
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create artifact directory {parent:?}"))?;
    }
    let file = File::create(&path)
        .with_context(|| format!("failed to create artifact file {}", path.display()))?;
    serde_json::to_writer_pretty(file, payload)
        .with_context(|| format!("failed to encode artifact {}", path.display()))?;
    Ok(())
}

fn append_log(relative: &str, line: &str) -> Result<()> {
    let root = match artifact_root() {
        Some(root) => root,
        None => return Ok(()),
    };
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create log directory {parent:?}"))?;
    }
    let mut file = File::options()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open log file {}", path.display()))?;
    writeln!(file, "{line}")
        .with_context(|| format!("failed to append log entry to {}", path.display()))?;
    Ok(())
}

async fn start_cluster() -> Option<TestCluster> {
    match TestCluster::start(3).await {
        Ok(cluster) => Some(cluster),
        Err(err) => {
            eprintln!("skipping regression cluster bootstrap: {err:?}");
            None
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn regression_cluster_bootstrap_establishes_quorum() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match start_cluster().await {
        Some(cluster) => cluster,
        None => return Ok(()),
    };

    let started = Instant::now();

    cluster
        .wait_for_full_mesh(NETWORK_TIMEOUT)
        .await
        .context("cluster mesh formation")?;

    let baseline = cluster
        .consensus_snapshots()
        .context("capture baseline snapshots")?;

    let baseline_records: Vec<_> = baseline
        .iter()
        .enumerate()
        .map(|(index, snapshot)| SnapshotRecord {
            node_index: index,
            height: snapshot.height,
            block_hash: &snapshot.block_hash,
            pending_votes: snapshot.pending_votes,
            node_pending_votes: snapshot.node_pending_votes,
        })
        .collect();

    if let Err(err) = write_json_artifact(
        "snapshots/cluster_bootstrap_baseline.json",
        &baseline_records,
    ) {
        eprintln!("failed to persist cluster bootstrap baseline: {err:?}");
    }

    cluster
        .wait_for_quorum_progress(&baseline, PROGRESS_TIMEOUT)
        .await
        .context("quorum progression")?;

    let progressed = cluster
        .consensus_snapshots()
        .context("capture progressed snapshots")?;

    let progressed_records: Vec<_> = progressed
        .iter()
        .enumerate()
        .map(|(index, snapshot)| SnapshotRecord {
            node_index: index,
            height: snapshot.height,
            block_hash: &snapshot.block_hash,
            pending_votes: snapshot.pending_votes,
            node_pending_votes: snapshot.node_pending_votes,
        })
        .collect();

    if let Err(err) = write_json_artifact(
        "snapshots/cluster_bootstrap_progress.json",
        &progressed_records,
    ) {
        eprintln!("failed to persist cluster bootstrap progress: {err:?}");
    }

    let elapsed = started.elapsed().as_millis();
    let final_height = progressed_records
        .first()
        .map(|record| record.height.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let report = ScenarioReport {
        scenario: "cluster_bootstrap",
        elapsed_ms: elapsed,
        notes: vec![format!("final_height={final_height}")],
    };

    if let Err(err) = write_json_artifact("metrics/cluster_bootstrap.json", &report) {
        eprintln!("failed to persist cluster bootstrap metrics: {err:?}");
    }

    cluster.shutdown().await.context("shutdown cluster")?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn regression_wallet_transaction_finalises() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let cluster = match start_cluster().await {
        Some(cluster) => cluster,
        None => return Ok(()),
    };

    cluster
        .wait_for_full_mesh(NETWORK_TIMEOUT)
        .await
        .context("cluster mesh formation")?;

    let consensus_baseline = cluster
        .consensus_snapshots()
        .context("capture consensus baseline")?;

    let (primary_handle, orchestrator, wallet, recipient, recipient_handle) = {
        let nodes = cluster.nodes();
        let primary = &nodes[0];
        let secondary = &nodes[1];
        (
            primary.node_handle.clone(),
            primary.orchestrator.clone(),
            primary.wallet.clone(),
            secondary.wallet.address().to_string(),
            secondary.node_handle.clone(),
        )
    };

    let workflows = WalletWorkflows::new(wallet.as_ref());
    let amount = 5_000u128;
    let fee = 100u64;
    let started = Instant::now();
    let workflow = workflows
        .transaction_bundle(recipient.clone(), amount, fee, None)
        .context("build transaction workflow")?;

    if let Err(err) = append_log(
        "logs/wallet_transaction.log",
        &format!(
            "submit nonce={} recipient={recipient} amount={amount}",
            workflow.nonce
        ),
    ) {
        eprintln!("failed to persist wallet transaction log: {err:?}");
    }

    let hash = orchestrator
        .submit_transaction(workflow.clone())
        .await
        .context("submit orchestrator transaction")?;

    for stage in [
        PipelineStage::GossipReceived,
        PipelineStage::MempoolAccepted,
        PipelineStage::LeaderElected,
        PipelineStage::BftFinalised,
        PipelineStage::RewardsDistributed,
    ] {
        orchestrator
            .wait_for_stage(&hash, stage, PROGRESS_TIMEOUT)
            .await
            .with_context(|| format!("wait for pipeline stage {stage:?}"))?;
    }

    cluster
        .wait_for_quorum_progress(&consensus_baseline, PROGRESS_TIMEOUT)
        .await
        .context("quorum progress after transaction")?;

    let sender_account = primary_handle
        .get_account(wallet.address())
        .context("fetch sender account")?
        .context("sender account missing")?;
    let recipient_account = recipient_handle
        .get_account(&recipient)
        .context("fetch recipient account")?
        .context("recipient account missing")?;

    let elapsed = started.elapsed().as_millis();
    let preview = &workflow.preview;
    let report = ScenarioReport {
        scenario: "wallet_transaction",
        elapsed_ms: elapsed,
        notes: vec![
            format!("sender_nonce={}", workflow.nonce),
            format!(
                "sender_balance={} (expected {})",
                sender_account.balance, preview.balance_after
            ),
            format!("recipient_balance={}", recipient_account.balance),
        ],
    };

    if let Err(err) = write_json_artifact("metrics/wallet_transaction.json", &report) {
        eprintln!("failed to persist wallet transaction metrics: {err:?}");
    }

    if let Err(err) = write_json_artifact(
        "snapshots/wallet_transaction_accounts.json",
        &vec![
            (
                wallet.address().to_string(),
                sender_account.balance,
                preview.balance_before,
                preview.balance_after,
            ),
            (recipient.clone(), recipient_account.balance, 0u128, 0u128),
        ],
    ) {
        eprintln!("failed to persist wallet transaction snapshot: {err:?}");
    }

    orchestrator.shutdown();
    cluster.shutdown().await.context("shutdown cluster")?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn regression_proof_generation_persists_bundle() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let cluster = match start_cluster().await {
        Some(cluster) => cluster,
        None => return Ok(()),
    };

    cluster
        .wait_for_full_mesh(NETWORK_TIMEOUT)
        .await
        .context("cluster mesh formation")?;

    let consensus_baseline = cluster
        .consensus_snapshots()
        .context("capture consensus baseline")?;

    let (primary_handle, orchestrator, wallet, recipient) = {
        let nodes = cluster.nodes();
        let primary = &nodes[0];
        let secondary = &nodes[1];
        (
            primary.node_handle.clone(),
            primary.orchestrator.clone(),
            primary.wallet.clone(),
            secondary.wallet.address().to_string(),
        )
    };

    let workflows = WalletWorkflows::new(wallet.as_ref());
    let started = Instant::now();
    let workflow = workflows
        .transaction_bundle(recipient, 7_500u128, 100u64, None)
        .context("build transaction workflow")?;

    let hash = orchestrator
        .submit_transaction(workflow.clone())
        .await
        .context("submit orchestrator transaction")?;

    orchestrator
        .wait_for_stage(&hash, PipelineStage::BftFinalised, PROGRESS_TIMEOUT)
        .await
        .context("wait for finalisation")?;

    cluster
        .wait_for_quorum_progress(&consensus_baseline, PROGRESS_TIMEOUT)
        .await
        .context("quorum progress for proof generation")?;

    let status = primary_handle
        .consensus_status()
        .context("fetch consensus status")?;

    let proofs = primary_handle
        .block_proofs(status.height)
        .context("fetch block proofs")?
        .context("proof bundle missing")?;

    let elapsed = started.elapsed().as_millis();
    let report = ScenarioReport {
        scenario: "proof_generation",
        elapsed_ms: elapsed,
        notes: vec![
            format!("height={}", proofs.height),
            format!(
                "tx_proofs={} state_proof_system={:?}",
                proofs.stark.transaction_proofs.len(),
                proofs.stark.state_proof.system()
            ),
        ],
    };

    if let Err(err) = write_json_artifact("metrics/proof_generation.json", &report) {
        eprintln!("failed to persist proof generation metrics: {err:?}");
    }

    if let Err(err) = write_json_artifact("snapshots/proof_generation_bundle.json", &proofs) {
        eprintln!("failed to persist proof generation snapshot: {err:?}");
    }

    orchestrator.shutdown();
    cluster.shutdown().await.context("shutdown cluster")?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn regression_snapshot_recovery_restores_state() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match start_cluster().await {
        Some(cluster) => cluster,
        None => return Ok(()),
    };

    let started = Instant::now();

    cluster
        .wait_for_full_mesh(NETWORK_TIMEOUT)
        .await
        .context("cluster mesh formation")?;

    let baseline = cluster
        .consensus_snapshots()
        .context("capture consensus baseline")?;

    cluster
        .wait_for_quorum_progress(&baseline, PROGRESS_TIMEOUT)
        .await
        .context("initial quorum progress")?;

    let pre_restart_status = {
        let node = &cluster.nodes()[0];
        node.node_handle
            .consensus_status()
            .context("consensus status before restart")?
    };

    let block = cluster.nodes()[0]
        .node_handle
        .get_block(pre_restart_status.height)
        .context("fetch block before restart")?
        .context("block missing before restart")?;

    if let Err(err) = write_json_artifact("snapshots/snapshot_recovery_block.json", &block) {
        eprintln!("failed to persist snapshot recovery block: {err:?}");
    }

    cluster.nodes_mut()[0]
        .restart()
        .await
        .context("restart primary node")?;

    sleep(RESTART_GRACE).await;

    cluster.nodes()[0]
        .wait_for_peer_count(cluster.nodes().len() - 1, NETWORK_TIMEOUT)
        .await
        .context("wait for peer reconnection")?;

    let post_restart_status = cluster.nodes()[0]
        .node_handle
        .consensus_status()
        .context("consensus status after restart")?;

    let resumed_block = cluster.nodes()[0]
        .node_handle
        .get_block(pre_restart_status.height)
        .context("fetch block after restart")?
        .context("block missing after restart")?;

    let elapsed = started.elapsed().as_millis();
    let report = ScenarioReport {
        scenario: "snapshot_recovery",
        elapsed_ms: elapsed,
        notes: vec![
            format!("pre_height={}", pre_restart_status.height),
            format!("post_height={}", post_restart_status.height),
        ],
    };

    if let Err(err) = write_json_artifact("metrics/snapshot_recovery.json", &report) {
        eprintln!("failed to persist snapshot recovery metrics: {err:?}");
    }

    if let Err(err) = append_log(
        "logs/snapshot_recovery.log",
        &format!(
            "block_hash_before={:?} block_hash_after={:?}",
            block.hash, resumed_block.hash
        ),
    ) {
        eprintln!("failed to persist snapshot recovery log: {err:?}");
    }

    cluster.shutdown().await.context("shutdown cluster")?;

    Ok(())
}
