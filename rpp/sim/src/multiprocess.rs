use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tempfile::TempDir;
use tokio::fs as async_fs;
use tokio::process::{Child, Command};
use tokio::time::{sleep, Instant};
use tracing::{info, warn};

use crate::harness::run_in_process;
use crate::metrics::{ComparisonReport, SimulationSummary};
use crate::scenario::Scenario;

struct NodeProcess {
    index: usize,
    child: Child,
    log_path: PathBuf,
}

pub struct MultiprocessOutcome {
    pub summary: SimulationSummary,
    pub log_directory: PathBuf,
    pub harness_logs: Vec<String>,
}

pub async fn run(scenario: Scenario) -> Result<SimulationSummary> {
    let mut baseline_scenario = scenario.clone();
    baseline_scenario.sim.mode = None;
    let baseline = run_in_process(baseline_scenario).await?;

    let outcome = orchestrate(&scenario).await?;
    let mut summary = outcome.summary;
    let comparison = ComparisonReport::from_runs(
        &baseline,
        &summary,
        Some(outcome.log_directory.clone()),
        outcome.harness_logs,
    );
    summary.comparison = Some(comparison);

    Ok(summary)
}

async fn orchestrate(scenario: &Scenario) -> Result<MultiprocessOutcome> {
    let workspace = TempDir::new().context("create multiprocess workspace")?;
    let base_dir = workspace.keep();
    let log_dir = base_dir.join("logs");
    fs::create_dir_all(&log_dir).context("create log directory")?;

    info!(
        target = "rpp::sim::multiprocess",
        nodes = scenario.topology.n,
        "launching node workers"
    );
    let mut nodes = spawn_nodes(scenario, &log_dir).await?;
    health_check_nodes(&nodes).await?;
    apply_netem_plan(scenario);

    let (summary, harness_logs) = run_external_simulation(scenario, &base_dir).await?;

    shutdown_nodes(&mut nodes).await;

    Ok(MultiprocessOutcome {
        summary,
        log_directory: log_dir,
        harness_logs,
    })
}

async fn spawn_nodes(scenario: &Scenario, log_dir: &Path) -> Result<Vec<NodeProcess>> {
    let mut handles = Vec::with_capacity(scenario.topology.n);
    for idx in 0..scenario.topology.n {
        let log_path = log_dir.join(format!("node-{idx}.log"));
        let stdout =
            File::create(&log_path).with_context(|| format!("create log file for node {idx}"))?;
        let stderr = stdout
            .try_clone()
            .with_context(|| format!("clone log handle for node {idx}"))?;

        let duration_ms = scenario.sim.duration_ms + 1_000;
        let mut command = Command::new("cargo");
        command
            .arg("run")
            .arg("--quiet")
            .arg("--package")
            .arg("rpp-node")
            .arg("--")
            .arg("--node-index")
            .arg(idx.to_string())
            .arg("--duration-ms")
            .arg(duration_ms.to_string());
        command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));

        let child = command
            .spawn()
            .with_context(|| format!("spawn rpp-node process {idx}"))?;
        handles.push(NodeProcess {
            index: idx,
            child,
            log_path,
        });
    }
    Ok(handles)
}

async fn health_check_nodes(nodes: &[NodeProcess]) -> Result<()> {
    for node in nodes {
        let mut attempts = 0;
        loop {
            attempts += 1;
            if attempts > 50 {
                return Err(anyhow!(
                    "node {} failed to report readiness within timeout",
                    node.index
                ));
            }
            if let Ok(contents) = async_fs::read_to_string(&node.log_path).await {
                if contents.contains("node ready") {
                    info!(
                        target = "rpp::sim::multiprocess",
                        node = node.index,
                        "worker reported ready"
                    );
                    break;
                }
            }
            sleep(Duration::from_millis(100)).await;
        }
    }
    Ok(())
}

fn apply_netem_plan(scenario: &Scenario) {
    for (key, params) in &scenario.links.entries {
        info!(
            target = "rpp::sim::multiprocess",
            link = %key,
            delay_ms = params.delay_ms,
            jitter_ms = params.jitter_ms,
            loss_percent = params.loss,
            "netem configuration pending"
        );
    }
}

async fn run_external_simulation(
    scenario: &Scenario,
    base_dir: &Path,
) -> Result<(SimulationSummary, Vec<String>)> {
    let scenario_path = scenario
        .source_path()
        .ok_or_else(|| anyhow!("scenario file path required for multiprocess mode"))?;
    let output_path = base_dir.join("multiprocess-summary.json");

    let mut command = Command::new("cargo");
    command
        .arg("run")
        .arg("--quiet")
        .arg("--package")
        .arg("rpp-sim")
        .arg("--")
        .arg("--scenario")
        .arg(scenario_path)
        .arg("--output")
        .arg(&output_path)
        .arg("--mode")
        .arg("inprocess");

    let started = Instant::now();
    let output = command
        .output()
        .await
        .context("spawn multiprocess harness run")?;
    let elapsed = started.elapsed().as_secs_f64();
    info!(
        target = "rpp::sim::multiprocess",
        duration_s = elapsed,
        status = ?output.status,
        "external simulation completed"
    );

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("multiprocess harness failed: {stderr}"));
    }

    let summary_bytes = async_fs::read(&output_path)
        .await
        .with_context(|| format!("read multiprocess summary {output_path:?}"))?;
    let summary: SimulationSummary =
        serde_json::from_slice(&summary_bytes).context("parse multiprocess summary")?;

    let stdout_log = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr_log = String::from_utf8_lossy(&output.stderr).to_string();

    Ok((summary, vec![stdout_log, stderr_log]))
}

async fn shutdown_nodes(nodes: &mut [NodeProcess]) {
    for node in nodes.iter_mut() {
        if let Some(id) = node.child.id() {
            info!(
                target = "rpp::sim::multiprocess",
                node = node.index,
                pid = id,
                "terminating worker"
            );
        }
        if let Err(err) = node.child.start_kill() {
            warn!(
                target = "rpp::sim::multiprocess",
                node = node.index,
                "failed to signal termination: {err:?}"
            );
        }
    }

    for node in nodes.iter_mut() {
        match node.child.wait().await {
            Ok(status) => {
                info!(
                    target = "rpp::sim::multiprocess",
                    node = node.index,
                    status = ?status,
                    "worker exited"
                );
            }
            Err(err) => {
                warn!(
                    target = "rpp::sim::multiprocess",
                    node = node.index,
                    "failed to await worker: {err:?}"
                );
            }
        }
    }
}
