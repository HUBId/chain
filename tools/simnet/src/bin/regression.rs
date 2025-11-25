use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser;
use html_escape::encode_text;
use serde::Serialize;
use serde_json::Value;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use simnet::config::SimnetConfig;
use simnet::consensus::{ConsensusLoadSummary, QuantileStats, TamperSummary};
use simnet::runner::SimnetRunner;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run the Phase-2 regression scenarios", long_about = None)]
struct Args {
    /// Override the root directory used to store artifacts for all scenarios.
    #[arg(long)]
    artifacts_root: Option<PathBuf>,

    /// Optional path for the aggregated JSON report. Defaults to <artifacts_root>/regression.json.
    #[arg(long)]
    json_report: Option<PathBuf>,

    /// Optional path for the aggregated HTML report. Defaults to <artifacts_root>/regression.html.
    #[arg(long)]
    html_report: Option<PathBuf>,

    /// Execute only the provided scenario files (repeat flag).
    #[arg(long = "scenario", value_name = "PATH")]
    scenarios: Vec<PathBuf>,

    /// Keep processes alive for 60 seconds between scenarios.
    #[arg(long)]
    keep_alive: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ScenarioReport {
    name: String,
    description: Option<String>,
    status: ScenarioStatus,
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    duration_secs: f64,
    artifacts_dir: PathBuf,
    errors: Vec<String>,
    consensus: Option<ConsensusSummary>,
    p2p_summary_path: Option<PathBuf>,
    p2p_summary: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
struct ConsensusSummary {
    summary_path: PathBuf,
    csv_path: Option<PathBuf>,
    runs: u64,
    validators: usize,
    witness_commitments: usize,
    prove_ms: QuantileStats,
    verify_ms: QuantileStats,
    proof_bytes: QuantileStats,
    tamper_vrf: Option<TamperSummary>,
    tamper_quorum: Option<TamperSummary>,
    failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum ScenarioStatus {
    Passed,
    Failed,
}

#[derive(Debug, Serialize)]
struct RegressionReport {
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    duration_secs: f64,
    total: usize,
    passed: usize,
    failed: usize,
    scenarios: Vec<ScenarioReport>,
}

const DEFAULT_SCENARIOS: &[&str] = &[
    "tools/simnet/scenarios/consensus_quorum_stress.ron",
    "tools/simnet/scenarios/snapshot_rebuild.ron",
    "tools/simnet/scenarios/gossip_backpressure.ron",
    "tools/simnet/scenarios/canary_rolling_restart.ron",
];

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let args = Args::parse();

    let scenario_paths = resolve_scenarios(&args)?;
    if scenario_paths.is_empty() {
        bail!("no scenarios resolved for regression run");
    }

    let started_at = Utc::now();
    let artifacts_root = ensure_artifacts_root(&args, started_at).await?;
    let mut scenario_reports = Vec::with_capacity(scenario_paths.len());

    for scenario_path in scenario_paths {
        let scenario_start = Instant::now();
        let wall_start = Utc::now();
        match execute_scenario(&artifacts_root, &scenario_path).await {
            Ok(mut report) => {
                report.started_at = wall_start;
                report.finished_at = Utc::now();
                report.duration_secs = scenario_start.elapsed().as_secs_f64();
                scenario_reports.push(report);
            }
            Err(err) => {
                error!(
                    target = "simnet::regression",
                    path = %scenario_path.display(),
                    "scenario failed: {err:#}"
                );
                let slug = scenario_slug(&scenario_path);
                scenario_reports.push(ScenarioReport {
                    name: slug.clone(),
                    description: None,
                    status: ScenarioStatus::Failed,
                    started_at: wall_start,
                    finished_at: Utc::now(),
                    duration_secs: scenario_start.elapsed().as_secs_f64(),
                    artifacts_dir: artifacts_root.join(slug),
                    errors: vec![format!("{err:#}")],
                    consensus: None,
                    p2p_summary_path: None,
                    p2p_summary: None,
                });
            }
        }

        if args.keep_alive {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }

    let passed = scenario_reports
        .iter()
        .filter(|report| report.status == ScenarioStatus::Passed)
        .count();
    let failed = scenario_reports.len() - passed;
    let report = RegressionReport {
        started_at,
        finished_at: Utc::now(),
        duration_secs: scenario_reports
            .iter()
            .map(|scenario| scenario.duration_secs)
            .sum::<f64>(),
        total: scenario_reports.len(),
        passed,
        failed,
        scenarios: scenario_reports,
    };

    write_reports(&args, &artifacts_root, &report).await?;

    if failed > 0 {
        bail!("{failed} scenario(s) failed during regression run");
    }

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn resolve_manifest_relative(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn resolve_scenarios(args: &Args) -> Result<Vec<PathBuf>> {
    if !args.scenarios.is_empty() {
        return Ok(args
            .scenarios
            .iter()
            .map(|path| resolve_manifest_relative(path))
            .collect());
    }

    Ok(DEFAULT_SCENARIOS
        .iter()
        .map(|path| resolve_manifest_relative(Path::new(path)))
        .collect())
}

fn scenario_slug(path: &Path) -> String {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("scenario")
        .replace('_', "-")
}

async fn ensure_artifacts_root(args: &Args, started_at: DateTime<Utc>) -> Result<PathBuf> {
    if let Some(explicit) = &args.artifacts_root {
        fs::create_dir_all(explicit)
            .await
            .with_context(|| format!("create artifacts root {}", explicit.display()))?;
        return Ok(explicit.clone());
    }

    let dir = PathBuf::from("target/simnet/regression")
        .join(started_at.format("%Y%m%d%H%M%S").to_string());
    fs::create_dir_all(&dir)
        .await
        .with_context(|| format!("create regression root {}", dir.display()))?;
    Ok(dir)
}

async fn execute_scenario(artifacts_root: &Path, scenario_path: &Path) -> Result<ScenarioReport> {
    let config = SimnetConfig::from_path(scenario_path)
        .with_context(|| format!("load scenario {}", scenario_path.display()))?;
    config
        .validate()
        .with_context(|| format!("invalid scenario {}", scenario_path.display()))?;
    let slug = scenario_slug(scenario_path);
    let scenario_dir = artifacts_root.join(&slug);
    fs::create_dir_all(&scenario_dir)
        .await
        .with_context(|| format!("create scenario dir {}", scenario_dir.display()))?;
    let artifacts_dir = config
        .resolve_artifacts_dir(Some(&scenario_dir))
        .with_context(|| format!("prepare artifacts dir {}", scenario_dir.display()))?;

    let mut runner = SimnetRunner::new(config.clone(), artifacts_dir.clone(), None);

    info!(
        target = "simnet::regression",
        path = %scenario_path.display(),
        artifacts = %artifacts_dir.display(),
        "executing scenario"
    );

    let mut errors = Vec::new();
    if let Err(err) = runner.execute().await {
        errors.push(format!("execution error: {err:#}"));
    }

    if let Err(err) = runner.shutdown().await {
        errors.push(format!("shutdown error: {err:#}"));
    }

    let (p2p_summary_path, p2p_summary) = if let Some(p2p) = &config.p2p {
        let path = config.resolve_summary_path(p2p, &artifacts_dir);
        let summary = if path.exists() {
            Some(read_json::<Value>(&path).await?)
        } else {
            None
        };
        (Some(path), summary)
    } else {
        (None, None)
    };

    let consensus_summary = if let Some(consensus) = &config.consensus {
        let summary_path = config.resolve_consensus_summary_path(consensus, &artifacts_dir);
        if summary_path.exists() {
            let summary: ConsensusLoadSummary = read_json(&summary_path).await?;
            Some(ConsensusSummary {
                summary_path,
                csv_path: summary.csv_path.clone(),
                runs: summary.runs,
                validators: summary.validators,
                witness_commitments: summary.witness_commitments,
                prove_ms: summary.prove_ms.clone(),
                verify_ms: summary.verify_ms.clone(),
                proof_bytes: summary.proof_bytes.clone(),
                tamper_vrf: summary.tamper_vrf.clone(),
                tamper_quorum: summary.tamper_quorum.clone(),
                failures: summary.failures.clone(),
            })
        } else {
            errors.push(format!(
                "missing consensus summary at {}",
                summary_path.display()
            ));
            None
        }
    } else {
        None
    };

    let status = if errors.is_empty() {
        ScenarioStatus::Passed
    } else {
        ScenarioStatus::Failed
    };

    Ok(ScenarioReport {
        name: config.name,
        description: config.description,
        status,
        started_at: Utc::now(),
        finished_at: Utc::now(),
        duration_secs: 0.0,
        artifacts_dir,
        errors,
        consensus: consensus_summary,
        p2p_summary_path,
        p2p_summary,
    })
}

async fn write_reports(
    args: &Args,
    artifacts_root: &Path,
    report: &RegressionReport,
) -> Result<()> {
    let json_path = args
        .json_report
        .clone()
        .unwrap_or_else(|| artifacts_root.join("regression.json"));
    let html_path = args
        .html_report
        .clone()
        .unwrap_or_else(|| artifacts_root.join("regression.html"));

    if let Some(parent) = json_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create directory {}", parent.display()))?;
    }
    let json_bytes = serde_json::to_vec_pretty(report).context("serialize regression report")?;
    fs::write(&json_path, json_bytes)
        .await
        .with_context(|| format!("write JSON report {}", json_path.display()))?;

    let html = render_html(report);
    if let Some(parent) = html_path.parent() {
        fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create directory {}", parent.display()))?;
    }
    let mut file = fs::File::create(&html_path)
        .await
        .with_context(|| format!("create HTML report {}", html_path.display()))?;
    file.write_all(html.as_bytes())
        .await
        .with_context(|| format!("write HTML report {}", html_path.display()))?;

    info!(
        target = "simnet::regression",
        json = %json_path.display(),
        html = %html_path.display(),
        "wrote regression reports"
    );

    Ok(())
}

async fn read_json<T>(path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = fs::read(path)
        .await
        .with_context(|| format!("read JSON file {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON file {}", path.display()))
}

fn render_html(report: &RegressionReport) -> String {
    let mut rows = String::new();
    for scenario in &report.scenarios {
        let status_class = match scenario.status {
            ScenarioStatus::Passed => "status-passed",
            ScenarioStatus::Failed => "status-failed",
        };
        let mut details = String::new();
        if let Some(consensus) = &scenario.consensus {
            details.push_str(&format!(
                "<div class=\"metrics\"><strong>Consensus</strong>: runs={} validators={} p95_prove_ms={:.0} p95_verify_ms={:.0}</div>",
                consensus.runs,
                consensus.validators,
                consensus.prove_ms.p95,
                consensus.verify_ms.p95
            ));
        }
        if let Some(path) = &scenario.p2p_summary_path {
            details.push_str(&format!(
                "<div class=\"metrics\"><strong>P2P Summary</strong>: {}</div>",
                encode_text(&path.display().to_string())
            ));
        }
        if !scenario.errors.is_empty() {
            details.push_str("<ul class=\"errors\">");
            for error in &scenario.errors {
                details.push_str(&format!("<li>{}</li>", encode_text(error)));
            }
            details.push_str("</ul>");
        }
        rows.push_str(&format!(
            "<tr class=\"{status_class}\"><td>{name}</td><td>{description}</td><td>{duration:.1}</td><td>{artifacts}</td><td>{details}</td></tr>\n",
            status_class = status_class,
            name = encode_text(&scenario.name),
            description = encode_text(
                scenario
                    .description
                    .as_deref()
                    .unwrap_or("(no description)")
            ),
            duration = scenario.duration_secs,
            artifacts = encode_text(&scenario.artifacts_dir.display().to_string()),
            details = details
        ));
    }

    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Simnet Regression Report</title><style>{styles}</style></head><body><h1>Simnet Regression Report</h1><p>Started: {started}<br>Finished: {finished}<br>Total duration (s): {duration:.1}<br>Passed: {passed}/{total}</p><table><thead><tr><th>Scenario</th><th>Description</th><th>Duration (s)</th><th>Artifacts</th><th>Details</th></tr></thead><tbody>{rows}</tbody></table></body></html>",
        styles = HTML_STYLES,
        started = report.started_at,
        finished = report.finished_at,
        duration = report.duration_secs,
        passed = report.passed,
        total = report.total,
        rows = rows
    )
}

const HTML_STYLES: &str = r#"
body {
  font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  margin: 2rem;
  color: #1f2933;
  background: #f7fafc;
}

h1 {
  font-size: 1.75rem;
  margin-bottom: 1rem;
}

p {
  background: #fff;
  padding: 1rem;
  border-radius: 0.5rem;
  box-shadow: 0 1px 3px rgba(15, 23, 42, 0.1);
}

table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 1rem;
}

th, td {
  text-align: left;
  padding: 0.75rem;
  border-bottom: 1px solid #e2e8f0;
  vertical-align: top;
}

tr.status-passed {
  background: #f0fff4;
}

tr.status-failed {
  background: #fff5f5;
}

tr:nth-child(even) {
  background: rgba(255, 255, 255, 0.7);
}

.metrics {
  margin-bottom: 0.25rem;
}

.errors {
  margin: 0.5rem 0 0 1rem;
  color: #b83280;
}

.errors li {
  margin-bottom: 0.25rem;
}
"#;
