mod config;
mod process;
mod runner;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::time::Duration;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::SimnetConfig;
use crate::runner::SimnetRunner;

#[derive(Debug, Parser)]
#[command(author, version, about = "Orchestrate RPP simulation networks", long_about = None)]
struct Cli {
    /// Path to the RON scenario file
    #[arg(long)]
    scenario: PathBuf,

    /// Override the artifacts directory defined in the scenario
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Keep processes alive after the harness finishes
    #[arg(long)]
    keep_alive: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing();

    let config = SimnetConfig::from_path(&cli.scenario)
        .with_context(|| format!("failed to load scenario {}", cli.scenario.display()))?;
    let artifacts_dir = config.resolve_artifacts_dir(cli.artifacts_dir.as_deref())?;

    let mut runner = SimnetRunner::new(config, artifacts_dir);
    let outcome = runner.execute().await;

    if cli.keep_alive {
        info!(target = "simnet", "keep-alive requested; sleeping for 60s");
        tokio::time::sleep(Duration::from_secs(60)).await;
    }

    let mut shutdown_error = None;
    if let Err(err) = runner.shutdown().await {
        error!(target = "simnet", "failed to shutdown processes: {err:#}");
        shutdown_error = Some(err);
    }

    outcome?;

    if let Some(err) = shutdown_error {
        return Err(err);
    }

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}
