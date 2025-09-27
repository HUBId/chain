use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use rpp_sim::metrics::SimulationSummary;
use rpp_sim::reporters::cli;
use rpp_sim::scenario::Scenario;
use rpp_sim::SimHarness;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run rpp network simulations", long_about = None)]
struct Cli {
    /// Path to the scenario TOML file
    #[arg(long)]
    scenario: PathBuf,

    /// Override the metrics output location
    #[arg(long)]
    output: Option<PathBuf>,

    /// Override the simulation mode defined in the scenario file
    #[arg(long)]
    mode: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let harness = SimHarness;
    let mut scenario = Scenario::from_path(&cli.scenario)?;

    if let Some(mode) = cli.mode.clone() {
        scenario.sim.mode = Some(mode);
    }

    if let Some(output) = cli.output.clone() {
        let mut metrics = scenario.metrics.clone().unwrap_or_default();
        metrics.json = Some(output.clone());
        metrics.output = Some(output);
        scenario.metrics = Some(metrics);
    }

    let summary: SimulationSummary = harness.run_scenario(scenario)?;

    println!("{}", cli::render_compact(&summary));

    Ok(())
}
