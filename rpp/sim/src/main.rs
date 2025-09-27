use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use rpp_sim::metrics::SimulationSummary;
use rpp_sim::scenario::Scenario;
use rpp_sim::SimHarness;
use serde_json::json;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run rpp network simulations", long_about = None)]
struct Cli {
    /// Path to the scenario TOML file
    #[arg(long)]
    scenario: PathBuf,

    /// Override the metrics output location
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let harness = SimHarness;
    let summary: SimulationSummary = if let Some(output) = cli.output.clone() {
        let mut scenario = Scenario::from_path(&cli.scenario)?;
        let mut metrics = scenario.metrics.clone().unwrap_or_default();
        metrics.output = Some(output);
        scenario.metrics = Some(metrics);
        harness.run_scenario(scenario)?
    } else {
        harness.run_from_path(&cli.scenario)?
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "summary": summary
        }))?
    );

    Ok(())
}
