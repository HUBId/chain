use std::fs;
use std::path::PathBuf;

use anyhow::Result;
use rpp_sim::metrics::{exporters, SimulationSummary};
use rpp_sim::SimHarness;

fn scenario_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios/small_world_smoke.toml")
}

fn export_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../target/{file}"))
}

fn run_smoke() -> Result<SimulationSummary> {
    let harness = SimHarness;
    harness.run_from_path(scenario_path())
}

#[test]
#[ignore]
fn small_world_smoke_is_deterministic() -> Result<()> {
    let summary_first = run_smoke()?;
    let summary_second = run_smoke()?;

    assert_eq!(
        summary_first, summary_second,
        "summary must be reproducible"
    );

    let propagation = summary_first
        .propagation
        .as_ref()
        .expect("propagation percentiles");
    assert!(
        (propagation.p95_ms >= 10_000.0) && (propagation.p95_ms <= 60_000.0),
        "p95 in expected corridor: {}",
        propagation.p95_ms
    );

    let json_path = export_path("sim-smoke-summary.json");
    exporters::export_json(&json_path, &summary_first)?;
    let value: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&json_path)?).expect("valid json summary");
    assert!(value.get("total_publishes").is_some(), "json schema check");

    Ok(())
}
