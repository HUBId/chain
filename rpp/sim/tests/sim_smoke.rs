use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Once;

use anyhow::Result;
use rpp_sim::metrics::{exporters, SimulationSummary};
use rpp_sim::SimHarness;

const PLAN_MAX_REJOIN_LATENCY_MS: f64 = 12_000.0;
const PLAN_MIN_MESH_STABILITY: f64 = 0.82;

static INIT_STATIC_KEY: Once = Once::new();

fn scenario_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios/small_world_smoke.toml")
}

fn partition_restart_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scenarios/partition_restart_plan.toml")
}

fn export_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("../../target/{file}"))
}

fn ensure_static_key_seed() {
    INIT_STATIC_KEY.call_once(|| {
        // Tests require deterministic peer identities so restart cycles are reproducible.
        env::set_var("RPP_SIM_STATIC_KEY_SEED", "ci-plan");
    });
}

fn run_from_path(path: PathBuf) -> Result<SimulationSummary> {
    ensure_static_key_seed();
    let harness = SimHarness;
    harness.run_from_path(path)
}

fn run_smoke() -> Result<SimulationSummary> {
    run_from_path(scenario_path())
}

fn run_partition_restart() -> Result<SimulationSummary> {
    run_from_path(partition_restart_path())
}

#[test]
#[cfg_attr(
    not(feature = "ci-sim"),
    ignore = "requires --features ci-sim to enable deterministic simulator"
)]
fn small_world_smoke_is_deterministic() -> Result<()> {
    let summary_first = run_smoke()?;
    let summary_second = run_smoke()?;

    let require_deterministic = env::var("RPP_SIM_REQUIRE_DETERMINISTIC")
        .map(|value| value != "0")
        .unwrap_or(true);
    if require_deterministic {
        assert_eq!(
            summary_first, summary_second,
            "summary must be reproducible"
        );
    }

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

#[test]
#[cfg_attr(
    not(feature = "ci-sim"),
    ignore = "requires --features ci-sim to enable deterministic simulator"
)]
fn partition_restart_plan_recovers_mesh() -> Result<()> {
    let summary = run_partition_restart()?;

    assert!(
        summary
            .faults
            .iter()
            .any(|fault| fault.kind == "partition_start"),
        "partition start fault must be recorded"
    );
    assert!(
        summary
            .faults
            .iter()
            .any(|fault| fault.kind == "partition_end"),
        "partition end fault must be recorded"
    );

    let mut outstanding: HashMap<String, f64> = HashMap::new();
    let mut max_rejoin_latency_ms: f64 = 0.0;
    let mut down_count = 0usize;
    let mut up_count = 0usize;

    for fault in &summary.faults {
        match fault.kind.as_str() {
            "churn_down" => {
                let detail = fault
                    .detail
                    .as_ref()
                    .expect("churn_down events carry node detail")
                    .clone();
                outstanding.insert(detail, fault.timestamp_ms);
                down_count += 1;
            }
            "churn_up" => {
                let detail = fault
                    .detail
                    .as_ref()
                    .expect("churn_up events carry node detail")
                    .clone();
                let down_timestamp = outstanding
                    .remove(&detail)
                    .expect("peer restart recorded after churn_down");
                let latency = fault.timestamp_ms - down_timestamp;
                max_rejoin_latency_ms = max_rejoin_latency_ms.max(latency);
                up_count += 1;
            }
            _ => {}
        }
    }

    assert_eq!(
        down_count, up_count,
        "every churn_down must be paired with a churn_up"
    );
    assert!(
        outstanding.is_empty(),
        "no peers should remain offline at the end of the run"
    );
    assert!(
        max_rejoin_latency_ms <= PLAN_MAX_REJOIN_LATENCY_MS,
        "max rejoin latency {:.2} ms must be below plan target {:.2} ms",
        max_rejoin_latency_ms,
        PLAN_MAX_REJOIN_LATENCY_MS
    );

    let total_receives = summary.total_receives.max(1) as f64;
    let mesh_changes = summary.mesh_changes.len() as f64;
    let mesh_stability = 1.0 - mesh_changes / total_receives;
    assert!(
        mesh_stability >= PLAN_MIN_MESH_STABILITY,
        "mesh stability {:.3} below plan floor {:.3}",
        mesh_stability,
        PLAN_MIN_MESH_STABILITY
    );

    Ok(())
}
