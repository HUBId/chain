use std::env;
use std::path::PathBuf;
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in workspace root")
}

fn run_command(mut command: Command, context: &str) -> anyhow::Result<()> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("{context} exited with status {status}")
    }
}

fn run_pruning_validation() -> anyhow::Result<()> {
    run_command(
        Command::new("cargo")
            .current_dir(workspace_root())
            .arg("test")
            .arg("-p")
            .arg("rpp-chain")
            .arg("--locked")
            .arg("--test")
            .arg("pruning_validation"),
        "pruning validation",
    )
}

fn run_unit_suites() -> anyhow::Result<()> {
    run_command(
        Command::new("cargo")
            .current_dir(workspace_root())
            .arg("test")
            .arg("-p")
            .arg("rpp-chain")
            .arg("--locked")
            .arg("--test")
            .arg("unit"),
        "unit test suite",
    )
}

fn run_integration_workflows() -> anyhow::Result<()> {
    run_command(
        Command::new("cargo")
            .current_dir(workspace_root())
            .arg("test")
            .arg("-p")
            .arg("rpp-chain")
            .arg("--locked")
            .arg("--test")
            .arg("integration"),
        "integration workflows",
    )
}

fn run_simnet_smoke() -> anyhow::Result<()> {
    let scenario = workspace_root().join("tools/simnet/scenarios/ci_block_pipeline.ron");
    let artifacts = workspace_root().join("target/simnet/ci-block-pipeline");
    run_command(
        Command::new("cargo")
            .current_dir(workspace_root())
            .arg("run")
            .arg("--quiet")
            .arg("--package")
            .arg("simnet")
            .arg("--")
            .arg("--scenario")
            .arg(scenario)
            .arg("--artifacts-dir")
            .arg(artifacts),
        "simnet scenario",
    )
}

fn run_full_test_matrix() -> anyhow::Result<()> {
    run_unit_suites()?;
    run_integration_workflows()?;
    run_simnet_smoke()
}

fn usage() {
    eprintln!("xtask commands:\n  pruning-validation    Run pruning receipt conformance checks\n  test-unit            Execute lightweight unit test suites\n  test-integration     Execute integration workflows\n  test-simnet          Run the CI simnet scenario\n  test-all             Run unit, integration, and simnet scenarios");
}

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("pruning-validation") => run_pruning_validation(),
        Some("test-unit") => run_unit_suites(),
        Some("test-integration") => run_integration_workflows(),
        Some("test-simnet") => run_simnet_smoke(),
        Some("test-all") => run_full_test_matrix(),
        Some("help") | None => {
            usage();
            Ok(())
        }
        Some(other) => anyhow::bail!("unknown xtask command: {other}"),
    }
}
