use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in workspace root")
        .to_path_buf()
}

fn apply_feature_flags(command: &mut Command) {
    let no_defaults = env::var("XTASK_NO_DEFAULT_FEATURES")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    if no_defaults {
        command.arg("--no-default-features");
    }
    if let Ok(features) = env::var("XTASK_FEATURES") {
        let trimmed = features.trim();
        if !trimmed.is_empty() {
            command.arg("--features").arg(trimmed);
        }
    }
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
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("pruning_validation");
    apply_feature_flags(&mut command);
    run_command(command, "pruning validation")
}

fn run_unit_suites() -> anyhow::Result<()> {
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("unit");
    apply_feature_flags(&mut command);
    run_command(command, "unit test suite")
}

fn run_integration_workflows() -> anyhow::Result<()> {
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("integration");
    apply_feature_flags(&mut command);
    run_command(command, "integration workflows")
}

fn run_simnet_smoke() -> anyhow::Result<()> {
    let scenarios = [
        "tools/simnet/scenarios/ci_block_pipeline.ron",
        "tools/simnet/scenarios/ci_state_sync_guard.ron",
        "tools/simnet/scenarios/consensus_quorum_stress.ron",
    ];
    for scenario in scenarios {
        let scenario_path = workspace_root().join(scenario);
        let stem = Path::new(scenario)
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("ci-simnet");
        let artifacts = workspace_root()
            .join("target/simnet")
            .join(stem.replace('_', "-"));
        let mut command = Command::new("cargo");
        command
            .current_dir(workspace_root())
            .arg("run")
            .arg("--quiet")
            .arg("--package")
            .arg("simnet")
            .arg("--")
            .arg("--scenario")
            .arg(scenario_path)
            .arg("--artifacts-dir")
            .arg(artifacts);
        apply_feature_flags(&mut command);
        let context = format!("simnet scenario {stem}");
        run_command(command, &context)?;
    }
    Ok(())
}

fn run_consensus_manipulation_tests() -> anyhow::Result<()> {
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace_root())
        .arg("test")
        .arg("--locked")
        .arg("--test")
        .arg("consensus_certificate_tampering");
    apply_feature_flags(&mut command);
    run_command(command, "consensus manipulation checks")
}

fn run_full_test_matrix() -> anyhow::Result<()> {
    run_unit_suites()?;
    run_integration_workflows()?;
    run_simnet_smoke()
}

fn usage() {
    eprintln!("xtask commands:\n  pruning-validation    Run pruning receipt conformance checks\n  test-unit            Execute lightweight unit test suites\n  test-integration     Execute integration workflows\n  test-simnet          Run the CI simnet scenario\n  test-consensus-manipulation  Exercise consensus tamper detection tests\n  test-all             Run unit, integration, and simnet scenarios");
}

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("pruning-validation") => run_pruning_validation(),
        Some("test-unit") => run_unit_suites(),
        Some("test-integration") => run_integration_workflows(),
        Some("test-simnet") => run_simnet_smoke(),
        Some("test-consensus-manipulation") => run_consensus_manipulation_tests(),
        Some("test-all") => run_full_test_matrix(),
        Some("help") | None => {
            usage();
            Ok(())
        }
        Some(other) => anyhow::bail!("unknown xtask command: {other}"),
    }
}
