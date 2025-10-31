use std::env;
use std::path::PathBuf;
use std::process::Command;

use anyhow::Context;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in workspace root")
}

fn run_pruning_validation() -> anyhow::Result<()> {
    let status = Command::new("cargo")
        .current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("rpp-chain")
        .arg("--locked")
        .arg("--test")
        .arg("pruning_validation")
        .status()?;

    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("pruning validation suite failed")
    }
}

fn run_test_matrix() -> anyhow::Result<()> {
    let root = workspace_root();
    let suites: [(&str, &[&str]); 2] = [
        (
            "stable rpp-chain tests",
            &[
                "+stable",
                "test",
                "-p",
                "rpp-chain",
                "--all-targets",
                "--locked",
            ],
        ),
        (
            "prover-stwo matrix",
            &[
                "+nightly-2025-07-14",
                "test",
                "-p",
                "rpp-chain",
                "--all-targets",
                "--features",
                "prover-stwo",
                "--locked",
            ],
        ),
    ];

    for (label, args) in suites {
        println!("running {label}: cargo {}", args.join(" "));
        let status = Command::new("cargo")
            .current_dir(&root)
            .args(args)
            .status()
            .with_context(|| format!("failed to spawn {label}"))?;
        if !status.success() {
            anyhow::bail!("{label} failed");
        }
    }

    Ok(())
}

fn usage() {
    eprintln!(
        "xtask commands:\n  pruning-validation    Run pruning receipt conformance checks\n  test-matrix          Execute rpp-chain unit/integration tests across the prover-stwo matrix"
    );
}

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("pruning-validation") => run_pruning_validation(),
        Some("test-matrix") => run_test_matrix(),
        Some("help") | None => {
            usage();
            Ok(())
        }
        Some(other) => anyhow::bail!("unknown xtask command: {other}"),
    }
}
