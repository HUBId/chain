use std::env;
use std::path::PathBuf;
use std::process::Command;

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

fn usage() {
    eprintln!("xtask commands:\n  pruning-validation    Run pruning receipt conformance checks");
}

fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("pruning-validation") => run_pruning_validation(),
        Some("help") | None => {
            usage();
            Ok(())
        }
        Some(other) => anyhow::bail!("unknown xtask command: {other}"),
    }
}
