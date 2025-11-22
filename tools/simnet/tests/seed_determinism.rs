use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("simnet lives under tools/")
        .parent()
        .expect("tools lives under workspace root")
        .to_path_buf()
}

fn artifacts_dir(label: &str) -> PathBuf {
    workspace_root().join("target").join("simnet").join(label)
}

fn read_summary(path: &PathBuf) -> Value {
    let contents = fs::read_to_string(path).expect("read summary file");
    serde_json::from_str(&contents).expect("parse summary json")
}

fn run_seeded_consensus(seed: u64, label: &str) -> PathBuf {
    let workspace = workspace_root();
    let scenario = workspace
        .join("tools/simnet/tests/data")
        .join("deterministic_consensus.ron");
    let artifacts = artifacts_dir(label);
    if artifacts.exists() {
        fs::remove_dir_all(&artifacts).expect("remove previous artifacts");
    }

    let output = Command::new("cargo")
        .current_dir(&workspace)
        .arg("run")
        .arg("--quiet")
        .arg("-p")
        .arg("simnet")
        .arg("--bin")
        .arg("simnet")
        .arg("--")
        .arg("--scenario")
        .arg(&scenario)
        .arg("--artifacts-dir")
        .arg(&artifacts)
        .arg("--seed")
        .arg(seed.to_string())
        .env("RUST_LOG", "off")
        .output()
        .expect("spawn cargo run simnet");

    if !output.status.success() {
        panic!(
            "seeded consensus run failed: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    artifacts
        .join("summaries")
        .join("deterministic_consensus.json")
}

#[test]
fn repeats_with_identical_seed_are_stable() {
    let seed = 2024_u64;
    let first_summary = run_seeded_consensus(seed, "deterministic-consensus-a");
    let second_summary = run_seeded_consensus(seed, "deterministic-consensus-b");

    let first = read_summary(&first_summary);
    let second = read_summary(&second_summary);

    assert_eq!(
        first, second,
        "consensus summaries should match when using identical seeds"
    );

    assert_eq!(
        first
            .get("seed")
            .and_then(|value| value.as_u64())
            .expect("seed recorded in summary"),
        seed,
        "summary should record the CLI-provided seed"
    );
}
