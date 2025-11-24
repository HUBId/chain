use std::fs;
use std::path::PathBuf;
use std::process::Command;

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

fn run_simnet_scenario(
    name: &str,
    extra_args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
) -> (std::process::ExitStatus, String, String) {
    let workspace = workspace_root();
    let scenario = workspace.join("tools/simnet/tests/data").join(name);
    let artifacts = artifacts_dir(&format!("test-{name}"));
    if artifacts.exists() {
        fs::remove_dir_all(&artifacts).expect("clean previous artifacts");
    }

    let mut command = Command::new("cargo");
    command
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
        .env("RUST_LOG", "off");

    for arg in extra_args {
        command.arg(arg);
    }

    let output = command.output().expect("spawn cargo run simnet");

    (
        output.status,
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn rejects_zero_peer_topology() {
    let (status, _stdout, stderr) = run_simnet_scenario("invalid_zero_peers.ron", []);

    assert!(!status.success(), "simnet should reject zero-peer topology");
    assert_ne!(status.code().unwrap_or_default(), 0);
    assert!(
        stderr.contains("topology must include at least one peer"),
        "stderr should mention missing peers, got: {stderr}"
    );
}

#[test]
fn rejects_negative_link_loss() {
    let (status, _stdout, stderr) = run_simnet_scenario("invalid_link_loss.ron", []);

    assert!(!status.success(), "simnet should reject invalid link loss");
    assert_ne!(status.code().unwrap_or_default(), 0);
    assert!(
        stderr.contains("link 'default' loss must be between 0 and 1 inclusive"),
        "stderr should mention link loss bounds, got: {stderr}"
    );
}

#[test]
fn rejects_empty_consensus_parameters() {
    let (status, _stdout, stderr) = run_simnet_scenario("invalid_consensus.ron", []);

    assert!(
        !status.success(),
        "simnet should reject invalid consensus config"
    );
    assert_ne!(status.code().unwrap_or_default(), 0);
    assert!(
        stderr.contains("consensus.runs must be greater than zero"),
        "stderr should mention invalid consensus runs, got: {stderr}"
    );
}

#[test]
fn rejects_insufficient_resources_without_override() {
    let (status, _stdout, stderr) = run_simnet_scenario("insufficient_resources.ron", []);

    assert!(
        !status.success(),
        "simnet should reject runs that do not meet resource guidance"
    );
    assert!(
        stderr.contains("host resources below scenario guidance"),
        "stderr should mention resource guidance, got: {stderr}"
    );
}

#[test]
fn allows_resource_override_flag() {
    let (status, _stdout, stderr) = run_simnet_scenario(
        "insufficient_resources.ron",
        ["--allow-insufficient-resources"],
    );

    assert!(status.success(), "override flag should permit running");
    assert!(
        stderr.contains("resource guidance"),
        "resource totals should be logged, got: {stderr}"
    );
}
