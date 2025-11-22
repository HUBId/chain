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

#[test]
fn xtask_simnet_runs_small_world_smoke() {
    let workspace = workspace_root();
    let artifacts = workspace.join("target/simnet/test-small-world-smoke");
    if artifacts.exists() {
        fs::remove_dir_all(&artifacts).expect("clean previous artifacts");
    }

    let output = Command::new("cargo")
        .current_dir(&workspace)
        .arg("xtask")
        .arg("simnet")
        .arg("--profile")
        .arg("small-world")
        .arg("--artifacts-dir")
        .arg(&artifacts)
        .env("RUST_LOG", "off")
        .output()
        .expect("spawn cargo xtask simnet");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "xtask simnet small-world failed: {}\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        );
    }

    assert!(
        artifacts.exists(),
        "simnet artifacts directory should be created"
    );
}
