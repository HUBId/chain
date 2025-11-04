use std::env;
use std::process::Command;

const ERROR_FRAGMENT: &str = "The Plonky3 backend cannot be combined with the mock prover feature.";

fn run_guard_check(features: &str) -> (bool, String) {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

    let output = Command::new(cargo)
        .current_dir(env!("CARGO_WORKSPACE_DIR"))
        .arg("check")
        .arg("--package")
        .arg("rpp-node")
        .arg("--no-default-features")
        .arg("--features")
        .arg(features)
        .output()
        .expect("failed to execute cargo check for feature guard test");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (output.status.success(), stderr)
}

#[test]
fn backend_plonky3_rejected_with_mock_prover() {
    let (success, stderr) = run_guard_check("backend-plonky3,prover-mock");
    assert!(
        !success,
        "expected cargo check to fail when backend-plonky3 and prover-mock are combined\n{}",
        stderr
    );
    assert!(
        stderr.contains(ERROR_FRAGMENT),
        "feature guard error message missing from stderr\n{}",
        stderr
    );
}

#[test]
fn backend_plonky3_gpu_rejected_with_mock_prover() {
    let (success, stderr) = run_guard_check("backend-plonky3-gpu,prover-mock");
    assert!(
        !success,
        "expected cargo check to fail when backend-plonky3-gpu and prover-mock are combined\n{}",
        stderr
    );
    assert!(
        stderr.contains(ERROR_FRAGMENT),
        "feature guard error message missing from stderr\n{}",
        stderr
    );
}
