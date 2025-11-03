use std::env;

use assert_cmd::Command;
use predicates::str::contains;

const ERROR_FRAGMENT: &str = "The Plonky3 backend cannot be combined with the mock prover feature.";

#[test]
fn backend_plonky3_rejected_with_mock_prover() {
    assert_forbidden_features("backend-plonky3,prover-mock");
}

#[test]
fn backend_plonky3_gpu_rejected_with_mock_prover() {
    assert_forbidden_features("backend-plonky3-gpu,prover-mock");
}

fn assert_forbidden_features(features: &str) {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());

    let mut cmd = Command::new(cargo);
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
    cmd.arg("check")
        .arg("-p")
        .arg("rpp-node")
        .arg("--no-default-features")
        .arg("--features")
        .arg(features);

    cmd.assert().failure().stderr(contains(ERROR_FRAGMENT));
}
