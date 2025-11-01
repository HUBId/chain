use std::env;

use assert_cmd::Command;
use predicates::str::contains;

const ERROR_FRAGMENT: &str =
    "Plonky3 backend cannot be enabled together with the `prod` or `validator` features.";

#[test]
fn backend_plonky3_rejected_in_prod_builds() {
    assert_forbidden_features("backend-plonky3,prod");
}

#[test]
fn backend_plonky3_rejected_for_validator_feature() {
    assert_forbidden_features("backend-plonky3,validator");
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
