use std::process::Command;

#[test]
fn rpp_chain_builds_without_default_features() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let status = Command::new(cargo)
        .args(["check", "-p", "rpp-chain", "--no-default-features"])
        .status()
        .expect("failed to invoke cargo check for bypass configuration");
    assert!(
        status.success(),
        "cargo check --no-default-features for rpp-chain failed with {:?}",
        status
    );
}
