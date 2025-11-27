use std::path::PathBuf;

use rpp_chain::runtime::config::{ConfigValidation, NodeConfig};

fn load_template(path: &str) -> NodeConfig {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let full_path = base.join("../../").join(path);
    NodeConfig::load_with_validation(&full_path, ConfigValidation::Strict)
        .unwrap_or_else(|err| panic!("failed to load {}: {}", path, err))
}

#[test]
fn production_templates_validate_under_strict_rules() {
    let stwo = load_template("config/examples/production/validator-stwo-tls.toml");
    assert!(stwo.network.tls.enabled && stwo.network.tls.require_client_auth);
    assert!(stwo.network.rpc.require_auth);
    assert!(stwo.rollout.feature_gates.malachite_consensus);
    assert!(stwo.pruning.pacing.cpu_max_percent <= 100.0);

    let plonky3 = load_template("config/examples/production/validator-plonky3-tls.toml");
    assert!(plonky3.network.tls.enabled && plonky3.network.tls.require_client_auth);
    assert!(plonky3.network.rpc.require_auth);
    assert!(plonky3.rollout.feature_gates.malachite_consensus);
    assert!(plonky3
        .proof_cache
        .per_backend_retain
        .contains_key("plonky3"));
}
