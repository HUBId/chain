use std::collections::BTreeMap;
use std::error::Error;
use std::fs;

use rpp_chain::config::FeatureGates;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct RolloutBundle {
    version: u32,
    bundle: String,
    description: String,
    node_template: String,
    wallet_template: String,
    notes: Vec<String>,
    stages: Vec<StageProfile>,
}

#[derive(Debug, Deserialize)]
struct StageProfile {
    name: String,
    release_channel: String,
    change_window: String,
    feature_gates: FeatureGates,
    release_checks: Vec<String>,
    recovery_playbook: String,
}

#[test]
fn mainnet_bundle_progression_is_monotonic() -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string("config/defaults/mainnet.toml")?;
    let bundle: RolloutBundle = toml::from_str(&contents)?;

    assert_eq!(bundle.version, 1, "unexpected config bundle version");
    assert_eq!(bundle.bundle, "mainnet-rollout", "bundle identifier drifted");
    assert!(
        bundle.description.contains("Staged rollout"),
        "bundle description should explain staged rollout purpose"
    );
    assert!(
        bundle.node_template.ends_with("validator.toml"),
        "node_template should point at validator defaults"
    );
    assert!(
        bundle.wallet_template.ends_with("wallet.toml"),
        "wallet_template should point at wallet defaults"
    );
    assert!(
        bundle
            .notes
            .iter()
            .any(|note| note.contains("Feature gates graduate")),
        "bundle notes must spell out feature gate monotonicity"
    );

    let expected_order = ["development", "testnet", "canary", "mainnet"];
    assert_eq!(
        bundle.stages.len(),
        expected_order.len(),
        "unexpected number of rollout stages"
    );
    let mut seen_names = Vec::new();
    let mut previous_gates: Option<BTreeMap<&'static str, bool>> = None;

    for (index, stage) in bundle.stages.iter().enumerate() {
        assert_eq!(
            stage.name, expected_order[index],
            "stages must remain in development→testnet→canary→mainnet order"
        );
        assert_eq!(
            stage.release_channel, expected_order[index],
            "release_channel must match stage name"
        );
        assert!(
            !stage.change_window.is_empty(),
            "stage change window should be documented"
        );
        assert!(
            stage
                .release_checks
                .iter()
                .any(|check| check.contains("common-preflight-checks")),
            "each stage must reference the shared preflight checklist"
        );
        assert!(
            stage
                .release_checks
                .iter()
                .all(|check| check.starts_with("docs/deployment/staged_rollout.md#")),
            "release checks must link to the staged rollout runbook"
        );
        assert!(
            stage
                .recovery_playbook
                .starts_with("docs/deployment/staged_rollout.md#"),
            "recovery playbook should live in the staged rollout runbook"
        );

        let gate_map = to_gate_map(&stage.feature_gates);
        if let Some(prev) = &previous_gates {
            for (gate, enabled) in &gate_map {
                if let Some(previous_value) = prev.get(gate) {
                    assert!(
                        !previous_value || *enabled,
                        "feature gate `{gate}` regressed from true to false in {stage_name}",
                        stage_name = stage.name
                    );
                }
            }
        }
        previous_gates = Some(gate_map.clone());
        seen_names.push(stage.name.clone());
    }

    assert_eq!(seen_names, expected_order, "stage order drifted");

    let final_stage = bundle
        .stages
        .last()
        .expect("at least one stage should be defined");
    let final_gates = to_gate_map(&final_stage.feature_gates);
    for (gate, enabled) in final_gates {
        assert!(enabled, "final stage must enable `{gate}`");
    }

    Ok(())
}

fn to_gate_map(gates: &FeatureGates) -> BTreeMap<&'static str, bool> {
    BTreeMap::from([
        ("consensus_enforcement", gates.consensus_enforcement),
        ("malachite_consensus", gates.malachite_consensus),
        ("pruning", gates.pruning),
        ("reconstruction", gates.reconstruction),
        ("recursive_proofs", gates.recursive_proofs),
        ("timetoke_rewards", gates.timetoke_rewards),
        ("witness_network", gates.witness_network),
    ])
}
