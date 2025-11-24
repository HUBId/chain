use std::collections::HashMap;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AlertRuleFile {
    groups: Vec<AlertGroup>,
}

#[derive(Debug, Deserialize)]
struct AlertGroup {
    rules: Vec<AlertRule>,
}

#[derive(Debug, Deserialize)]
struct AlertRule {
    alert: String,
    expr: String,
    #[serde(default)]
    labels: HashMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
struct AlertPayload {
    alert: String,
    backend: String,
    threshold: f64,
    observed: f64,
}

#[test]
fn zk_alerts_are_backend_scoped() -> Result<()> {
    let rpp_alerts: AlertRuleFile =
        serde_yaml::from_str(include_str!("../ops/alerts/zk/rpp_stark.yaml"))
            .context("parse RPP-STARK alert definitions")?;
    let stwo_alerts: AlertRuleFile =
        serde_yaml::from_str(include_str!("../ops/alerts/zk/stwo.yaml"))
            .context("parse STWO prover alert definitions")?;

    let rpp_samples = HashMap::from([
        ("ZkRppStarkVerificationFailuresWarning".to_string(), 2.0),
        ("ZkRppStarkVerificationFailuresCritical".to_string(), 5.0),
        ("ZkRppStarkVerifierLatencyCritical".to_string(), 3.7),
    ]);
    let stwo_samples = HashMap::from([
        ("ZkStwoProverFailuresWarning".to_string(), 1.0),
        ("ZkStwoProverFailuresCritical".to_string(), 5.0),
        ("ZkStwoProverQueueBacklogWarning".to_string(), 3.0),
        ("ZkStwoProverLatencyCritical".to_string(), 190_000.0),
        ("ZkStwoProverFailureRateCritical".to_string(), 0.25),
    ]);

    let rpp_payloads = simulate_backend_alerts(&rpp_alerts, "rpp-stark", &rpp_samples)?;
    assert_eq!(
        rpp_payloads.len(),
        3,
        "all RPP-STARK alerts should fire for matching backend"
    );
    assert!(
        rpp_payloads
            .iter()
            .all(|payload| payload.backend == "rpp-stark"),
        "RPP-STARK alerts must carry the backend identifier"
    );

    let stwo_payloads_from_rpp = simulate_backend_alerts(&rpp_alerts, "stwo", &rpp_samples)?;
    assert!(
        stwo_payloads_from_rpp.is_empty(),
        "STWO samples must not trigger RPP-STARK verifier alerts"
    );

    let stwo_payloads = simulate_backend_alerts(&stwo_alerts, "stwo", &stwo_samples)?;
    assert_eq!(
        stwo_payloads.len(),
        5,
        "all STWO prover alerts should fire for matching backend"
    );
    assert!(
        stwo_payloads
            .iter()
            .all(|payload| payload.backend == "stwo"),
        "STWO alerts must carry the backend identifier"
    );

    let rpp_payloads_from_stwo = simulate_backend_alerts(&stwo_alerts, "rpp-stark", &stwo_samples)?;
    assert!(
        rpp_payloads_from_stwo.is_empty(),
        "RPP-STARK backend should not receive STWO prover alerts"
    );

    Ok(())
}

fn simulate_backend_alerts(
    alerts: &AlertRuleFile,
    backend: &str,
    samples: &HashMap<String, f64>,
) -> Result<Vec<AlertPayload>> {
    let mut payloads = Vec::new();

    for rule in alerts.groups.iter().flat_map(|group| &group.rules) {
        let target_backend = extract_backend(&rule)?;
        if target_backend != backend {
            continue;
        }

        let observed = *samples.get(&rule.alert).unwrap_or(&0.0);
        let threshold = extract_threshold(&rule.expr)?;
        if observed > threshold {
            payloads.push(AlertPayload {
                alert: rule.alert.clone(),
                backend: target_backend.to_string(),
                threshold,
                observed,
            });
        }
    }

    Ok(payloads)
}

fn extract_threshold(expr: &str) -> Result<f64> {
    let comparator = expr
        .rsplit('>')
        .next()
        .ok_or_else(|| anyhow!("expression missing comparator: {expr}"))?;
    comparator
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("missing threshold in expression: {expr}"))?
        .parse::<f64>()
        .context("parse expression threshold")
}

fn extract_backend(rule: &AlertRule) -> Result<String> {
    if let Some(backend) = rule.labels.get("backend") {
        return Ok(backend.clone());
    }

    for key in ["backend", "proof_backend"] {
        if let Some(start) = rule.expr.find(&format!("{key}=\"")) {
            let tail = &rule.expr[start + key.len() + 2..];
            if let Some(end) = tail.find('"') {
                return Ok(tail[..end].to_string());
            }
        }
    }

    Err(anyhow!(
        "alert {} is missing an explicit backend label or selector",
        rule.alert
    ))
}
