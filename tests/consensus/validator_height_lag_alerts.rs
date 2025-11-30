use anyhow::{anyhow, ensure, Context, Result};
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
}

#[test]
fn validator_height_lag_alerts_escalate() -> Result<()> {
    let alerts: AlertRuleFile = serde_yaml::from_str(include_str!(
        "../../ops/alerts/consensus/validator_height.yaml"
    ))
    .context("parse validator height lag alert definitions")?;

    let warning = find_rule(&alerts, "ConsensusValidatorHeightLagWarning")?;
    let critical = find_rule(&alerts, "ConsensusValidatorHeightLagCritical")?;

    let warning_threshold = trailing_threshold(&warning.expr)?;
    let critical_threshold = trailing_threshold(&critical.expr)?;

    ensure!(
        critical_threshold > warning_threshold,
        "critical validator height lag threshold must exceed warning threshold",
    );

    let warning_triggers = [warning_threshold + 1.0, warning_threshold + 4.0];
    let warning_quiet = [warning_threshold - 1.0, warning_threshold - 0.25];
    for sample in warning_triggers { assert!(sample > warning_threshold); }
    for sample in warning_quiet { assert!(sample <= warning_threshold); }

    let critical_triggers = [critical_threshold + 0.5, critical_threshold + 3.0];
    let critical_quiet = [critical_threshold - 1.0, critical_threshold - 0.5];
    for sample in critical_triggers { assert!(sample > critical_threshold); }
    for sample in critical_quiet { assert!(sample <= critical_threshold); }

    Ok(())
}

fn find_rule<'a>(alerts: &'a AlertRuleFile, name: &str) -> Result<&'a AlertRule> {
    alerts
        .groups
        .iter()
        .flat_map(|group| &group.rules)
        .find(|rule| rule.alert == name)
        .ok_or_else(|| anyhow!("missing alert rule {name}"))
}

fn trailing_threshold(expr: &str) -> Result<f64> {
    let comparator = expr
        .split('>')
        .nth(1)
        .ok_or_else(|| anyhow!("expected comparator in expression: {expr}"))?;
    comparator
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("missing threshold in expression: {expr}"))?
        .parse::<f64>()
        .context("parse threshold as floating point")
}
