use anyhow::{anyhow, ensure, Context, Result};
use serde::Deserialize;
use std::f64;

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
fn finality_alert_probe_detects_delayed_finality() -> Result<()> {
    let alerts: AlertRuleFile =
        serde_yaml::from_str(include_str!("../../ops/alerts/consensus/finality.yaml"))
            .context("parse consensus finality alert definitions")?;

    let lag_warning = find_rule(&alerts, "ConsensusFinalityLagWarning")?;
    let lag_critical = find_rule(&alerts, "ConsensusFinalityLagCritical")?;
    let height_warning = find_rule(&alerts, "ConsensusFinalizedHeightGapWarning")?;
    let height_critical = find_rule(&alerts, "ConsensusFinalizedHeightGapCritical")?;

    // Finality lag thresholds must escalate from warning to critical.
    let warning_lag_threshold = trailing_threshold(&lag_warning.expr)?;
    let critical_lag_threshold = trailing_threshold(&lag_critical.expr)?;
    ensure!(
        critical_lag_threshold > warning_lag_threshold,
        "critical finality lag threshold must exceed warning threshold",
    );

    assert!(max_alert_fires(
        &lag_warning.expr,
        &[warning_lag_threshold + 0.5, warning_lag_threshold + 2.0],
    )?);
    assert!(!max_alert_fires(
        &lag_warning.expr,
        &[warning_lag_threshold - 1.0, warning_lag_threshold - 0.25],
    )?);

    assert!(max_alert_fires(
        &lag_critical.expr,
        &[critical_lag_threshold + 1.0, critical_lag_threshold + 3.0],
    )?);
    assert!(!max_alert_fires(
        &lag_critical.expr,
        &[critical_lag_threshold - 1.0, critical_lag_threshold - 0.25],
    )?);

    // Finalized height gap thresholds must also escalate.
    let warning_height_threshold = trailing_threshold(&height_warning.expr)?;
    let critical_height_threshold = trailing_threshold(&height_critical.expr)?;
    ensure!(
        critical_height_threshold > warning_height_threshold,
        "critical finalized height gap threshold must exceed warning threshold",
    );

    assert!(max_alert_fires(
        &height_warning.expr,
        &[
            warning_height_threshold + 1.0,
            warning_height_threshold + 0.5
        ],
    )?);
    assert!(!max_alert_fires(
        &height_warning.expr,
        &[
            warning_height_threshold - 0.5,
            warning_height_threshold - 0.1
        ],
    )?);

    assert!(max_alert_fires(
        &height_critical.expr,
        &[
            critical_height_threshold + 1.0,
            critical_height_threshold + 0.5
        ],
    )?);
    assert!(!max_alert_fires(
        &height_critical.expr,
        &[
            critical_height_threshold - 0.5,
            critical_height_threshold - 0.1
        ],
    )?);

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

fn max_alert_fires(expr: &str, samples: &[f64]) -> Result<bool> {
    ensure!(
        expr.contains("max_over_time"),
        "expected max_over_time aggregator in expression: {expr}"
    );
    let threshold = trailing_threshold(expr)?;
    let max_value = samples
        .iter()
        .fold(f64::NEG_INFINITY, |acc, value| acc.max(*value));
    Ok(max_value > threshold)
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
