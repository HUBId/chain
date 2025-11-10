use std::f64;

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
fn replay_alert_probe_saturates_window_triggers_alerts() -> Result<()> {
    let alerts: AlertRuleFile = serde_yaml::from_str(include_str!(
        "../../ops/alerts/networking/replay_guard.yaml"
    ))
    .context("parse replay guard alert definitions")?;

    let drops_warning = find_rule(&alerts, "NetworkReplayGuardDropsWarning")?;
    let drops_critical = find_rule(&alerts, "NetworkReplayGuardDropsCritical")?;
    let window_warning = find_rule(&alerts, "NetworkReplayGuardWindowFillWarning")?;
    let window_critical = find_rule(&alerts, "NetworkReplayGuardWindowFillCritical")?;

    // Duplicate drop thresholds escalate from warning to critical.
    let warning_drops_threshold = trailing_threshold(&drops_warning.expr)?;
    let critical_drops_threshold = trailing_threshold(&drops_critical.expr)?;
    ensure!(
        critical_drops_threshold > warning_drops_threshold,
        "critical duplicate-drop threshold must exceed warning threshold"
    );

    assert!(drop_alert_fires(
        &drops_warning.expr,
        10.0,
        10.0 + warning_drops_threshold + 5.0
    )?);
    assert!(!drop_alert_fires(
        &drops_warning.expr,
        500.0,
        500.0 + warning_drops_threshold - 1.0
    )?);

    assert!(drop_alert_fires(
        &drops_critical.expr,
        20.0,
        20.0 + critical_drops_threshold + 15.0,
    )?);
    assert!(!drop_alert_fires(
        &drops_critical.expr,
        20.0,
        20.0 + critical_drops_threshold - 1.0,
    )?);

    // Window fill thresholds should progress similarly.
    let warning_window_threshold = trailing_threshold(&window_warning.expr)?;
    let critical_window_threshold = trailing_threshold(&window_critical.expr)?;
    ensure!(
        critical_window_threshold > warning_window_threshold,
        "critical window-fill threshold must exceed warning threshold"
    );

    assert!(window_alert_fires(
        &window_warning.expr,
        &[
            warning_window_threshold + 0.05,
            warning_window_threshold + 0.01
        ],
    )?);
    assert!(!window_alert_fires(
        &window_warning.expr,
        &[
            warning_window_threshold - 0.05,
            warning_window_threshold - 0.01
        ],
    )?);

    assert!(window_alert_fires(
        &window_critical.expr,
        &[
            critical_window_threshold + 0.02,
            critical_window_threshold + 0.01
        ],
    )?);
    assert!(!window_alert_fires(
        &window_critical.expr,
        &[
            critical_window_threshold - 0.02,
            critical_window_threshold - 0.01
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

fn drop_alert_fires(expr: &str, previous: f64, current: f64) -> Result<bool> {
    let threshold = trailing_threshold(expr)?;
    Ok((current - previous) > threshold)
}

fn window_alert_fires(expr: &str, samples: &[f64]) -> Result<bool> {
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
