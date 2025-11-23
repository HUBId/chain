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
fn state_sync_stream_alert_probe_detects_lag_and_stall() -> Result<()> {
    let alerts: AlertRuleFile = serde_yaml::from_str(include_str!(
        "../../ops/alerts/storage/state_sync_stream.yaml"
    ))
    .context("parse state-sync stream alert definitions")?;

    let lag_warning = find_rule(&alerts, "StateSyncChunkStreamLagWarning")?;
    let lag_critical = find_rule(&alerts, "StateSyncChunkStreamLagCritical")?;
    let stalled = find_rule(&alerts, "StateSyncChunkStreamStalled")?;

    let warning_threshold = trailing_threshold(&lag_warning.expr, '>')?;
    let critical_threshold = trailing_threshold(&lag_critical.expr, '>')?;
    ensure!(
        critical_threshold > warning_threshold,
        "critical lag threshold must exceed warning threshold"
    );

    assert!(lag_alert_fires(&lag_warning.expr, 320.0, 2.0)?);
    assert!(!lag_alert_fires(&lag_warning.expr, 50.0, 2.0)?);

    assert!(lag_alert_fires(&lag_critical.expr, 300.0, 1.0)?);
    assert!(!lag_alert_fires(&lag_critical.expr, 100.0, 2.0)?);

    let stall_threshold = trailing_threshold(&stalled.expr, '<')?;
    assert!(stalled_alert_fires(&stalled.expr, 10.0, stall_threshold / 2.0)?);
    assert!(!stalled_alert_fires(&stalled.expr, 0.0, stall_threshold / 2.0)?);
    assert!(!stalled_alert_fires(&stalled.expr, 10.0, stall_threshold * 2.0)?);

    Ok(())
}

#[test]
fn state_sync_tamper_alert_tracks_metric() -> Result<()> {
    let alerts: AlertRuleFile = serde_yaml::from_str(include_str!(
        "../../docs/observability/alerts/root_integrity.yaml"
    ))
    .context("parse root-integrity alert definitions")?;

    let tamper = find_rule(&alerts, "StateSyncTamperDetected")?;
    assert!(tamper.expr.contains("rpp_node_pipeline_state_sync_tamper_total"));

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

fn lag_alert_fires(expr: &str, age_sum: f64, sample_count: f64) -> Result<bool> {
    if sample_count <= 0.0 {
        return Ok(false);
    }
    let threshold = trailing_threshold(expr, '>')?;
    Ok((age_sum / sample_count) > threshold)
}

fn stalled_alert_fires(expr: &str, chunks_sent_sum: f64, chunk_rate: f64) -> Result<bool> {
    let threshold = trailing_threshold(expr, '<')?;
    Ok(chunks_sent_sum > 0.0 && chunk_rate < threshold)
}

fn trailing_threshold(expr: &str, comparator: char) -> Result<f64> {
    let mut splits = expr.split(comparator);
    let _ = splits
        .next()
        .ok_or_else(|| anyhow!("missing comparator prefix: {expr}"))?;
    let tail = splits
        .next()
        .ok_or_else(|| anyhow!("expected comparator {comparator} in expression: {expr}"))?;
    let threshold = tail
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("missing threshold in expression: {expr}"))?
        .parse::<f64>()
        .context("parse threshold as floating point")?;
    Ok(threshold)
}
