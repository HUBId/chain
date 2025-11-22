use anyhow::{anyhow, ensure, Context, Result};
use serde::Deserialize;
use std::{collections::HashSet, env, f64, fs, path::PathBuf};
use std::{fmt::Write as FmtWrite, thread};

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

const ARTIFACT_ENV: &str = "FINALITY_ALERT_ARTIFACT_DIR";
const DEFAULT_ARTIFACT_DIR: &str = "target/artifacts/finality-alert-probe";

#[test]
fn finality_alert_probe_detects_delayed_finality() -> Result<()> {
    let mut artifacts = FinalityProbeArtifacts::new();
    let result = run_finality_alert_probe(&mut artifacts);

    if result.is_err() {
        artifacts
            .persist()
            .context("write finality alert probe artifacts")?;
    }

    result
}

fn run_finality_alert_probe(artifacts: &mut FinalityProbeArtifacts) -> Result<()> {
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

    let lag_warning_triggers = [warning_lag_threshold + 0.5, warning_lag_threshold + 2.0];
    let lag_warning_quiet = [warning_lag_threshold - 1.0, warning_lag_threshold - 0.25];
    artifacts.record_alert(
        lag_warning,
        warning_lag_threshold,
        &lag_warning_triggers,
        &lag_warning_quiet,
    )?;

    assert!(max_alert_fires(&lag_warning.expr, &lag_warning_triggers)?);
    assert!(!max_alert_fires(&lag_warning.expr, &lag_warning_quiet)?);

    let lag_critical_triggers = [critical_lag_threshold + 1.0, critical_lag_threshold + 3.0];
    let lag_critical_quiet = [critical_lag_threshold - 1.0, critical_lag_threshold - 0.25];
    artifacts.record_alert(
        lag_critical,
        critical_lag_threshold,
        &lag_critical_triggers,
        &lag_critical_quiet,
    )?;

    assert!(max_alert_fires(&lag_critical.expr, &lag_critical_triggers)?);
    assert!(!max_alert_fires(&lag_critical.expr, &lag_critical_quiet)?);

    // Finalized height gap thresholds must also escalate.
    let warning_height_threshold = trailing_threshold(&height_warning.expr)?;
    let critical_height_threshold = trailing_threshold(&height_critical.expr)?;
    ensure!(
        critical_height_threshold > warning_height_threshold,
        "critical finalized height gap threshold must exceed warning threshold",
    );

    let height_warning_triggers = [
        warning_height_threshold + 1.0,
        warning_height_threshold + 0.5,
    ];
    let height_warning_quiet = [
        warning_height_threshold - 0.5,
        warning_height_threshold - 0.1,
    ];
    artifacts.record_alert(
        height_warning,
        warning_height_threshold,
        &height_warning_triggers,
        &height_warning_quiet,
    )?;

    assert!(max_alert_fires(
        &height_warning.expr,
        &height_warning_triggers,
    )?);
    assert!(!max_alert_fires(
        &height_warning.expr,
        &height_warning_quiet,
    )?);

    let height_critical_triggers = [
        critical_height_threshold + 1.0,
        critical_height_threshold + 0.5,
    ];
    let height_critical_quiet = [
        critical_height_threshold - 0.5,
        critical_height_threshold - 0.1,
    ];
    artifacts.record_alert(
        height_critical,
        critical_height_threshold,
        &height_critical_triggers,
        &height_critical_quiet,
    )?;

    assert!(max_alert_fires(
        &height_critical.expr,
        &height_critical_triggers,
    )?);
    assert!(!max_alert_fires(
        &height_critical.expr,
        &height_critical_quiet,
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

fn metric_name_from_expr(expr: &str) -> Result<String> {
    let (_, tail) = expr
        .split_once("max_over_time(")
        .ok_or_else(|| anyhow!("expected max_over_time aggregator in expression: {expr}"))?;
    let metric = tail
        .split_once('[')
        .map(|(metric, _)| metric)
        .ok_or_else(|| anyhow!("unable to parse metric name from expression: {expr}"))?
        .trim();
    ensure!(
        !metric.is_empty(),
        "metric name missing in expression: {expr}"
    );
    Ok(metric.to_string())
}

#[derive(Clone, Debug)]
struct AlertSnapshot {
    alert: String,
    expr: String,
    metric: String,
    threshold: f64,
    trigger_samples: Vec<f64>,
    quiet_samples: Vec<f64>,
}

#[derive(Default)]
struct FinalityProbeArtifacts {
    dir: PathBuf,
    alerts: Vec<AlertSnapshot>,
    armed: bool,
}

impl FinalityProbeArtifacts {
    fn new() -> Self {
        let base = env::var(ARTIFACT_ENV)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DEFAULT_ARTIFACT_DIR)
            });

        Self {
            dir: base,
            alerts: Vec::new(),
            armed: true,
        }
    }

    fn record_alert(
        &mut self,
        alert: &AlertRule,
        threshold: f64,
        trigger_samples: &[f64],
        quiet_samples: &[f64],
    ) -> Result<()> {
        let metric = metric_name_from_expr(&alert.expr)?;
        self.alerts.push(AlertSnapshot {
            alert: alert.alert.clone(),
            expr: alert.expr.clone(),
            metric,
            threshold,
            trigger_samples: trigger_samples.to_vec(),
            quiet_samples: quiet_samples.to_vec(),
        });
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        if self.alerts.is_empty() {
            return Ok(());
        }

        fs::create_dir_all(&self.dir).context("create finality probe artifact directory")?;

        let mut log = String::new();
        for alert in &self.alerts {
            writeln!(log, "Alert: {}", alert.alert)?;
            writeln!(log, "Expression: {}", alert.expr)?;
            writeln!(log, "Metric: {}", alert.metric)?;
            writeln!(log, "Threshold: {:.3}", alert.threshold)?;
            writeln!(log, "Trigger samples: {:?}", alert.trigger_samples)?;
            writeln!(log, "Quiet samples: {:?}\n", alert.quiet_samples)?;
        }

        fs::write(self.dir.join("probe.log"), log).context("write finality probe log artifact")?;

        let mut metrics = String::new();
        let mut typed_metrics = HashSet::new();

        for alert in &self.alerts {
            if typed_metrics.insert(alert.metric.clone()) {
                writeln!(metrics, "# TYPE {} gauge", alert.metric)?;
            }

            for (index, value) in alert.trigger_samples.iter().enumerate() {
                writeln!(
                    metrics,
                    "{}{{alert=\"{}\",scenario=\"triggers\",sample=\"{}\"}} {}",
                    alert.metric, alert.alert, index, value,
                )?;
            }

            for (index, value) in alert.quiet_samples.iter().enumerate() {
                writeln!(
                    metrics,
                    "{}{{alert=\"{}\",scenario=\"quiet\",sample=\"{}\"}} {}",
                    alert.metric, alert.alert, index, value,
                )?;
            }
        }

        fs::write(self.dir.join("metrics.prom"), metrics)
            .context("write finality probe metrics artifact")?;

        Ok(())
    }
}

impl Drop for FinalityProbeArtifacts {
    fn drop(&mut self) {
        if self.armed && thread::panicking() {
            let _ = self.persist();
        }
    }
}
