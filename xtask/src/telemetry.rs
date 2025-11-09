use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::registry::Registry;
use reqwest::blocking::Client as HttpClient;
use serde_json::{json, Value as JsonValue};

fn normalize_env(value: Option<String>) -> Option<String> {
    value
        .map(|raw| raw.trim().to_string())
        .filter(|trimmed| !trimmed.is_empty())
}

fn parse_headers(raw: Option<String>) -> Result<Vec<(String, String)>> {
    let Some(header_source) = normalize_env(raw) else {
        return Ok(Vec::new());
    };

    let mut headers = Vec::new();
    for entry in header_source.split(|c| c == ',' || c == '\n') {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (key, value) = trimmed
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid header entry '{trimmed}', expected key=value"))?;
        headers.push((key.trim().to_string(), value.trim().to_string()));
    }
    Ok(headers)
}

fn now_unix_nanos() -> Result<u128> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock appears to be before UNIX_EPOCH")?;
    Ok(duration.as_nanos())
}

#[derive(Default)]
struct MetricCounts {
    worm_checks: u64,
    worm_failures: u64,
    snapshot_runs: u64,
    snapshot_failures: u64,
    dirty: bool,
}

impl MetricCounts {
    fn record_worm_retention(&mut self, success: bool) {
        self.worm_checks = self.worm_checks.saturating_add(1);
        if !success {
            self.worm_failures = self.worm_failures.saturating_add(1);
        }
        self.dirty = true;
    }

    fn record_snapshot_chaos(&mut self, success: bool) {
        self.snapshot_runs = self.snapshot_runs.saturating_add(1);
        if !success {
            self.snapshot_failures = self.snapshot_failures.saturating_add(1);
        }
        self.dirty = true;
    }

    fn reset_dirty(&mut self) {
        self.worm_checks = 0;
        self.worm_failures = 0;
        self.snapshot_runs = 0;
        self.snapshot_failures = 0;
        self.dirty = false;
    }
}

pub struct MetricsReporter {
    prom: Option<PrometheusReporter>,
    otlp: Option<OtlpReporter>,
    counts: MetricCounts,
}

impl MetricsReporter {
    pub fn from_env(scope: &str, default_service: &str) -> Result<Self> {
        let prom = PrometheusReporter::from_env()?;
        let otlp = OtlpReporter::from_env(scope, default_service)?;
        Ok(Self {
            prom,
            otlp,
            counts: MetricCounts::default(),
        })
    }

    pub fn record_worm_retention(&mut self, success: bool) {
        self.counts.record_worm_retention(success);
    }

    pub fn record_snapshot_chaos(&mut self, success: bool) {
        self.counts.record_snapshot_chaos(success);
    }

    pub fn flush(&mut self) {
        if !self.counts.dirty {
            return;
        }
        if let Some(prom) = &mut self.prom {
            if let Err(error) = prom.flush(&self.counts) {
                eprintln!(
                    "warning: failed to write Prometheus metrics to {}: {error}",
                    prom.output_path.display()
                );
            }
        }
        if let Some(otlp) = &mut self.otlp {
            if let Err(error) = otlp.flush(&self.counts) {
                eprintln!(
                    "warning: failed to export OTLP metrics to {}: {error}",
                    otlp.endpoint
                );
            }
        }
        self.counts.reset_dirty();
    }
}

struct PrometheusReporter {
    registry: Registry,
    worm_checks: Counter<u64>,
    worm_failures: Counter<u64>,
    snapshot_runs: Counter<u64>,
    snapshot_failures: Counter<u64>,
    output_path: PathBuf,
}

impl PrometheusReporter {
    fn from_env() -> Result<Option<Self>> {
        let Some(path) = normalize_env(env::var("OBSERVABILITY_METRICS_PROM_PATH").ok()) else {
            return Ok(None);
        };
        let output_path = PathBuf::from(path);

        let mut registry = Registry::default();
        let worm_checks = Counter::<u64>::default();
        registry.register(
            "worm_retention_checks_total",
            "Total number of worm-retention verification runs executed.",
            worm_checks.clone(),
        );
        let worm_failures = Counter::<u64>::default();
        registry.register(
            "worm_retention_failures_total",
            "Count of worm-retention verification runs that reported failures.",
            worm_failures.clone(),
        );
        let snapshot_runs = Counter::<u64>::default();
        registry.register(
            "snapshot_chaos_runs_total",
            "Total snapshot chaos drill executions.",
            snapshot_runs.clone(),
        );
        let snapshot_failures = Counter::<u64>::default();
        registry.register(
            "snapshot_chaos_failures_total",
            "Snapshot chaos drill executions that breached configured thresholds.",
            snapshot_failures.clone(),
        );

        Ok(Some(Self {
            registry,
            worm_checks,
            worm_failures,
            snapshot_runs,
            snapshot_failures,
            output_path,
        }))
    }

    fn flush(&mut self, counts: &MetricCounts) -> Result<()> {
        if let Some(parent) = self.output_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create metrics directory {}", parent.display()))?;
            }
        }

        self.worm_checks.inc_by(counts.worm_checks);
        self.worm_failures.inc_by(counts.worm_failures);
        self.snapshot_runs.inc_by(counts.snapshot_runs);
        self.snapshot_failures.inc_by(counts.snapshot_failures);

        let mut buffer = Vec::new();
        encode(&mut buffer, &self.registry).context("encode Prometheus metrics")?;
        let mut file = File::create(&self.output_path).with_context(|| {
            format!(
                "create Prometheus metrics file {}",
                self.output_path.display()
            )
        })?;
        file.write_all(&buffer).with_context(|| {
            format!(
                "write Prometheus metrics file {}",
                self.output_path.display()
            )
        })?;

        Ok(())
    }
}

struct OtlpReporter {
    client: HttpClient,
    endpoint: String,
    auth_header: Option<String>,
    extra_headers: Vec<(String, String)>,
    service_name: String,
    service_instance: Option<String>,
    scope_name: String,
    job_label: Option<String>,
    start_time_ns: u128,
    timeout_ms: u64,
}

impl OtlpReporter {
    fn from_env(scope: &str, default_service: &str) -> Result<Option<Self>> {
        let Some(endpoint) = normalize_env(env::var("OBSERVABILITY_METRICS_OTLP_ENDPOINT").ok())
        else {
            return Ok(None);
        };
        let auth_header =
            normalize_env(env::var("OBSERVABILITY_METRICS_AUTH_TOKEN").ok()).map(|token| {
                if token.to_ascii_lowercase().starts_with("bearer ") {
                    token
                } else {
                    format!("Bearer {token}")
                }
            });
        let extra_headers = parse_headers(env::var("OBSERVABILITY_METRICS_HEADERS").ok())?;

        let timeout_ms = normalize_env(env::var("OBSERVABILITY_METRICS_TIMEOUT_MS").ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(10_000);

        let client = HttpClient::builder()
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .build()
            .context("build OTLP HTTP client")?;

        let service_name = normalize_env(env::var("OBSERVABILITY_METRICS_SERVICE_NAME").ok())
            .unwrap_or_else(|| default_service.to_string());
        let service_instance =
            normalize_env(env::var("OBSERVABILITY_METRICS_SERVICE_INSTANCE").ok());
        let scope_name = normalize_env(env::var("OBSERVABILITY_METRICS_SCOPE").ok())
            .unwrap_or_else(|| scope.to_string());
        let job_label = normalize_env(env::var("OBSERVABILITY_METRICS_JOB").ok());

        Ok(Some(Self {
            client,
            endpoint,
            auth_header,
            extra_headers,
            service_name,
            service_instance,
            scope_name,
            job_label,
            start_time_ns: now_unix_nanos()?,
            timeout_ms,
        }))
    }

    fn flush(&mut self, counts: &MetricCounts) -> Result<()> {
        if !counts.dirty {
            return Ok(());
        }

        let current_time = now_unix_nanos()?;

        let mut resource_attributes = vec![json!({
            "key": "service.name",
            "value": { "stringValue": self.service_name }
        })];
        if let Some(instance) = &self.service_instance {
            resource_attributes.push(json!({
                "key": "service.instance.id",
                "value": { "stringValue": instance }
            }));
        }
        if let Some(job) = &self.job_label {
            resource_attributes.push(json!({
                "key": "job",
                "value": { "stringValue": job }
            }));
        }

        let mut metrics = Vec::new();
        metrics.push(Self::counter_metric(
            "worm_retention_checks_total",
            "Total number of worm-retention verification runs executed.",
            counts.worm_checks,
            self.start_time_ns,
            current_time,
        ));
        metrics.push(Self::counter_metric(
            "worm_retention_failures_total",
            "Count of worm-retention verification runs that reported failures.",
            counts.worm_failures,
            self.start_time_ns,
            current_time,
        ));
        metrics.push(Self::counter_metric(
            "snapshot_chaos_runs_total",
            "Total snapshot chaos drill executions.",
            counts.snapshot_runs,
            self.start_time_ns,
            current_time,
        ));
        metrics.push(Self::counter_metric(
            "snapshot_chaos_failures_total",
            "Snapshot chaos drill executions that breached configured thresholds.",
            counts.snapshot_failures,
            self.start_time_ns,
            current_time,
        ));

        let payload = json!({
            "resourceMetrics": [
                {
                    "resource": { "attributes": resource_attributes },
                    "scopeMetrics": [
                        {
                            "scope": { "name": self.scope_name.clone() },
                            "metrics": metrics
                        }
                    ]
                }
            ]
        });

        let mut request = self.client.post(&self.endpoint);
        request = request.json(&payload);
        if let Some(header) = &self.auth_header {
            request = request.header("Authorization", header);
        }
        for (key, value) in &self.extra_headers {
            request = request.header(key, value);
        }

        request
            .send()
            .and_then(|response| response.error_for_status())
            .with_context(|| {
                let mut context = format!("export OTLP metrics to {}", self.endpoint);
                if self.timeout_ms > 0 {
                    context.push_str(&format!(" (timeout {}ms)", self.timeout_ms));
                }
                context
            })?;

        Ok(())
    }

    fn counter_metric(
        name: &str,
        description: &str,
        value: u64,
        start_time: u128,
        current_time: u128,
    ) -> JsonValue {
        json!({
            "name": name,
            "description": description,
            "sum": {
                "aggregationTemporality": "AGGREGATION_TEMPORALITY_CUMULATIVE",
                "isMonotonic": true,
                "dataPoints": [
                    {
                        "startTimeUnixNano": start_time.to_string(),
                        "timeUnixNano": current_time.to_string(),
                        "asInt": value.to_string(),
                        "attributes": []
                    }
                ]
            }
        })
    }
}
