use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use super::collector::{FaultRecord, MeshChangeRecord, SlowPeerRecord};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PropagationPercentiles {
    pub p50_ms: f64,
    pub p95_ms: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PropagationProbeKind {
    Block,
    Transaction,
}

impl PropagationProbeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PropagationProbeKind::Block => "block",
            PropagationProbeKind::Transaction => "transaction",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PropagationByPeerClass {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted: Option<PropagationPercentiles>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untrusted: Option<PropagationPercentiles>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PropagationProbes {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block: Option<PropagationPercentiles>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<PropagationPercentiles>,
    #[serde(default)]
    pub backend: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ReplayGuardMetrics {
    pub drops_by_class: ReplayGuardDrops,
    pub window_fill_ratio_by_class: ReplayWindowFill,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ReplayGuardDrops {
    pub trusted: usize,
    pub untrusted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ReplayWindowFill {
    pub trusted: f64,
    pub untrusted: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SimulationSummary {
    pub total_publishes: usize,
    pub total_receives: usize,
    pub duplicates: usize,
    #[serde(default)]
    pub chunk_retries: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_guard: Option<ReplayGuardMetrics>,
    pub propagation: Option<PropagationPercentiles>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagation_by_peer_class: Option<PropagationByPeerClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub propagation_probes: Option<PropagationProbes>,
    pub mesh_changes: Vec<MeshChangeRecord>,
    pub faults: Vec<FaultRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<BandwidthMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gossip_backpressure: Option<GossipBackpressureMetrics>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_traffic: Vec<PeerTrafficRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub slow_peer_records: Vec<SlowPeerRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_usage: Option<ResourceUsageMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison: Option<ComparisonReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunMetrics {
    pub total_publishes: usize,
    pub total_receives: usize,
    pub duplicates: usize,
    pub propagation: Option<PropagationPercentiles>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RecoveryMetrics {
    #[serde(default)]
    pub resume_latencies_ms: Vec<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_resume_latency_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_resume_latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct BandwidthMetrics {
    pub throttled_peers: usize,
    pub slow_peer_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GossipBackpressureMetrics {
    pub events: usize,
    pub unique_peers: usize,
    pub queue_full_messages: usize,
    pub publish_failures: usize,
    pub forward_failures: usize,
    pub timeout_failures: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PeerTrafficRecord {
    pub peer_id: String,
    pub peer_class: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ResourceUsageMetrics {
    /// Sum of user and system CPU time in seconds.
    pub cpu_time_secs: f64,
    /// Wall-clock time spanned by the simulation in seconds.
    pub wall_time_secs: f64,
    /// Average CPU consumption expressed as a percentage of a single core.
    pub avg_cpu_percent: f64,
    /// Peak resident set size observed for the orchestrator process.
    pub max_rss_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunDeltas {
    pub total_publishes: isize,
    pub total_receives: isize,
    pub duplicates: isize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub propagation_p50_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub propagation_p95_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ComparisonReport {
    pub in_process: RunMetrics,
    pub multi_process: RunMetrics,
    pub deltas: RunDeltas,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_directory: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orchestrator_logs: Vec<String>,
}

impl RunMetrics {
    pub fn from_summary(summary: &SimulationSummary) -> Self {
        Self {
            total_publishes: summary.total_publishes,
            total_receives: summary.total_receives,
            duplicates: summary.duplicates,
            propagation: summary.propagation.clone(),
        }
    }
}

pub fn propagation_by_peer_class(
    latencies: &HashMap<String, Vec<f64>>,
) -> Option<PropagationByPeerClass> {
    if latencies.is_empty() {
        return None;
    }

    let trusted = latencies
        .get("trusted")
        .filter(|values| !values.is_empty())
        .map(|values| calculate_percentiles(values));
    let untrusted = latencies
        .get("untrusted")
        .filter(|values| !values.is_empty())
        .map(|values| calculate_percentiles(values));

    if trusted.is_none() && untrusted.is_none() {
        None
    } else {
        Some(PropagationByPeerClass { trusted, untrusted })
    }
}

pub fn propagation_by_probe_kind(
    latencies: &HashMap<PropagationProbeKind, Vec<f64>>,
    backend: Option<String>,
) -> Option<PropagationProbes> {
    if latencies.is_empty() {
        return None;
    }

    let block = latencies
        .get(&PropagationProbeKind::Block)
        .filter(|values| !values.is_empty())
        .map(|values| calculate_percentiles(values));
    let transaction = latencies
        .get(&PropagationProbeKind::Transaction)
        .filter(|values| !values.is_empty())
        .map(|values| calculate_percentiles(values));

    if block.is_none() && transaction.is_none() {
        None
    } else {
        Some(PropagationProbes {
            block,
            transaction,
            backend,
        })
    }
}

impl RunDeltas {
    fn between(base: &RunMetrics, multi: &RunMetrics) -> Self {
        let propagation_p50_ms = match (&base.propagation, &multi.propagation) {
            (Some(left), Some(right)) => Some(right.p50_ms - left.p50_ms),
            _ => None,
        };
        let propagation_p95_ms = match (&base.propagation, &multi.propagation) {
            (Some(left), Some(right)) => Some(right.p95_ms - left.p95_ms),
            _ => None,
        };
        Self {
            total_publishes: multi.total_publishes as isize - base.total_publishes as isize,
            total_receives: multi.total_receives as isize - base.total_receives as isize,
            duplicates: multi.duplicates as isize - base.duplicates as isize,
            propagation_p50_ms,
            propagation_p95_ms,
        }
    }
}

impl ComparisonReport {
    pub fn from_runs(
        baseline: &SimulationSummary,
        multi: &SimulationSummary,
        log_directory: Option<PathBuf>,
        orchestrator_logs: Vec<String>,
    ) -> Self {
        let in_process = RunMetrics::from_summary(baseline);
        let multi_process = RunMetrics::from_summary(multi);
        let deltas = RunDeltas::between(&in_process, &multi_process);
        Self {
            in_process,
            multi_process,
            deltas,
            log_directory: log_directory.map(|p| p.display().to_string()),
            orchestrator_logs,
        }
    }
}

pub fn calculate_percentiles(samples: &[f64]) -> Option<PropagationPercentiles> {
    if samples.is_empty() {
        return None;
    }

    let p50 = percentile(samples, 0.50);
    let p95 = percentile(samples, 0.95);

    Some(PropagationPercentiles {
        p50_ms: p50,
        p95_ms: p95,
    })
}

fn percentile(samples: &[f64], quantile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }
    let max_index = samples.len() - 1;
    let position = quantile * max_index as f64;
    let lower = position.floor() as usize;
    let upper = position.ceil() as usize;
    if lower == upper {
        samples[lower]
    } else {
        let weight = position - lower as f64;
        samples[lower] * (1.0 - weight) + samples[upper] * weight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_interpolate() {
        let samples = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        let summary = calculate_percentiles(&samples).expect("percentiles");
        assert!((summary.p50_ms - 30.0).abs() < f64::EPSILON);
        assert!((summary.p95_ms - 48.0).abs() < 1.0);
    }

    #[test]
    fn comparison_report_builds_deltas() {
        let base = SimulationSummary {
            total_publishes: 10,
            total_receives: 20,
            duplicates: 2,
            chunk_retries: 0,
            replay_guard: None,
            propagation: Some(PropagationPercentiles {
                p50_ms: 100.0,
                p95_ms: 200.0,
            }),
            propagation_by_peer_class: None,
            propagation_probes: None,
            mesh_changes: vec![],
            faults: vec![],
            recovery: None,
            bandwidth: None,
            gossip_backpressure: None,
            peer_traffic: Vec::new(),
            slow_peer_records: Vec::new(),
            resource_usage: None,
            backend: None,
            comparison: None,
        };
        let multi = SimulationSummary {
            total_publishes: 12,
            total_receives: 25,
            duplicates: 3,
            chunk_retries: 1,
            replay_guard: None,
            propagation: Some(PropagationPercentiles {
                p50_ms: 110.0,
                p95_ms: 205.0,
            }),
            propagation_by_peer_class: None,
            propagation_probes: None,
            mesh_changes: vec![],
            faults: vec![],
            recovery: None,
            bandwidth: None,
            gossip_backpressure: None,
            peer_traffic: Vec::new(),
            slow_peer_records: Vec::new(),
            resource_usage: None,
            backend: None,
            comparison: None,
        };

        let report = ComparisonReport::from_runs(
            &base,
            &multi,
            Some(PathBuf::from("/tmp/logs")),
            vec!["stdout".into()],
        );

        assert_eq!(report.deltas.total_publishes, 2);
        assert_eq!(report.deltas.total_receives, 5);
        assert_eq!(report.deltas.duplicates, 1);
        assert_eq!(report.deltas.propagation_p50_ms, Some(10.0));
        assert_eq!(report.log_directory.as_deref(), Some("/tmp/logs"));
        assert_eq!(report.orchestrator_logs.len(), 1);
    }
}
