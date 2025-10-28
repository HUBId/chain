use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::scenario::NodeRole;

use super::collector::{FaultRecord, MeshChangeRecord};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PropagationPercentiles {
    pub p50_ms: f64,
    pub p95_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SimulationSummary {
    pub total_publishes: usize,
    pub total_receives: usize,
    pub duplicates: usize,
    pub propagation: Option<PropagationPercentiles>,
    pub mesh_changes: Vec<MeshChangeRecord>,
    pub faults: Vec<FaultRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reputation_drift: Option<ReputationDrift>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_drift: Option<TierDrift>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bft_success: Option<BftSuccessSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_latency: Option<ProofLatencySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub performance: Option<PerformanceKpi>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_performance: Vec<NodePerformance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison: Option<ComparisonReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodePerformance {
    pub peer_id: String,
    pub role: NodeRole,
    pub publishes: usize,
    pub receives: usize,
    pub duplicates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReputationDrift {
    pub mean_receives: f64,
    pub std_dev_receives: f64,
    pub max_receives: usize,
    pub min_receives: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TierBucket {
    pub tier: String,
    pub count: usize,
    pub average_receives: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TierDrift {
    pub expected_per_tier: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub buckets: Vec<TierBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BftSuccessSummary {
    pub rounds: usize,
    pub quorum: usize,
    pub successes: usize,
    pub success_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProofLatencySummary {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerformanceKpi {
    pub duration_secs: f64,
    pub publish_rate_per_sec: f64,
    pub receive_rate_per_sec: f64,
    pub duplicate_rate: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_proof_latency_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunMetrics {
    pub total_publishes: usize,
    pub total_receives: usize,
    pub duplicates: usize,
    pub propagation: Option<PropagationPercentiles>,
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

pub(crate) fn percentile(samples: &[f64], quantile: f64) -> f64 {
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
            propagation: Some(PropagationPercentiles {
                p50_ms: 100.0,
                p95_ms: 200.0,
            }),
            mesh_changes: vec![],
            faults: vec![],
            reputation_drift: None,
            tier_drift: None,
            bft_success: None,
            proof_latency: None,
            performance: None,
            node_performance: Vec::new(),
            comparison: None,
        };
        let multi = SimulationSummary {
            total_publishes: 12,
            total_receives: 25,
            duplicates: 3,
            propagation: Some(PropagationPercentiles {
                p50_ms: 110.0,
                p95_ms: 205.0,
            }),
            mesh_changes: vec![],
            faults: vec![],
            reputation_drift: None,
            tier_drift: None,
            bft_success: None,
            proof_latency: None,
            performance: None,
            node_performance: Vec::new(),
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
