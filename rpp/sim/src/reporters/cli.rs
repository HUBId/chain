use std::fmt::Write;

use crate::metrics::SimulationSummary;

pub fn render_compact(summary: &SimulationSummary) -> String {
    let mut out = String::new();

    writeln!(&mut out, "Simulation Summary").unwrap();
    writeln!(&mut out, "===================").unwrap();
    writeln!(
        &mut out,
        "Publishes : {:>6}\nReceives  : {:>6}\nDuplicates: {:>6}",
        summary.total_publishes, summary.total_receives, summary.duplicates,
    )
    .unwrap();

    if let Some(propagation) = &summary.propagation {
        writeln!(&mut out, "Propagation p50: {:>8.2} ms", propagation.p50_ms).unwrap();
        writeln!(&mut out, "Propagation p95: {:>8.2} ms", propagation.p95_ms).unwrap();
    } else {
        writeln!(&mut out, "Propagation    : (no samples)").unwrap();
    }

    if let Some(proof) = &summary.proof_latency {
        writeln!(&mut out, "Proof p99      : {:>8.2} ms", proof.p99_ms).unwrap();
        writeln!(&mut out, "Proof max      : {:>8.2} ms", proof.max_ms).unwrap();
    }

    if let Some(reputation) = &summary.reputation_drift {
        writeln!(
            &mut out,
            "Validator μ     : {:>8.2}",
            reputation.mean_receives
        )
        .unwrap();
        writeln!(
            &mut out,
            "Validator σ     : {:>8.2}",
            reputation.std_dev_receives
        )
        .unwrap();
    }

    if let Some(bft) = &summary.bft_success {
        writeln!(
            &mut out,
            "BFT success  : {:>8.2}% ({}/{})",
            bft.success_rate * 100.0,
            bft.successes,
            bft.rounds
        )
        .unwrap();
    }

    if let Some(perf) = &summary.performance {
        writeln!(
            &mut out,
            "Throughput  : {:>8.2} rx/s",
            perf.receive_rate_per_sec
        )
        .unwrap();
        writeln!(&mut out, "Duplicates  : {:>8.3}", perf.duplicate_rate).unwrap();
    }

    if summary.mesh_changes.is_empty() {
        writeln!(&mut out, "Mesh changes  : none").unwrap();
    } else {
        writeln!(
            &mut out,
            "Mesh changes  : {} events",
            summary.mesh_changes.len()
        )
        .unwrap();
    }

    if summary.faults.is_empty() {
        writeln!(&mut out, "Fault events  : none").unwrap();
    } else {
        writeln!(&mut out, "Fault events  : {} entries", summary.faults.len()).unwrap();
    }

    if let Some(comparison) = &summary.comparison {
        writeln!(&mut out, "\nMulti-process Comparison").unwrap();
        writeln!(&mut out, "-----------------------").unwrap();
        writeln!(
            &mut out,
            "Δ Publishes : {:+5}",
            comparison.deltas.total_publishes
        )
        .unwrap();
        writeln!(
            &mut out,
            "Δ Receives  : {:+5}",
            comparison.deltas.total_receives
        )
        .unwrap();
        writeln!(
            &mut out,
            "Δ Duplicates: {:+5}",
            comparison.deltas.duplicates
        )
        .unwrap();
        match comparison.deltas.propagation_p50_ms {
            Some(delta) => {
                writeln!(&mut out, "Δ p50 (ms) : {:+8.2}", delta).unwrap();
            }
            None => {
                writeln!(&mut out, "Δ p50 (ms) :    n/a").unwrap();
            }
        }
        match comparison.deltas.propagation_p95_ms {
            Some(delta) => {
                writeln!(&mut out, "Δ p95 (ms) : {:+8.2}", delta).unwrap();
            }
            None => {
                writeln!(&mut out, "Δ p95 (ms) :    n/a").unwrap();
            }
        }
        if let Some(path) = &comparison.log_directory {
            writeln!(&mut out, "Logs        : {}", path).unwrap();
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{
        BftSuccessSummary, ComparisonReport, PerformanceKpi, ProofLatencySummary,
        PropagationPercentiles, ReputationDrift, RunDeltas, RunMetrics,
    };

    #[test]
    fn formats_summary() {
        let summary = SimulationSummary {
            total_publishes: 42,
            total_receives: 420,
            duplicates: 7,
            propagation: Some(PropagationPercentiles {
                p50_ms: 120.5,
                p95_ms: 240.75,
            }),
            mesh_changes: vec![],
            faults: vec![],
            reputation_drift: Some(ReputationDrift {
                mean_receives: 32.0,
                std_dev_receives: 4.5,
                max_receives: 40,
                min_receives: 25,
            }),
            tier_drift: None,
            bft_success: Some(BftSuccessSummary {
                rounds: 10,
                quorum: 14,
                successes: 9,
                success_rate: 0.9,
            }),
            proof_latency: Some(ProofLatencySummary {
                p50_ms: 80.0,
                p95_ms: 120.0,
                p99_ms: 150.0,
                max_ms: 210.0,
            }),
            performance: Some(PerformanceKpi {
                duration_secs: 60.0,
                publish_rate_per_sec: 0.7,
                receive_rate_per_sec: 7.0,
                duplicate_rate: 0.01,
                mean_proof_latency_ms: Some(90.0),
            }),
            node_performance: Vec::new(),
            comparison: None,
        };

        let rendered = render_compact(&summary);
        assert!(rendered.contains("Simulation Summary"));
        assert!(rendered.contains("Publishes"));
        assert!(rendered.contains("120.50"));
    }

    #[test]
    fn formats_comparison() {
        let base = PropagationPercentiles {
            p50_ms: 100.0,
            p95_ms: 200.0,
        };
        let comparison = ComparisonReport {
            in_process: RunMetrics {
                total_publishes: 10,
                total_receives: 20,
                duplicates: 1,
                propagation: Some(base.clone()),
            },
            multi_process: RunMetrics {
                total_publishes: 12,
                total_receives: 24,
                duplicates: 2,
                propagation: Some(PropagationPercentiles {
                    p50_ms: 110.0,
                    p95_ms: 210.0,
                }),
            },
            deltas: RunDeltas {
                total_publishes: 2,
                total_receives: 4,
                duplicates: 1,
                propagation_p50_ms: Some(10.0),
                propagation_p95_ms: Some(10.0),
            },
            log_directory: Some("/tmp/logs".into()),
            orchestrator_logs: vec![],
        };

        let summary = SimulationSummary {
            total_publishes: 12,
            total_receives: 24,
            duplicates: 2,
            propagation: Some(PropagationPercentiles {
                p50_ms: 110.0,
                p95_ms: 210.0,
            }),
            mesh_changes: vec![],
            faults: vec![],
            reputation_drift: None,
            tier_drift: None,
            bft_success: None,
            proof_latency: None,
            performance: None,
            node_performance: Vec::new(),
            comparison: Some(comparison),
        };

        let rendered = render_compact(&summary);
        assert!(rendered.contains("Multi-process Comparison"));
        assert!(rendered.contains("Δ Publishes"));
        assert!(rendered.contains("Logs"));
    }
}
