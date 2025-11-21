use std::fmt::Write;

use crate::metrics::{RecoveryMetrics, SimulationSummary};

pub fn render_compact(summary: &SimulationSummary) -> String {
    let mut out = String::new();

    writeln!(&mut out, "Simulation Summary").unwrap();
    writeln!(&mut out, "===================").unwrap();
    writeln!(
        &mut out,
        "Publishes : {:>6}\nReceives  : {:>6}\nDuplicates: {:>6}\nRetries   : {:>6}",
        summary.total_publishes, summary.total_receives, summary.duplicates, summary.chunk_retries,
    )
    .unwrap();

    if let Some(propagation) = &summary.propagation {
        writeln!(&mut out, "Propagation p50: {:>8.2} ms", propagation.p50_ms).unwrap();
        writeln!(&mut out, "Propagation p95: {:>8.2} ms", propagation.p95_ms).unwrap();
    } else {
        writeln!(&mut out, "Propagation    : (no samples)").unwrap();
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

    if let Some(recovery) = &summary.recovery {
        writeln!(
            &mut out,
            "Recovery      : {} resume events",
            recovery.resume_latencies_ms.len()
        )
        .unwrap();
        if let Some(max) = recovery.max_resume_latency_ms {
            writeln!(&mut out, "  max resume  : {:>8.2} ms", max).unwrap();
        }
        if let Some(mean) = recovery.mean_resume_latency_ms {
            writeln!(&mut out, "  mean resume : {:>8.2} ms", mean).unwrap();
        }
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
    use crate::metrics::{ComparisonReport, PropagationPercentiles, RunDeltas, RunMetrics};

    #[test]
    fn formats_summary() {
        let summary = SimulationSummary {
            total_publishes: 42,
            total_receives: 420,
            duplicates: 7,
            chunk_retries: 3,
            propagation: Some(PropagationPercentiles {
                p50_ms: 120.5,
                p95_ms: 240.75,
            }),
            mesh_changes: vec![],
            faults: vec![],
            recovery: Some(RecoveryMetrics {
                resume_latencies_ms: vec![1200.0, 1400.0],
                max_resume_latency_ms: Some(1400.0),
                mean_resume_latency_ms: Some(1300.0),
            }),
            bandwidth: None,
            gossip_backpressure: None,
            slow_peer_records: Vec::new(),
            resource_usage: None,
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
            chunk_retries: 1,
            propagation: Some(PropagationPercentiles {
                p50_ms: 110.0,
                p95_ms: 210.0,
            }),
            mesh_changes: vec![],
            faults: vec![],
            recovery: None,
            bandwidth: None,
            gossip_backpressure: None,
            slow_peer_records: Vec::new(),
            resource_usage: None,
            comparison: Some(comparison),
        };

        let rendered = render_compact(&summary);
        assert!(rendered.contains("Multi-process Comparison"));
        assert!(rendered.contains("Δ Publishes"));
        assert!(rendered.contains("Logs"));
    }
}
