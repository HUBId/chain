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

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::PropagationPercentiles;

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
        };

        let rendered = render_compact(&summary);
        assert!(rendered.contains("Simulation Summary"));
        assert!(rendered.contains("Publishes"));
        assert!(rendered.contains("120.50"));
    }
}
