use serde::Serialize;

use super::collector::{FaultRecord, MeshChangeRecord};

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PropagationPercentiles {
    pub p50_ms: f64,
    pub p95_ms: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SimulationSummary {
    pub total_publishes: usize,
    pub total_receives: usize,
    pub duplicates: usize,
    pub propagation: Option<PropagationPercentiles>,
    pub mesh_changes: Vec<MeshChangeRecord>,
    pub faults: Vec<FaultRecord>,
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
}
