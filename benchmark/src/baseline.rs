use std::error::Error;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::smoke::SmokeRunMetrics;

const BASELINE_ENV: &str = "FIREWOOD_SMOKE_BASELINE";
const EMBEDDED_BASELINE: &str = include_str!("../baselines/smoke.json");

#[derive(Debug, Clone, Deserialize)]
struct RangeSpec {
    lower: Option<f64>,
    upper: Option<f64>,
}

impl RangeSpec {
    fn validate(&self, value: f64) -> bool {
        if let Some(lower) = self.lower {
            if value < lower {
                return false;
            }
        }
        if let Some(upper) = self.upper {
            if value > upper {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Deserialize)]
struct SmokeBaselineConfig {
    throughput_ops_per_sec: RangeSpec,
    total_duration_ms: RangeSpec,
    per_batch_p95_ms: RangeSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonResult {
    pub actual: f64,
    pub lower: Option<f64>,
    pub upper: Option<f64>,
    pub within_range: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SmokeBaselineReport {
    pub source: BaselineSource,
    pub throughput_ops_per_sec: ComparisonResult,
    pub total_duration_ms: ComparisonResult,
    pub per_batch_p95_ms: ComparisonResult,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "path")]
pub enum BaselineSource {
    Embedded,
    File(PathBuf),
}

pub fn evaluate(metrics: &SmokeRunMetrics) -> Result<SmokeBaselineReport, Box<dyn Error>> {
    let (config, source) = load_config()?;
    let throughput = metrics.throughput_ops_per_sec;
    let total_duration = metrics.total_duration_ms;
    let per_batch_p95 = metrics.per_batch_p95_ms();

    Ok(SmokeBaselineReport {
        source,
        throughput_ops_per_sec: build_result(&config.throughput_ops_per_sec, throughput),
        total_duration_ms: build_result(&config.total_duration_ms, total_duration),
        per_batch_p95_ms: build_result(&config.per_batch_p95_ms, per_batch_p95),
    })
}

fn load_config() -> Result<(SmokeBaselineConfig, BaselineSource), Box<dyn Error>> {
    if let Ok(path) = std::env::var(BASELINE_ENV) {
        let path = PathBuf::from(path);
        let contents = fs::read_to_string(&path)?;
        let config = serde_json::from_str(&contents)?;
        return Ok((config, BaselineSource::File(path)));
    }

    let config = serde_json::from_str(EMBEDDED_BASELINE)?;
    Ok((config, BaselineSource::Embedded))
}

fn build_result(range: &RangeSpec, actual: f64) -> ComparisonResult {
    ComparisonResult {
        actual,
        lower: range.lower,
        upper: range.upper,
        within_range: range.validate(actual),
    }
}

impl SmokeRunMetrics {
    fn per_batch_p95_ms(&self) -> f64 {
        let mut values = self.per_batch_ms.clone();
        if values.is_empty() {
            return 0.0;
        }
        values.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let index = ((values.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
        values[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comparison(lower: Option<f64>, upper: Option<f64>, actual: f64) -> bool {
        RangeSpec { lower, upper }.validate(actual)
    }

    #[test]
    fn range_validation_enforces_bounds() {
        assert!(comparison(Some(1.0), Some(5.0), 3.0));
        assert!(!comparison(Some(1.0), Some(5.0), 0.5));
        assert!(!comparison(Some(1.0), Some(5.0), 5.1));
        assert!(comparison(None, Some(5.0), 4.9));
        assert!(!comparison(None, Some(5.0), 6.0));
        assert!(comparison(Some(1.0), None, 10.0));
        assert!(!comparison(Some(1.0), None, 0.5));
    }

    #[test]
    fn percentile_calculation_handles_small_samples() {
        let metrics = SmokeRunMetrics {
            batches: 5,
            batch_size: 10,
            total_operations: 50,
            total_duration_ms: 100.0,
            throughput_ops_per_sec: 500.0,
            per_batch_ms: vec![1.0, 2.0, 3.0, 4.0, 50.0],
        };
        assert_eq!(metrics.per_batch_p95_ms(), 50.0);

        let metrics = SmokeRunMetrics {
            batches: 1,
            batch_size: 10,
            total_operations: 10,
            total_duration_ms: 10.0,
            throughput_ops_per_sec: 1000.0,
            per_batch_ms: vec![12.0],
        };
        assert_eq!(metrics.per_batch_p95_ms(), 12.0);

        let metrics = SmokeRunMetrics {
            batches: 0,
            batch_size: 0,
            total_operations: 0,
            total_duration_ms: 0.0,
            throughput_ops_per_sec: 0.0,
            per_batch_ms: vec![],
        };
        assert_eq!(metrics.per_batch_p95_ms(), 0.0);
    }
}
