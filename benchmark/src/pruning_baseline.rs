use std::error::Error;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::pruning::PruningRunMetrics;

const BASELINE_ENV: &str = "FIREWOOD_PRUNING_BASELINE";
const EMBEDDED_BASELINE: &str = include_str!("../baselines/pruning.json");

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
struct PruningBaselineConfig {
    throughput_ops_per_sec: RangeSpec,
    total_duration_ms: RangeSpec,
    per_block_p95_ms: RangeSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonResult {
    pub actual: f64,
    pub lower: Option<f64>,
    pub upper: Option<f64>,
    pub within_range: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PruningBaselineReport {
    pub source: BaselineSource,
    pub profile: String,
    pub throughput_ops_per_sec: ComparisonResult,
    pub total_duration_ms: ComparisonResult,
    pub per_block_p95_ms: ComparisonResult,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "path")]
pub enum BaselineSource {
    Embedded,
    File(PathBuf),
}

#[derive(Debug, Clone, Deserialize)]
struct BaselineProfiles(serde_json::Map<String, serde_json::Value>);

pub fn evaluate(metrics: &PruningRunMetrics) -> Result<PruningBaselineReport, Box<dyn Error>> {
    let (profiles, source) = load_config()?;
    let profile_key = format!("{}-bf{}", metrics.backend, metrics.branch_factor);
    let Some(profile) = profiles.0.get(&profile_key) else {
        return Err(format!("No pruning baseline named {profile_key}").into());
    };

    let config: PruningBaselineConfig = serde_json::from_value(profile.clone())?;
    let throughput = metrics.throughput_ops_per_sec;
    let total_duration = metrics.total_duration_ms;
    let per_block_p95 = per_block_p95_ms(metrics);

    Ok(PruningBaselineReport {
        source,
        profile: profile_key,
        throughput_ops_per_sec: build_result(&config.throughput_ops_per_sec, throughput),
        total_duration_ms: build_result(&config.total_duration_ms, total_duration),
        per_block_p95_ms: build_result(&config.per_block_p95_ms, per_block_p95),
    })
}

impl PruningBaselineReport {
    pub fn within_thresholds(&self) -> bool {
        self.throughput_ops_per_sec.within_range
            && self.total_duration_ms.within_range
            && self.per_block_p95_ms.within_range
    }
}

fn load_config() -> Result<(BaselineProfiles, BaselineSource), Box<dyn Error>> {
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

fn per_block_p95_ms(metrics: &PruningRunMetrics) -> f64 {
    let mut values = metrics.per_block_ms.clone();
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let index = ((values.len() as f64 * 0.95).ceil() as usize).saturating_sub(1);
    values[index]
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
        let metrics = PruningRunMetrics {
            backend: "standard",
            branch_factor: 16,
            blocks: 2,
            ops_per_block: 2,
            total_operations: 4,
            total_duration_ms: 1.0,
            throughput_ops_per_sec: 4.0,
            per_block_ms: vec![1.0, 50.0],
        };
        assert_eq!(per_block_p95_ms(&metrics), 50.0);

        let metrics = PruningRunMetrics {
            per_block_ms: vec![12.0],
            ..metrics
        };
        assert_eq!(per_block_p95_ms(&metrics), 12.0);

        let metrics = PruningRunMetrics {
            per_block_ms: vec![],
            ..metrics
        };
        assert_eq!(per_block_p95_ms(&metrics), 0.0);
    }
}
