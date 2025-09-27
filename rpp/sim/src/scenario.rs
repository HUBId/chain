use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Scenario {
    pub sim: SimSection,
    pub topology: TopologySection,
    pub traffic: TrafficSection,
    #[serde(default)]
    pub metrics: Option<MetricsSection>,
}

#[derive(Debug, Deserialize)]
pub struct SimSection {
    pub seed: u64,
    pub duration_ms: u64,
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TopologySection {
    #[serde(rename = "type")]
    pub topology_type: String,
    pub n: usize,
    pub k: usize,
}

#[derive(Debug, Deserialize)]
pub struct TrafficSection {
    pub tx: TxTraffic,
}

#[derive(Debug, Deserialize)]
pub struct TxTraffic {
    pub model: String,
    pub lambda_per_sec: f64,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct MetricsSection {
    pub output: Option<PathBuf>,
}

impl Scenario {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read scenario file {path:?}"))?;
        let scenario: Scenario = toml::from_str(&contents)
            .with_context(|| format!("failed to parse scenario file {path:?}"))?;
        scenario.validate()?;
        Ok(scenario)
    }

    fn validate(&self) -> Result<()> {
        if self.topology.topology_type != "ring" {
            return Err(anyhow!(
                "only ring topology is currently supported (got {})",
                self.topology.topology_type
            ));
        }
        if self.traffic.tx.model != "poisson" {
            return Err(anyhow!(
                "only poisson traffic is currently supported (got {})",
                self.traffic.tx.model
            ));
        }
        Ok(())
    }

    pub fn metrics_output(&self) -> Option<PathBuf> {
        self.metrics
            .as_ref()
            .and_then(|metrics| metrics.output.clone())
    }
}
