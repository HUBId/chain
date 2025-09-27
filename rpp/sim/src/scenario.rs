use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Scenario {
    pub sim: SimSection,
    pub topology: TopologySection,
    pub traffic: TrafficSection,
    #[serde(default)]
    pub regions: RegionsSection,
    #[serde(default)]
    pub links: LinksSection,
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
#[serde(rename_all = "snake_case")]
pub enum TopologyType {
    Ring,
    ErdosRenyi,
    KRegular,
    SmallWorld,
    ScaleFree,
}

#[derive(Debug, Deserialize)]
pub struct TopologySection {
    #[serde(rename = "type")]
    pub topology_type: TopologyType,
    pub n: usize,
    #[serde(default)]
    pub k: Option<usize>,
    #[serde(default)]
    pub p: Option<f64>,
    #[serde(default)]
    pub rewire_p: Option<f64>,
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

#[derive(Debug, Deserialize, Clone)]
pub struct RegionsSection {
    #[serde(default)]
    pub assignments: Vec<String>,
}

impl Default for RegionsSection {
    fn default() -> Self {
        Self {
            assignments: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct LinkParams {
    pub delay_ms: u64,
    pub jitter_ms: u64,
    pub loss: f64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LinksSection {
    #[serde(flatten)]
    pub entries: HashMap<String, LinkParams>,
}

impl LinksSection {
    pub fn with_defaults(mut self) -> Self {
        self.entries
            .entry("default".to_string())
            .or_insert(LinkParams {
                delay_ms: 0,
                jitter_ms: 0,
                loss: 0.0,
            });
        self
    }
}

impl Default for LinksSection {
    fn default() -> Self {
        let mut entries = HashMap::new();
        entries.insert(
            "default".to_string(),
            LinkParams {
                delay_ms: 0,
                jitter_ms: 0,
                loss: 0.0,
            },
        );
        Self { entries }
    }
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
        let mut scenario: Scenario = toml::from_str(&contents)
            .with_context(|| format!("failed to parse scenario file {path:?}"))?;
        scenario.links = scenario.links.with_defaults();
        scenario.validate()?;
        Ok(scenario)
    }

    fn validate(&self) -> Result<()> {
        if self.traffic.tx.model != "poisson" {
            return Err(anyhow!(
                "only poisson traffic is currently supported (got {})",
                self.traffic.tx.model
            ));
        }
        if let Some(k) = self.topology.k {
            if k == 0 {
                return Err(anyhow!("topology degree k must be greater than zero"));
            }
        }
        if let Some(p) = self.topology.p {
            if !(0.0..=1.0).contains(&p) {
                return Err(anyhow!("topology probability p must be between 0 and 1"));
            }
        }
        if let Some(rewire_p) = self.topology.rewire_p {
            if !(0.0..=1.0).contains(&rewire_p) {
                return Err(anyhow!("rewire probability must be between 0 and 1"));
            }
        }
        if !self.regions.assignments.is_empty() {
            if self.regions.assignments.len() != self.topology.n {
                return Err(anyhow!(
                    "number of region assignments ({}) must match node count ({})",
                    self.regions.assignments.len(),
                    self.topology.n
                ));
            }
        }
        match self.topology.topology_type {
            TopologyType::Ring | TopologyType::KRegular | TopologyType::SmallWorld => {
                if self.topology.k.is_none() {
                    return Err(anyhow!("topology requires k parameter"));
                }
            }
            TopologyType::ErdosRenyi => {
                if self.topology.p.is_none() {
                    return Err(anyhow!("erdos-renyi topology requires p parameter"));
                }
            }
            TopologyType::ScaleFree => {}
        }
        if matches!(self.topology.topology_type, TopologyType::SmallWorld)
            && self.topology.rewire_p.is_none()
        {
            return Err(anyhow!("small-world topology requires rewire_p parameter"));
        }
        Ok(())
    }

    pub fn metrics_output(&self) -> Option<PathBuf> {
        self.metrics
            .as_ref()
            .and_then(|metrics| metrics.output.clone())
    }

    pub fn node_regions(&self) -> Vec<String> {
        if self.regions.assignments.is_empty() {
            vec!["default".to_string(); self.topology.n]
        } else {
            self.regions.assignments.clone()
        }
    }

    pub fn link_params_for(&self, key: &str) -> Option<&LinkParams> {
        self.links.entries.get(key)
    }
}
