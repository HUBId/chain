use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;

use serde::Deserialize;

use crate::faults::{ByzantineFault, ChurnFault, PartitionFault};

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
    #[serde(default)]
    pub faults: FaultsSection,
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

#[derive(Debug, Deserialize, Clone, Default)]
pub struct FaultsSection {
    pub partition: Option<PartitionFaultConfig>,
    pub churn: Option<ChurnFaultConfig>,
    pub byzantine: Option<ByzantineFaultConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PartitionFaultConfig {
    pub start_ms: u64,
    pub duration_ms: u64,
    pub group_a: String,
    pub group_b: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ChurnFaultConfig {
    #[serde(default)]
    pub start_ms: Option<u64>,
    pub rate_per_min: f64,
    pub restart_after_ms: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ByzantineFaultConfig {
    #[serde(default)]
    pub start_ms: Option<u64>,
    pub spam_factor: u64,
    pub publishers: Vec<usize>,
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
        if let Some(partition) = &self.faults.partition {
            if self.regions.assignments.is_empty() {
                return Err(anyhow!(
                    "region assignments are required when configuring a partition fault"
                ));
            }
            if !self
                .regions
                .assignments
                .iter()
                .any(|r| r == &partition.group_a)
            {
                return Err(anyhow!(
                    "partition group_a ({}) missing from region assignments",
                    partition.group_a
                ));
            }
            if !self
                .regions
                .assignments
                .iter()
                .any(|r| r == &partition.group_b)
            {
                return Err(anyhow!(
                    "partition group_b ({}) missing from region assignments",
                    partition.group_b
                ));
            }
            if partition.duration_ms == 0 {
                return Err(anyhow!("partition duration must be positive"));
            }
        }
        if let Some(churn) = &self.faults.churn {
            if churn.rate_per_min <= 0.0 {
                return Err(anyhow!("churn rate_per_min must be positive"));
            }
            if churn.restart_after_ms == 0 {
                return Err(anyhow!("churn restart_after_ms must be positive"));
            }
        }
        if let Some(byzantine) = &self.faults.byzantine {
            for &idx in &byzantine.publishers {
                if idx >= self.topology.n {
                    return Err(anyhow!(
                        "byzantine publisher index {} out of range (n = {})",
                        idx,
                        self.topology.n
                    ));
                }
            }
            if byzantine.spam_factor == 0 {
                return Err(anyhow!("byzantine spam_factor must be positive"));
            }
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

    pub fn partition_fault(&self) -> Option<PartitionFault> {
        self.faults.partition.as_ref().map(|cfg| {
            PartitionFault::new(
                Duration::from_millis(cfg.start_ms),
                Duration::from_millis(cfg.duration_ms),
                cfg.group_a.clone(),
                cfg.group_b.clone(),
            )
        })
    }

    pub fn churn_fault(&self) -> Option<ChurnFault> {
        self.faults.churn.as_ref().map(|cfg| {
            ChurnFault::new(
                Duration::from_millis(cfg.start_ms.unwrap_or(0)),
                cfg.rate_per_min,
                Duration::from_millis(cfg.restart_after_ms),
            )
        })
    }

    pub fn byzantine_fault(&self) -> Option<ByzantineFault> {
        self.faults.byzantine.as_ref().map(|cfg| {
            ByzantineFault::new(
                Duration::from_millis(cfg.start_ms.unwrap_or(0)),
                cfg.spam_factor,
                cfg.publishers.clone(),
            )
        })
    }
}
