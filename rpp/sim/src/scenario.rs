use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;

use serde::Deserialize;

use crate::faults::{ByzantineFault, ChurnFault, PartitionFault};
use crate::traffic::{
    OnOffBursty, PoissonTraffic, PublisherSelectorBuilder, TrafficModelState, TrafficPhaseConfig,
    TrafficProgram,
};

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

#[derive(Debug, Deserialize, Clone)]
pub struct TxTraffic {
    #[serde(default)]
    pub phases: Vec<TrafficPhase>,
    #[serde(default)]
    pub publisher_bias: Option<PublisherBiasConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TrafficPhase {
    #[serde(default)]
    pub name: Option<String>,
    pub duration_ms: u64,
    #[serde(flatten)]
    pub model: TrafficModelConfig,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "model", rename_all = "snake_case")]
pub enum TrafficModelConfig {
    Poisson {
        lambda_per_sec: f64,
    },
    OnOffBursty {
        on_lambda_per_sec: f64,
        on_duration_ms: u64,
        off_duration_ms: u64,
    },
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PublisherBiasConfig {
    Uniform,
    Zipf { s: f64 },
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
    /// Deprecated shorthand for `json`.
    pub output: Option<PathBuf>,
    #[serde(default)]
    pub json: Option<PathBuf>,
    #[serde(default)]
    pub csv: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct MetricsOutputs {
    pub json: Option<PathBuf>,
    pub csv: Option<PathBuf>,
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
        if self.traffic.tx.phases.is_empty() {
            return Err(anyhow!("at least one traffic phase must be specified"));
        }
        for (idx, phase) in self.traffic.tx.phases.iter().enumerate() {
            if phase.duration_ms == 0 {
                return Err(anyhow!("traffic phase {idx} duration must be positive"));
            }
            match &phase.model {
                TrafficModelConfig::Poisson { lambda_per_sec } => {
                    if *lambda_per_sec <= 0.0 {
                        return Err(anyhow!(
                            "traffic phase {idx} lambda_per_sec must be positive"
                        ));
                    }
                }
                TrafficModelConfig::OnOffBursty {
                    on_lambda_per_sec,
                    on_duration_ms,
                    off_duration_ms,
                } => {
                    if *on_lambda_per_sec <= 0.0 {
                        return Err(anyhow!(
                            "traffic phase {idx} on_lambda_per_sec must be positive"
                        ));
                    }
                    if *on_duration_ms == 0 {
                        return Err(anyhow!(
                            "traffic phase {idx} on_duration_ms must be positive"
                        ));
                    }
                    if *off_duration_ms == 0 {
                        return Err(anyhow!(
                            "traffic phase {idx} off_duration_ms must be positive"
                        ));
                    }
                }
            }
        }
        if let Some(PublisherBiasConfig::Zipf { s }) = &self.traffic.tx.publisher_bias {
            if *s <= 0.0 {
                return Err(anyhow!("zipf bias parameter s must be positive"));
            }
        }
        let total_phase_duration: u64 = self.traffic.tx.phases.iter().map(|p| p.duration_ms).sum();
        if total_phase_duration > self.sim.duration_ms {
            return Err(anyhow!(
                "sum of traffic phase durations ({total_phase_duration}) exceeds simulation duration ({})",
                self.sim.duration_ms
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

    pub fn metrics_outputs(&self) -> MetricsOutputs {
        let Some(section) = self.metrics.as_ref() else {
            return MetricsOutputs::default();
        };
        let json_path = section.json.clone().or_else(|| section.output.clone());
        MetricsOutputs {
            json: json_path,
            csv: section.csv.clone(),
        }
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

    pub fn traffic_program(&self) -> Result<TrafficProgram> {
        self.traffic.tx.build_program(self.sim.seed)
    }
}

impl TxTraffic {
    pub fn build_program(&self, seed: u64) -> Result<TrafficProgram> {
        let mut phases = Vec::with_capacity(self.phases.len());
        for (idx, phase) in self.phases.iter().enumerate() {
            let phase_seed = seed ^ ((idx as u64 + 1) * 0x9E37_79B9_7F4A_7C15);
            let model = phase.model.build(phase_seed)?;
            phases.push(TrafficPhaseConfig {
                name: phase.name.clone(),
                duration: Duration::from_millis(phase.duration_ms),
                model,
            });
        }
        let selector_seed = seed ^ 0xA5A5_A5A5_A5A5_A5A5;
        let publisher = match &self.publisher_bias {
            Some(PublisherBiasConfig::Zipf { s }) => {
                PublisherSelectorBuilder::zipf(selector_seed, *s)?
            }
            _ => PublisherSelectorBuilder::uniform(selector_seed),
        };
        Ok(TrafficProgram::new(phases, publisher))
    }
}

impl TrafficModelConfig {
    fn build(&self, seed: u64) -> Result<TrafficModelState> {
        match self {
            TrafficModelConfig::Poisson { lambda_per_sec } => Ok(TrafficModelState::Poisson(
                PoissonTraffic::new(*lambda_per_sec, seed)?,
            )),
            TrafficModelConfig::OnOffBursty {
                on_lambda_per_sec,
                on_duration_ms,
                off_duration_ms,
            } => Ok(TrafficModelState::OnOff(OnOffBursty::new(
                *on_lambda_per_sec,
                *on_duration_ms,
                *off_duration_ms,
                seed,
            )?)),
        }
    }
}
