use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::from_str;
use tokio::time::Duration;

#[derive(Debug, Clone, Deserialize)]
pub struct SimnetConfig {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_duration_secs")]
    pub duration_secs: u64,
    #[serde(default)]
    pub artifacts_dir: Option<PathBuf>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub nodes: Vec<ProcessConfig>,
    #[serde(default)]
    pub wallets: Vec<ProcessConfig>,
    #[serde(default)]
    pub p2p: Option<P2pConfig>,
    #[serde(default)]
    pub consensus: Option<ConsensusLoadConfig>,
    #[serde(skip)]
    source_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProcessConfig {
    pub label: String,
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default = "default_startup_timeout_ms")]
    pub startup_timeout_ms: u64,
    #[serde(default)]
    pub ready_log: Option<String>,
    #[serde(default)]
    pub working_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct P2pConfig {
    pub scenario_path: PathBuf,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub summary_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConsensusLoadConfig {
    #[serde(default = "default_consensus_runs")]
    pub runs: u64,
    #[serde(default = "default_validator_count")]
    pub validators: usize,
    #[serde(default = "default_witness_commitments")]
    pub witness_commitments: usize,
    #[serde(default)]
    pub security_bits: Option<u32>,
    #[serde(default)]
    pub use_gpu: Option<bool>,
    #[serde(default)]
    pub seed: Option<u64>,
    #[serde(default)]
    pub tamper: TamperConfig,
    #[serde(default)]
    pub summary_path: Option<PathBuf>,
    #[serde(default)]
    pub csv_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TamperConfig {
    #[serde(default)]
    pub vrf: bool,
    #[serde(default)]
    pub quorum_roots: bool,
    #[serde(default = "default_tamper_every")]
    pub every_n: u64,
}

impl Default for TamperConfig {
    fn default() -> Self {
        Self {
            vrf: true,
            quorum_roots: true,
            every_n: 16,
        }
    }
}

fn default_duration_secs() -> u64 {
    0
}

fn default_startup_timeout_ms() -> u64 {
    30_000
}

fn default_consensus_runs() -> u64 {
    64
}

fn default_validator_count() -> usize {
    64
}

fn default_witness_commitments() -> usize {
    192
}

fn default_tamper_every() -> u64 {
    8
}

impl SimnetConfig {
    pub fn from_path(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)
            .with_context(|| format!("failed to read scenario {}", path.display()))?;
        let mut config: SimnetConfig = from_str(&contents)
            .with_context(|| format!("failed to parse scenario {}", path.display()))?;
        config.source_path = Some(path.to_path_buf());
        Ok(config)
    }

    pub fn resolve_artifacts_dir(&self, override_dir: Option<&Path>) -> Result<PathBuf> {
        let dir = if let Some(override_dir) = override_dir {
            override_dir.to_path_buf()
        } else if let Some(configured) = &self.artifacts_dir {
            self.resolve_relative_path(configured)
        } else {
            PathBuf::from("target/simnet").join(self.slug())
        };

        fs::create_dir_all(&dir)
            .with_context(|| format!("create artifacts dir {}", dir.display()))?;
        Ok(dir)
    }

    pub fn scenario_dir(&self) -> PathBuf {
        self.source_path
            .as_ref()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."))
    }

    pub fn resolve_relative_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            return path.to_path_buf();
        }
        self.scenario_dir().join(path)
    }

    pub fn resolve_working_dir(&self, path: &Option<PathBuf>) -> Option<PathBuf> {
        path.as_ref().map(|dir| {
            if dir.is_absolute() {
                dir.clone()
            } else {
                self.scenario_dir().join(dir)
            }
        })
    }

    pub fn resolve_summary_path(&self, p2p: &P2pConfig, artifacts_dir: &Path) -> PathBuf {
        let relative = p2p
            .summary_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("summaries").join(format!("{}.json", self.slug())));
        if relative.is_absolute() {
            relative
        } else {
            artifacts_dir.join(relative)
        }
    }

    pub fn resolve_consensus_summary_path(
        &self,
        consensus: &ConsensusLoadConfig,
        artifacts_dir: &Path,
    ) -> PathBuf {
        let relative = consensus
            .summary_path
            .clone()
            .unwrap_or_else(|| PathBuf::from("summaries").join(format!("{}_consensus.json", self.slug())));
        if relative.is_absolute() {
            relative
        } else {
            artifacts_dir.join(relative)
        }
    }

    pub fn resolve_consensus_csv_path(
        &self,
        consensus: &ConsensusLoadConfig,
        artifacts_dir: &Path,
    ) -> Option<PathBuf> {
        consensus.csv_path.clone().map(|relative| {
            if relative.is_absolute() {
                relative
            } else {
                artifacts_dir.join(relative)
            }
        })
    }

    pub fn slug(&self) -> String {
        self.name
            .chars()
            .map(|c| match c {
                'a'..='z' | '0'..='9' => c,
                'A'..='Z' => c.to_ascii_lowercase(),
                _ => '-',
            })
            .collect()
    }
}

impl ProcessConfig {
    pub fn startup_timeout(&self) -> Duration {
        Duration::from_millis(self.startup_timeout_ms)
    }
}
