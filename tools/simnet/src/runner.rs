use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::to_vec_pretty;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

use crate::config::{P2pConfig, ProcessConfig, SimnetConfig};
use crate::process::{spawn_process, ProcessHandle};

pub struct SimnetRunner {
    config: SimnetConfig,
    artifacts_dir: PathBuf,
    handles: Vec<ProcessHandle>,
    manifest_processes: Vec<ManifestProcess>,
    p2p_manifest: Option<ManifestP2p>,
    started_at: SystemTime,
}

impl SimnetRunner {
    pub fn new(config: SimnetConfig, artifacts_dir: PathBuf) -> Self {
        Self {
            config,
            artifacts_dir,
            handles: Vec::new(),
            manifest_processes: Vec::new(),
            p2p_manifest: None,
            started_at: SystemTime::now(),
        }
    }

    pub async fn execute(&mut self) -> Result<()> {
        if !self.config.nodes.is_empty() {
            self.spawn_group("node", &self.config.nodes).await?;
        }
        if !self.config.wallets.is_empty() {
            self.spawn_group("wallet", &self.config.wallets).await?;
        }

        if let Some(p2p) = &self.config.p2p {
            let outcome = self.run_p2p(p2p).await?;
            self.p2p_manifest = Some(outcome.clone());
            info!(
                target = "simnet::runner",
                path = %outcome.summary_path.display(),
                "p2p summary written"
            );
        }

        if self.config.duration_secs > 0 {
            info!(
                target = "simnet::runner",
                seconds = self.config.duration_secs,
                "scenario requested post-run sleep"
            );
            sleep(Duration::from_secs(self.config.duration_secs)).await;
        }

        self.write_manifest().await?;

        Ok(())
    }

    async fn spawn_group(&mut self, group: &str, processes: &[ProcessConfig]) -> Result<()> {
        for process in processes {
            info!(
                target = "simnet::runner",
                group,
                label = %process.label,
                "starting process"
            );
            let mut handle = spawn_process(&self.config, process, &self.artifacts_dir).await?;
            let wait_result = handle.wait_ready(process.startup_timeout()).await;
            let log_path = handle.log_path().to_path_buf();
            self.manifest_processes.push(ManifestProcess {
                group: group.to_string(),
                label: process.label.clone(),
                program: process.program.clone(),
                args: process.args.clone(),
                log_path,
                ready_pattern: process.ready_log.clone(),
            });
            self.handles.push(handle);
            wait_result
                .with_context(|| format!("{group} {} failed to signal readiness", process.label))?;
        }
        Ok(())
    }

    async fn run_p2p(&self, config: &P2pConfig) -> Result<ManifestP2p> {
        let scenario_path = self.config.resolve_relative_path(&config.scenario_path);
        let summary_path = self
            .config
            .resolve_summary_path(config, &self.artifacts_dir);
        if let Some(parent) = summary_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("create summary dir {}", parent.display()))?;
        }

        info!(
            target = "simnet::runner",
            scenario = %scenario_path.display(),
            mode = ?config.mode,
            "running p2p harness"
        );

        let mut scenario = rpp_sim::scenario::Scenario::from_path(&scenario_path)
            .with_context(|| format!("load p2p scenario {}", scenario_path.display()))?;
        if let Some(mode) = &config.mode {
            scenario.sim.mode = Some(mode.clone());
        }
        let seed = scenario.sim.seed;
        let mode = scenario.sim.mode.clone();

        let harness = rpp_sim::SimHarness;
        let summary = tokio::task::spawn_blocking(move || harness.run_scenario(scenario))
            .await
            .context("p2p harness panicked")??;
        let serialized = to_vec_pretty(&summary).context("serialize p2p summary")?;
        tokio::fs::write(&summary_path, serialized)
            .await
            .with_context(|| format!("write summary {}", summary_path.display()))?;

        Ok(ManifestP2p {
            scenario_path,
            summary_path,
            seed,
            mode,
        })
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        let mut error: Option<anyhow::Error> = None;
        while let Some(handle) = self.handles.pop() {
            match handle.shutdown().await {
                Ok(()) => {}
                Err(err) => {
                    warn!(target = "simnet::runner", "shutdown failure: {err:#}");
                    if error.is_none() {
                        error = Some(err);
                    }
                }
            }
        }

        if let Some(err) = error {
            return Err(err);
        }

        Ok(())
    }

    async fn write_manifest(&self) -> Result<()> {
        let started_unix_ms = self
            .started_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let manifest = SimnetManifest {
            name: self.config.name.clone(),
            slug: self.config.slug(),
            started_unix_ms,
            duration_secs: self.config.duration_secs,
            env: self.config.env.clone(),
            processes: self.manifest_processes.clone(),
            p2p: self.p2p_manifest.clone(),
        };

        let serialized = to_vec_pretty(&manifest).context("serialize simnet manifest")?;
        let path = self.artifacts_dir.join("manifest.json");
        tokio::fs::write(&path, serialized)
            .await
            .with_context(|| format!("write manifest {}", path.display()))
    }
}

#[derive(Clone, Serialize)]
struct ManifestProcess {
    group: String,
    label: String,
    program: String,
    args: Vec<String>,
    log_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    ready_pattern: Option<String>,
}

#[derive(Clone, Serialize)]
struct ManifestP2p {
    scenario_path: PathBuf,
    summary_path: PathBuf,
    seed: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
}

#[derive(Serialize)]
struct SimnetManifest {
    name: String,
    slug: String,
    started_unix_ms: u128,
    duration_secs: u64,
    env: BTreeMap<String, String>,
    processes: Vec<ManifestProcess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    p2p: Option<ManifestP2p>,
}
