use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::to_vec_pretty;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

use crate::config::{P2pConfig, ProcessConfig, SimnetConfig};
use crate::process::{spawn_process, ProcessHandle};

pub struct SimnetRunner {
    config: SimnetConfig,
    artifacts_dir: PathBuf,
    handles: Vec<ProcessHandle>,
}

impl SimnetRunner {
    pub fn new(config: SimnetConfig, artifacts_dir: PathBuf) -> Self {
        Self {
            config,
            artifacts_dir,
            handles: Vec::new(),
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
            let summary_path = self.run_p2p(p2p).await?;
            info!(
                target = "simnet::runner",
                path = %summary_path.display(),
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
            self.handles.push(handle);
            wait_result
                .with_context(|| format!("{group} {} failed to signal readiness", process.label))?;
        }
        Ok(())
    }

    async fn run_p2p(&self, config: &P2pConfig) -> Result<PathBuf> {
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

        let harness = rpp_sim::SimHarness;
        let summary = tokio::task::spawn_blocking(move || harness.run_scenario(scenario))
            .await
            .context("p2p harness panicked")??;
        let serialized = to_vec_pretty(&summary).context("serialize p2p summary")?;
        tokio::fs::write(&summary_path, serialized)
            .await
            .with_context(|| format!("write summary {}", summary_path.display()))?;

        Ok(summary_path)
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
}
