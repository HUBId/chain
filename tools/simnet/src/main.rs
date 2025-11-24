mod config;
mod consensus;
mod process;
mod profiles;
mod runner;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use sysinfo::System;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use crate::config::SimnetConfig;
use crate::profiles::SimnetProfile;
use crate::runner::SimnetRunner;

#[derive(Debug, Parser)]
#[command(author, version, about = "Orchestrate RPP simulation networks", long_about = None)]
struct Cli {
    /// Use a predefined scenario profile
    #[arg(long, value_enum, conflicts_with = "scenario")]
    profile: Option<SimnetProfile>,

    /// Path to the RON scenario file
    #[arg(long, conflicts_with = "profile")]
    scenario: Option<PathBuf>,

    /// Override the artifacts directory defined in the scenario
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Keep processes alive after the harness finishes
    #[arg(long)]
    keep_alive: bool,

    /// Override the RNG seed used by p2p and consensus harnesses
    #[arg(long, env = "SIMNET_SEED")]
    seed: Option<u64>,

    /// Continue even when the host does not meet the scenario resource guidance
    #[arg(long)]
    allow_insufficient_resources: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing();

    let mut health_server = match init_health_server().await {
        Ok(server) => server,
        Err(err) => {
            error!(
                target = "simnet::health",
                "failed to start health server: {err:#}"
            );
            None
        }
    };

    let scenario_path = resolve_scenario_path(&cli)?;
    let config = SimnetConfig::from_path(&scenario_path)
        .with_context(|| format!("failed to load scenario {}", scenario_path.display()))?;
    config
        .validate()
        .with_context(|| format!("invalid scenario {}", scenario_path.display()))?;
    enforce_resources(&config, cli.allow_insufficient_resources)?;
    let artifacts_dir = config.resolve_artifacts_dir(cli.artifacts_dir.as_deref())?;

    let mut runner = SimnetRunner::new(config, artifacts_dir, cli.seed);

    if let Some(server) = &health_server {
        server.set_active(true);
    }
    let outcome = runner.execute().await;

    if cli.keep_alive {
        info!(target = "simnet", "keep-alive requested; sleeping for 60s");
        tokio::time::sleep(Duration::from_secs(60)).await;
    }

    if let Some(server) = &health_server {
        server.set_active(false);
    }

    let mut shutdown_error = None;
    if let Err(err) = runner.shutdown().await {
        error!(target = "simnet", "failed to shutdown processes: {err:#}");
        shutdown_error = Some(err);
    }

    outcome?;

    if let Some(err) = shutdown_error {
        if let Some(server) = health_server.take() {
            server.shutdown().await;
        }
        return Err(err);
    }

    if let Some(server) = health_server {
        server.shutdown().await;
    }

    Ok(())
}

fn resolve_scenario_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(profile) = cli.profile {
        let path = profile.scenario_path();
        if !path.exists() {
            bail!(
                "scenario for profile {} not found at {}",
                profile.slug(),
                path.display()
            );
        }
        return Ok(path);
    }

    if let Some(path) = &cli.scenario {
        return Ok(path.to_path_buf());
    }

    bail!("either --profile or --scenario must be provided")
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

fn enforce_resources(config: &SimnetConfig, allow_insufficient: bool) -> Result<()> {
    let Some(resources) = &config.resources else {
        return Ok(());
    };

    let system = System::new_all();
    let host_cpus = system.cpus().len();
    let host_memory = system.total_memory();

    info!(
        target = "simnet::resources",
        required_cpus = resources.cpus,
        host_cpus,
        required_memory_gb = resources.memory_gb,
        host_memory_gb = bytes_to_gb(host_memory),
        "resource guidance",
    );

    if host_cpus < resources.cpus || host_memory < resources.memory_bytes() {
        if allow_insufficient {
            warn!(
                target = "simnet::resources",
                "host resources are below scenario guidance; continuing due to --allow-insufficient-resources"
            );
            return Ok(());
        }

        bail!(
            "host resources below scenario guidance ({} cpus, {} GiB required); rerun with --allow-insufficient-resources to override",
            resources.cpus,
            resources.memory_gb,
        );
    }

    Ok(())
}

fn bytes_to_gb(bytes: u64) -> f64 {
    bytes as f64 / 1_073_741_824f64
}

struct HealthServer {
    active: Arc<AtomicBool>,
    shutdown: Option<oneshot::Sender<()>>,
    handle: JoinHandle<()>,
}

impl HealthServer {
    fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::SeqCst);
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Err(err) = self.handle.await {
            error!(
                target = "simnet::health",
                "health server task error: {err:#}"
            );
        }
    }
}

async fn init_health_server() -> Result<Option<HealthServer>> {
    let addr = match std::env::var("SIMNET_HEALTH_ADDR") {
        Ok(value) if !value.is_empty() => value,
        _ => return Ok(None),
    };

    let addr: SocketAddr = addr
        .parse()
        .with_context(|| format!("failed to parse SIMNET_HEALTH_ADDR '{addr}'"))?;

    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind health listener on {addr}"))?;
    let active = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server_active = Arc::clone(&active);

    info!(target = "simnet::health", listen = %addr, "health server listening");

    let handle = tokio::spawn(async move {
        if let Err(err) = run_health_server(listener, server_active, shutdown_rx).await {
            error!(target = "simnet::health", "health server failed: {err:#}");
        }
    });

    Ok(Some(HealthServer {
        active,
        shutdown: Some(shutdown_tx),
        handle,
    }))
}

async fn run_health_server(
    listener: TcpListener,
    active: Arc<AtomicBool>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                break;
            }
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((mut socket, _)) => {
                        let active = Arc::clone(&active);
                        tokio::spawn(async move {
                            let mut buf = [0u8; 1024];
                            match socket.read(&mut buf).await {
                                Ok(0) => {}
                                Ok(n) => {
                                    let request = String::from_utf8_lossy(&buf[..n]);
                                    let path = request
                                        .lines()
                                        .next()
                                        .and_then(|line| line.split_whitespace().nth(1))
                                        .unwrap_or("");

                                    let (status, body) = match path {
                                        "/health/live" | "/health/ready" => {
                                            if active.load(Ordering::SeqCst) {
                                                ("200 OK", "ok")
                                            } else {
                                                ("503 Service Unavailable", "inactive")
                                            }
                                        }
                                        _ => ("404 Not Found", "not found"),
                                    };

                                    let response = format!(
                                        "HTTP/1.1 {status}\r\ncontent-length: {}\r\ncontent-type: text/plain; charset=utf-8\r\nconnection: close\r\n\r\n{}",
                                        body.len(), body
                                    );

                                    if let Err(err) = socket.write_all(response.as_bytes()).await {
                                        error!(target = "simnet::health", "failed to write response: {err:#}");
                                    }
                                }
                                Err(err) => {
                                    error!(target = "simnet::health", "failed to read request: {err:#}");
                                }
                            }
                        });
                    }
                    Err(err) => {
                        error!(target = "simnet::health", "accept error: {err:#}");
                    }
                }
            }
        }
    }

    Ok(())
}
