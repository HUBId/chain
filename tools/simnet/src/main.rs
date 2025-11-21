mod config;
mod consensus;
mod process;
mod runner;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::config::SimnetConfig;
use crate::runner::SimnetRunner;

#[derive(Debug, Parser)]
#[command(author, version, about = "Orchestrate RPP simulation networks", long_about = None)]
struct Cli {
    /// Path to the RON scenario file
    #[arg(long)]
    scenario: PathBuf,

    /// Override the artifacts directory defined in the scenario
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Keep processes alive after the harness finishes
    #[arg(long)]
    keep_alive: bool,
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

    let config = SimnetConfig::from_path(&cli.scenario)
        .with_context(|| format!("failed to load scenario {}", cli.scenario.display()))?;
    config
        .validate()
        .with_context(|| format!("invalid scenario {}", cli.scenario.display()))?;
    let artifacts_dir = config.resolve_artifacts_dir(cli.artifacts_dir.as_deref())?;

    let mut runner = SimnetRunner::new(config, artifacts_dir);

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

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
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
