use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use parking_lot::RwLock;
use tokio::task::JoinError;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use rpp_chain::api::ApiContext;
use rpp_chain::config::NodeConfig;
use rpp_chain::node::{Node, NodeHandle};
use rpp_chain::runtime::RuntimeMode;

#[derive(Debug, Parser)]
#[command(author, version, about = "Run an rpp node", long_about = None)]
struct Cli {
    /// Optional path to a configuration file that will be loaded before starting the node
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override the data directory defined in the configuration
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Override the RPC listen address defined in the configuration
    #[arg(long)]
    rpc_listen: Option<std::net::SocketAddr>,

    /// Override the telemetry endpoint defined in the configuration
    #[arg(long)]
    telemetry_endpoint: Option<String>,

    /// Override the telemetry authentication token defined in the configuration
    #[arg(long)]
    telemetry_auth: Option<String>,

    /// Override the log level (also respects RUST_LOG)
    #[arg(long)]
    log_level: Option<String>,

    /// Emit logs in JSON format
    #[arg(long)]
    log_json: bool,

    /// Persist the resulting configuration into the current working directory
    #[arg(long)]
    write_config: bool,
}

#[derive(Debug)]
enum ShutdownEvent {
    Runtime(std::result::Result<(), JoinError>),
    CtrlC(std::io::Result<()>),
    #[cfg(unix)]
    SigTerm(Option<i32>),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.log_level.clone(), cli.log_json).context("failed to initialise logging")?;

    let mut config = load_configuration(&cli)?;
    apply_overrides(&mut config, &cli);

    if cli.write_config {
        let path = std::env::current_dir()
            .context("failed to resolve current working directory")?
            .join("node.toml");
        config
            .save(&path)
            .with_context(|| format!("failed to persist configuration to {}", path.display()))?;
        info!(path = %path.display(), "persisted node configuration");
    }

    let preview_node = Node::new(config.clone())
        .context("failed to build node with the provided configuration")?;
    info!(address = %preview_node.handle().address(), "node initialised");
    drop(preview_node);

    let (handle, runtime) = NodeHandle::start(config.clone())
        .await
        .context("failed to start node runtime")?;

    info!(address = %handle.address(), "node runtime started");
    info!(rpc_listen = %config.rpc_listen, "rpc endpoint configured");
    if config.rollout.telemetry.enabled {
        if let Some(endpoint) = &config.rollout.telemetry.endpoint {
            info!(
                target = "telemetry",
                endpoint = %endpoint,
                "telemetry endpoint configured"
            );
        } else {
            info!(
                target = "telemetry",
                "telemetry enabled without explicit endpoint"
            );
        }
    } else {
        info!(target = "telemetry", "telemetry disabled");
    }

    let runtime_mode = Arc::new(RwLock::new(RuntimeMode::Node));
    let rpc_context = ApiContext::new(
        Arc::clone(&runtime_mode),
        Some(handle.clone()),
        None,
        None,
        config
            .rpc_requests_per_minute
            .and_then(|limit| NonZeroU64::new(limit)),
    );

    let rpc_addr = config.rpc_listen;
    let rpc_auth = config.rpc_auth_token.clone();
    let rpc_origin = config.rpc_allowed_origin.clone();
    let rpc_task = tokio::spawn(async move {
        if let Err(err) = rpp_chain::api::serve(rpc_context, rpc_addr, rpc_auth, rpc_origin).await {
            error!(?err, "rpc server terminated");
        }
    });

    let shutdown_handle = handle.clone();
    let outcome = wait_for_shutdown(shutdown_handle, runtime).await;

    rpc_task.abort();
    if let Err(err) = rpc_task.await {
        if !err.is_cancelled() {
            warn!(?err, "rpc server join failed");
        }
    }

    match outcome {
        ShutdownOutcome::Clean => Ok(()),
        ShutdownOutcome::Errored(err) => Err(err),
    }
}

#[derive(Debug)]
enum ShutdownOutcome {
    Clean,
    Errored(anyhow::Error),
}

async fn wait_for_shutdown(
    handle: NodeHandle,
    mut runtime: tokio::task::JoinHandle<()>,
) -> ShutdownOutcome {
    tokio::pin!(runtime);

    let shutdown_event = {
        #[cfg(unix)]
        let mut sigterm =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(signal) => signal,
                Err(err) => {
                    return ShutdownOutcome::Errored(err.into());
                }
            };

        tokio::select! {
            result = &mut runtime => ShutdownEvent::Runtime(result),
            result = tokio::signal::ctrl_c() => ShutdownEvent::CtrlC(result),
            #[cfg(unix)]
            result = sigterm.recv() => ShutdownEvent::SigTerm(result),
        }
    };

    let mut runtime_result: Option<std::result::Result<(), JoinError>> = None;

    match shutdown_event {
        ShutdownEvent::Runtime(result) => {
            runtime_result = Some(result);
            if let Err(err) = handle.stop().await {
                error!(?err, "failed to stop node runtime after completion");
                return ShutdownOutcome::Errored(err.into());
            }
        }
        ShutdownEvent::CtrlC(result) => {
            match result {
                Ok(()) => info!("received ctrl_c signal"),
                Err(err) => warn!(?err, "failed to listen for ctrl_c"),
            }
            if let Err(err) = handle.stop().await {
                error!(?err, "failed to stop node runtime");
                return ShutdownOutcome::Errored(err.into());
            }
            runtime_result = Some((&mut runtime).await);
        }
        #[cfg(unix)]
        ShutdownEvent::SigTerm(result) => {
            match result {
                Some(_) => info!("received termination signal"),
                None => warn!("termination signal stream closed"),
            }
            if let Err(err) = handle.stop().await {
                error!(?err, "failed to stop node runtime");
                return ShutdownOutcome::Errored(err.into());
            }
            runtime_result = Some((&mut runtime).await);
        }
    }

    match runtime_result {
        Some(Ok(())) => {
            info!("node runtime exited cleanly");
            ShutdownOutcome::Clean
        }
        Some(Err(err)) => {
            let error = anyhow::Error::from(err);
            error!(?error, "node runtime join failed");
            ShutdownOutcome::Errored(error)
        }
        None => ShutdownOutcome::Clean,
    }
}

fn load_configuration(cli: &Cli) -> Result<NodeConfig> {
    if let Some(path) = cli.config.as_ref() {
        NodeConfig::load(path)
            .with_context(|| format!("failed to load configuration from {}", path.display()))
    } else {
        Ok(NodeConfig::default())
    }
}

fn apply_overrides(config: &mut NodeConfig, cli: &Cli) {
    if let Some(dir) = cli.data_dir.as_ref() {
        config.data_dir = dir.clone();
    }
    if let Some(addr) = cli.rpc_listen {
        config.rpc_listen = addr;
    }
    if let Some(endpoint) = cli.telemetry_endpoint.as_ref() {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            config.rollout.telemetry.endpoint = None;
            config.rollout.telemetry.enabled = false;
        } else {
            config.rollout.telemetry.endpoint = Some(endpoint.to_string());
            config.rollout.telemetry.enabled = true;
        }
    }
    if let Some(auth) = cli.telemetry_auth.as_ref() {
        let token = auth.trim();
        if token.is_empty() {
            config.rollout.telemetry.auth_token = None;
        } else {
            config.rollout.telemetry.auth_token = Some(token.to_string());
        }
    }
}

fn init_tracing(log_level: Option<String>, json: bool) -> Result<()> {
    let level = log_level.or_else(|| std::env::var("RUST_LOG").ok());
    let filter = match level {
        Some(level) => match EnvFilter::try_new(level) {
            Ok(filter) => filter,
            Err(err) => {
                warn!(?err, "invalid log level override, falling back to info");
                EnvFilter::new("info")
            }
        },
        None => EnvFilter::new("info"),
    };

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_ansi(!json);

    if json {
        builder.json().flatten_event(true).try_init()?;
    } else {
        builder.finish().try_init()?;
    }

    Ok(())
}
