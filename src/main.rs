use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use tokio::signal;
use tokio::task::JoinError;
use tracing::info;
use tracing_subscriber::EnvFilter;

use rpp_chain::api;
use rpp_chain::config::NodeConfig;
use rpp_chain::crypto::{generate_keypair, save_keypair};
use rpp_chain::node::Node;

#[derive(Parser)]
#[command(author, version, about = "Production-ready RPP blockchain node")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the node using the provided configuration file
    Start {
        #[arg(short, long, default_value = "config/node.toml")]
        config: PathBuf,
    },
    /// Generate a default node configuration file
    GenerateConfig {
        #[arg(short, long, default_value = "config/node.toml")]
        path: PathBuf,
    },
    /// Generate a new Ed25519 keypair for the node
    Keygen {
        #[arg(short, long, default_value = "keys/node.toml")]
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Start { config } => start_node(config).await?,
        Commands::GenerateConfig { path } => generate_config(path)?,
        Commands::Keygen { path } => keygen(path)?,
    }

    Ok(())
}

async fn start_node(config_path: PathBuf) -> Result<()> {
    let config = if config_path.exists() {
        NodeConfig::load(&config_path)?
    } else {
        let config = NodeConfig::default();
        config.save(&config_path)?;
        config
    };

    let rpc_addr = config.rpc_listen;
    let node = Node::new(config)?;
    let handle = node.handle();
    let node_task = tokio::spawn(async move { node.start().await });
    let api_task = tokio::spawn(async move { api::serve(handle.clone(), rpc_addr).await });

    let result = tokio::select! {
        res = node_task => handle_join(res),
        res = api_task => handle_join(res),
        _ = signal::ctrl_c() => {
            info!("shutdown signal received");
            Ok(())
        }
    };

    result?;
    Ok(())
}

fn generate_config(path: PathBuf) -> Result<()> {
    let config = NodeConfig::default();
    config.ensure_directories()?;
    config.save(&path)?;
    info!(?path, "wrote default configuration");
    Ok(())
}

fn keygen(path: PathBuf) -> Result<()> {
    let keypair = generate_keypair();
    save_keypair(&path, &keypair)?;
    info!(?path, "generated node keypair");
    Ok(())
}

fn handle_join(result: Result<rpp_chain::errors::ChainResult<()>, JoinError>) -> Result<()> {
    let inner = result?;
    inner?;
    Ok(())
}
