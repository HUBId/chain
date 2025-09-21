use std::path::PathBuf;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use tokio::signal;
use tokio::task::JoinError;
use tracing::info;
use tracing_subscriber::EnvFilter;

use rpp_chain::api;
use rpp_chain::config::NodeConfig;
use rpp_chain::crypto::{generate_keypair, generate_vrf_keypair, save_keypair, save_vrf_keypair};
use rpp_chain::migration;
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
        #[arg(long, default_value = "keys/vrf.toml")]
        vrf_path: PathBuf,
    },
    /// Upgrade the on-disk storage schema to the latest format
    Migrate {
        #[arg(short, long, default_value = "config/node.toml")]
        config: PathBuf,
        #[arg(long, default_value_t = false)]
        dry_run: bool,
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
        Commands::Keygen { path, vrf_path } => keygen(path, vrf_path)?,
        Commands::Migrate { config, dry_run } => migrate_storage(config, dry_run)?,
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

fn keygen(path: PathBuf, vrf_path: PathBuf) -> Result<()> {
    let keypair = generate_keypair();
    save_keypair(&path, &keypair)?;
    let vrf_keypair = generate_vrf_keypair()?;
    save_vrf_keypair(&vrf_path, &vrf_keypair)?;
    info!(?path, ?vrf_path, "generated node and VRF keypairs");
    Ok(())
}

fn migrate_storage(config_path: PathBuf, dry_run: bool) -> Result<()> {
    let config = if config_path.exists() {
        NodeConfig::load(&config_path)?
    } else {
        NodeConfig::default()
    };
    let db_path = config.data_dir.join("db");
    if !db_path.exists() {
        return Err(anyhow!(
            "storage directory {:?} does not exist; nothing to migrate",
            db_path
        ));
    }

    let report = migration::migrate_storage(&db_path, dry_run)?;

    if report.is_noop() {
        info!(
            ?db_path,
            version = report.from_version,
            "storage schema already up to date"
        );
    } else if dry_run {
        info!(
            ?db_path,
            upgraded = report.upgraded_blocks,
            from = report.from_version,
            to = report.to_version,
            "dry run completed; re-run without --dry-run to persist changes"
        );
    } else {
        info!(
            ?db_path,
            upgraded = report.upgraded_blocks,
            from = report.from_version,
            to = report.to_version,
            "storage migration completed"
        );
    }

    Ok(())
}

fn handle_join(result: Result<rpp_chain::errors::ChainResult<()>, JoinError>) -> Result<()> {
    let inner = result?;
    inner?;
    Ok(())
}
