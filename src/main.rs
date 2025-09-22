use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use clap::{Args, Parser, Subcommand};
use tokio::signal;
use tokio::task::{JoinError, JoinHandle};
use tracing::info;
use tracing_subscriber::EnvFilter;

use rpp_chain::api;
use rpp_chain::config::{NodeConfig, WalletConfig};
use rpp_chain::crypto::{
    generate_keypair, generate_vrf_keypair, load_or_generate_keypair, save_keypair,
    save_vrf_keypair,
};
use rpp_chain::migration;
use rpp_chain::node::Node;
use rpp_chain::storage::Storage;
use rpp_chain::wallet::Wallet;

#[derive(Parser)]
#[command(author, version, about = "Production-ready RPP blockchain node")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Debug)]
struct StartArgs {
    /// Enable the embedded wallet runtime (Electrum-style UI + proofs)
    #[arg(long, default_value_t = false)]
    wallet: bool,
    /// Enable the full node runtime (consensus, block production, RPC)
    #[arg(long, default_value_t = false)]
    node: bool,
    /// Path to the node configuration file
    #[arg(long, default_value = "config/node.toml")]
    node_config: PathBuf,
    /// Path to the wallet configuration file
    #[arg(long, default_value = "config/wallet.toml")]
    wallet_config: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the runtime with wallet and/or node roles
    Start(StartArgs),
    /// Generate a default node configuration file
    GenerateConfig {
        #[arg(short, long, default_value = "config/node.toml")]
        path: PathBuf,
    },
    /// Generate a default wallet configuration file
    GenerateWalletConfig {
        #[arg(short, long, default_value = "config/wallet.toml")]
        path: PathBuf,
    },
    /// Generate a new Ed25519 keypair for the node
    Keygen {
        #[arg(short, long, default_value = "keys/node.toml")]
        path: PathBuf,
        #[arg(long, default_value = "keys/vrf.toml")]
        vrf_path: PathBuf,
    },
    /// Generate a new Ed25519 keypair for the wallet runtime
    WalletKeygen {
        #[arg(short, long, default_value = "keys/node.toml")]
        path: PathBuf,
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
        Commands::Start(args) => start_runtime(args).await?,
        Commands::GenerateConfig { path } => generate_config(path)?,
        Commands::GenerateWalletConfig { path } => generate_wallet_config(path)?,
        Commands::Keygen { path, vrf_path } => keygen(path, vrf_path)?,
        Commands::WalletKeygen { path } => wallet_keygen(path)?,
        Commands::Migrate { config, dry_run } => migrate_storage(config, dry_run)?,
    }

    Ok(())
}

async fn start_runtime(args: StartArgs) -> Result<()> {
    let enable_wallet = args.wallet;
    let enable_node = args.node || (!args.wallet && !args.node);

    let mut node_handle = None;
    let mut node_task = None;
    let mut rpc_addr = None;

    if enable_node {
        let config = load_or_init_node_config(&args.node_config)?;
        let addr = config.rpc_listen;
        let node = Node::new(config)?;
        let handle = node.handle();
        node_handle = Some(handle.clone());
        node_task = Some(tokio::spawn(async move { node.start().await }));
        rpc_addr = Some(addr);
    }

    let mut wallet_instance = None;
    if enable_wallet {
        let config = load_or_init_wallet_config(&args.wallet_config)?;
        config.ensure_directories()?;
        let storage = if let Some(handle) = &node_handle {
            handle.storage()
        } else {
            let db_path = config.data_dir.join("db");
            Storage::open(&db_path)?
        };
        let keypair = load_or_generate_keypair(&config.key_path)?;
        let wallet = Wallet::new(storage, keypair);
        wallet_instance = Some(wallet);
        if rpc_addr.is_none() {
            rpc_addr = Some(config.rpc_listen);
        }
    }

    let rpc_addr = rpc_addr.ok_or_else(|| anyhow!("no runtime role selected"))?;

    let context = api::ApiContext::new(node_handle.clone(), wallet_instance.clone());
    let api_task = tokio::spawn(async move { api::serve(context, rpc_addr).await });

    if let Some(wallet) = &wallet_instance {
        info!(address = %wallet.address(), "wallet runtime initialised");
        if let Some(handle) = &node_handle {
            if wallet.address() != handle.address() {
                info!(
                    wallet = %wallet.address(),
                    node = %handle.address(),
                    "wallet/node identity mismatch; ensure shared keys for validator mode"
                );
            }
        }
    }
    if let Some(handle) = &node_handle {
        info!(address = %handle.address(), "node runtime initialised");
    }

    run_until_shutdown(node_task, api_task).await
}

fn generate_config(path: PathBuf) -> Result<()> {
    let config = NodeConfig::default();
    config.ensure_directories()?;
    config.save(&path)?;
    info!(?path, "wrote default configuration");
    Ok(())
}

fn generate_wallet_config(path: PathBuf) -> Result<()> {
    let config = WalletConfig::default();
    config.ensure_directories()?;
    config.save(&path)?;
    info!(?path, "wrote default wallet configuration");
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

fn wallet_keygen(path: PathBuf) -> Result<()> {
    let keypair = generate_keypair();
    save_keypair(&path, &keypair)?;
    info!(?path, "generated wallet keypair");
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

fn load_or_init_node_config(path: &Path) -> Result<NodeConfig> {
    if path.exists() {
        Ok(NodeConfig::load(path)?)
    } else {
        let config = NodeConfig::default();
        config.save(path)?;
        Ok(config)
    }
}

fn load_or_init_wallet_config(path: &Path) -> Result<WalletConfig> {
    if path.exists() {
        Ok(WalletConfig::load(path)?)
    } else {
        let config = WalletConfig::default();
        config.save(path)?;
        Ok(config)
    }
}

async fn run_until_shutdown(
    node_task: Option<JoinHandle<rpp_chain::errors::ChainResult<()>>>,
    api_task: JoinHandle<rpp_chain::errors::ChainResult<()>>,
) -> Result<()> {
    if let Some(node_task) = node_task {
        let result = tokio::select! {
            res = node_task => handle_join(res),
            res = api_task => handle_join(res),
            _ = signal::ctrl_c() => {
                info!("shutdown signal received");
                Ok(())
            }
        };
        result?;
    } else {
        let result = tokio::select! {
            res = api_task => handle_join(res),
            _ = signal::ctrl_c() => {
                info!("shutdown signal received");
                Ok(())
            }
        };
        result?;
    }
    Ok(())
}

fn handle_join(result: Result<rpp_chain::errors::ChainResult<()>, JoinError>) -> Result<()> {
    let inner = result?;
    inner?;
    Ok(())
}
