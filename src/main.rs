use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use clap::{Args, Parser, Subcommand};
use parking_lot::RwLock;
use tokio::runtime::Builder;
use tokio::signal;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::info;
use tracing_subscriber::EnvFilter;

use rpp_chain::api;
use rpp_chain::config::{NodeConfig, WalletConfig};
use rpp_chain::crypto::{
    generate_keypair, generate_vrf_keypair, load_or_generate_keypair, save_keypair,
    save_vrf_keypair,
};
use rpp_chain::migration;
use rpp_chain::node::{Node, NodeHandle};
use rpp_chain::orchestration::PipelineOrchestrator;
use rpp_chain::runtime::node_runtime::node::NodeRuntimeConfig;
use rpp_chain::runtime::node_runtime::{NodeHandle as P2pHandle, NodeInner as P2pNode};
#[cfg(feature = "vendor_electrs")]
use rpp_chain::runtime::sync::{
    PayloadProvider, ReconstructionRequest, RuntimeRecursiveProofVerifier,
};
use rpp_chain::runtime::wallet::rpc::AuthToken;
use rpp_chain::runtime::wallet::runtime::{
    NodeConnector as WalletNodeConnector, WalletRuntime, WalletRuntimeConfig, WalletRuntimeHandle,
};
use rpp_chain::runtime::wallet::sync::DeterministicSync;
use rpp_chain::runtime::{RuntimeMetrics, RuntimeMode, RuntimeProfile};
use rpp_chain::storage::Storage;
#[cfg(feature = "vendor_electrs")]
use rpp_chain::types::BlockPayload;
use rpp_chain::wallet::Wallet;

use rpp_chain::errors::ChainResult;
#[cfg(feature = "vendor_electrs")]
use rpp_chain::config::ElectrsConfig;
#[cfg(feature = "vendor_electrs")]
use rpp_chain::errors::ChainError;
use rpp_chain::gossip::{spawn_node_event_worker, NodeGossipProcessor};
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::firewood_adapter::RuntimeAdapters;
#[cfg(feature = "vendor_electrs")]
use rpp_wallet::vendor::electrs::init::{initialize, ElectrsHandles};

#[cfg(feature = "vendor_electrs")]
#[derive(Clone)]
struct StoragePayloadProvider {
    storage: Storage,
}

#[cfg(feature = "vendor_electrs")]
impl StoragePayloadProvider {
    fn new(storage: &Storage) -> Self {
        Self {
            storage: storage.clone(),
        }
    }
}

#[derive(Default)]
struct LocalWalletNodeConnector;

impl WalletNodeConnector<Wallet> for LocalWalletNodeConnector {
    fn attach(&self, _wallet: &Wallet) -> ChainResult<()> {
        Ok(())
    }
}

#[cfg(feature = "vendor_electrs")]
impl PayloadProvider for StoragePayloadProvider {
    fn fetch_payload(&self, request: &ReconstructionRequest) -> ChainResult<BlockPayload> {
        let record = self
            .storage
            .read_block_record(request.height)?
            .ok_or_else(|| {
                ChainError::Config(format!(
                    "block payload for height {} not found",
                    request.height
                ))
            })?;
        let payload = record.payload.ok_or_else(|| {
            ChainError::Config(format!(
                "block payload for height {} is not available",
                request.height
            ))
        })?;
        Ok(payload)
    }
}

#[derive(Parser)]
#[command(author, version, about = "Production-ready RPP blockchain node")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Debug, Clone)]
struct StartArgs {
    /// Select the runtime mode (node, wallet, hybrid, validator)
    #[arg(long, value_enum, default_value_t = RuntimeMode::Node)]
    mode: RuntimeMode,
    /// Optional runtime profile to apply (resolves config paths and default mode)
    #[arg(long)]
    profile: Option<String>,
    /// Override the node configuration file path
    #[arg(long)]
    node_config: Option<PathBuf>,
    /// Override the wallet configuration file path
    #[arg(long)]
    wallet_config: Option<PathBuf>,
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
    let resolved = args.resolve()?;
    let runtime_mode = Arc::new(RwLock::new(resolved.mode));
    let runtime_metrics = RuntimeMetrics::noop();
    let mut node_handle = None;
    let mut node_task: Option<JoinHandle<Result<()>>> = None;
    let mut p2p_handle: Option<P2pHandle> = None;
    let mut p2p_task: Option<JoinHandle<Result<()>>> = None;
    let mut rpc_addr = None;
    let mut rpc_auth_token: Option<String> = None;
    let mut rpc_allowed_origin: Option<String> = None;
    let mut orchestrator_instance: Option<Arc<PipelineOrchestrator>> = None;
    let mut orchestrator_shutdown: Option<watch::Receiver<bool>> = None;
    let mut gossip_task: Option<JoinHandle<Result<()>>> = None;
    let mut rpc_requests_per_minute: Option<NonZeroU64> = None;
    let mut wallet_runtime_handle: Option<WalletRuntimeHandle> = None;

    if let Some(node_config_path) = resolved.node_config.as_ref() {
        let config = load_or_init_node_config(node_config_path, resolved.mode)?;
        let addr = config.rpc_listen;
        rpc_auth_token = config.rpc_auth_token.clone();
        rpc_allowed_origin = config.rpc_allowed_origin.clone();
        let node = Node::new(config.clone(), Arc::clone(&runtime_metrics))?;
        let network_identity = node
            .network_identity_profile()
            .map_err(|err| anyhow!(err))?;
        let mut p2p_config = NodeRuntimeConfig::from(&config);
        p2p_config.metrics = node.runtime_metrics();
        p2p_config.identity = Some(network_identity.into());
        let (p2p_runtime, p2p_runtime_handle) = P2pNode::new(p2p_config)
            .map_err(|err| anyhow!("failed to initialise p2p runtime: {err}"))?;
        let p2p_join = tokio::task::spawn_blocking(move || -> Result<()> {
            let runtime = Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| anyhow!("failed to build p2p executor: {err}"))?;
            runtime
                .block_on(async move { p2p_runtime.run().await })
                .map_err(|err| anyhow!("p2p runtime error: {err}"))?;
            Ok(())
        });
        p2p_handle = Some(p2p_runtime_handle.clone());
        p2p_task = Some(p2p_join);

        let handle = node.handle();
        node_handle = Some(handle.clone());
        handle.attach_p2p(p2p_runtime_handle.clone()).await;
        node_task = Some(tokio::spawn(async move {
            node.start().await.map_err(|err| anyhow!(err))
        }));
        rpc_addr = Some(addr);
        rpc_requests_per_minute = config.rpc_requests_per_minute.and_then(NonZeroU64::new);

        let (orchestrator, shutdown_rx) =
            PipelineOrchestrator::new(handle.clone(), p2p_handle.clone());
        let orchestrator = Arc::new(orchestrator);
        orchestrator.spawn(shutdown_rx.clone());
        orchestrator_instance = Some(orchestrator);
        orchestrator_shutdown = Some(shutdown_rx);

        if let Some(p2p) = p2p_handle.as_ref() {
            let events = p2p.subscribe();
            let proof_storage_path = config.proof_cache_dir.join("gossip_proofs.json");
            let processor = Arc::new(NodeGossipProcessor::new(handle.clone(), proof_storage_path));
            let shutdown = orchestrator_shutdown.as_ref().map(|rx| rx.clone());
            gossip_task = Some(spawn_node_event_worker(events, processor, shutdown));
        }
    }

    let mut wallet_instance: Option<Arc<Wallet>> = None;
    if let Some(wallet_config_path) = resolved.wallet_config.as_ref() {
        let config = load_or_init_wallet_config(wallet_config_path)?;
        config.ensure_directories()?;
        let storage = if let Some(handle) = &node_handle {
            handle.storage()
        } else {
            let db_path = config.data_dir.join("db");
            Storage::open(&db_path)?
        };
        let keypair = load_or_generate_keypair(&config.wallet.keys.key_path)?;
        #[cfg(feature = "vendor_electrs")]
        let mut electrs_context: Option<(ElectrsConfig, ElectrsHandles)> = None;
        #[cfg(feature = "vendor_electrs")]
        if let Some(cfg) = config.electrs.clone() {
            let firewood_dir = config.electrs_firewood_dir();
            let index_dir = config.electrs_index_dir();
            let runtime_adapters = if let (Some(handle), Some(orchestrator)) =
                (&node_handle, orchestrator_instance.as_ref())
            {
                let storage_arc = Arc::new(storage.clone());
                let provider = Arc::new(StoragePayloadProvider::new(&storage));
                let verifier = Arc::new(RuntimeRecursiveProofVerifier::default());
                Some(RuntimeAdapters::new(
                    storage_arc,
                    handle.clone(),
                    orchestrator.as_ref().clone(),
                    provider,
                    verifier,
                ))
            } else {
                None
            };
            let handles = initialize(&cfg, &firewood_dir, &index_dir, runtime_adapters)?;
            electrs_context = Some((cfg, handles));
        }
        let wallet_metrics = Arc::clone(&runtime_metrics);
        let wallet = {
            #[cfg(feature = "vendor_electrs")]
            {
                if let Some((cfg, handles)) = electrs_context {
                    Arc::new(
                        Wallet::with_electrs(
                            storage,
                            keypair,
                            Arc::clone(&wallet_metrics),
                            cfg,
                            handles,
                        )
                        .map_err(|err| anyhow!(err))?,
                    )
                } else {
                    Arc::new(Wallet::new(storage, keypair, Arc::clone(&wallet_metrics)))
                }
            }
            #[cfg(not(feature = "vendor_electrs"))]
            {
                Arc::new(Wallet::new(storage, keypair, wallet_metrics))
            }
        };
        let mut runtime_config = WalletRuntimeConfig::new(config.wallet.rpc.listen);
        runtime_config.allowed_origin = config.wallet.rpc.allowed_origin.clone();
        if config.wallet.auth.enabled {
            runtime_config.auth_token = config
                .wallet
                .auth
                .token
                .clone()
                .map(AuthToken::new);
        }
        runtime_config.requests_per_minute = config
            .wallet
            .rpc
            .requests_per_minute
            .and_then(NonZeroU64::new);

        let sync_provider = Box::new(DeterministicSync::new(wallet.address().to_string()));
        let connector: Option<Box<dyn WalletNodeConnector<Wallet>>> =
            if resolved.mode.includes_node() {
                Some(Box::new(LocalWalletNodeConnector::default()))
            } else {
                None
            };

        let runtime_handle = WalletRuntime::start(
            Arc::clone(&wallet),
            runtime_config,
            Arc::clone(&runtime_metrics),
            sync_provider,
            connector,
        )
        .map_err(|err| anyhow!(err))?;

        if rpc_auth_token.is_none() {
            rpc_auth_token = runtime_handle
                .auth_token()
                .map(|token| token.secret().to_string());
        }
        if rpc_allowed_origin.is_none() {
            rpc_allowed_origin = runtime_handle.allowed_origin().cloned();
        }
        if rpc_requests_per_minute.is_none() {
            rpc_requests_per_minute = runtime_handle.requests_per_minute();
        }
        if rpc_addr.is_none() {
            rpc_addr = Some(runtime_handle.listen_addr());
        }

        wallet_instance = Some(runtime_handle.wallet());
        wallet_runtime_handle = Some(runtime_handle);
    }

    if node_handle.is_none() && wallet_instance.is_none() {
        return Err(anyhow!(
            "runtime mode {:?} requires node and/or wallet components",
            resolved.mode
        ));
    }

    let rpc_addr = rpc_addr.ok_or_else(|| anyhow!("no runtime role selected"))?;

    let wallet_runtime_active = wallet_instance.is_some();
    let context = api::ApiContext::new(
        runtime_mode.clone(),
        node_handle.clone(),
        wallet_instance.clone(),
        orchestrator_instance.clone(),
        rpc_requests_per_minute,
        rpc_auth_token.is_some(),
        wallet_runtime_active,
    );
    let api_task = tokio::spawn(async move {
        api::serve(
            context,
            rpc_addr,
            rpc_auth_token.clone(),
            rpc_allowed_origin.clone(),
        )
        .await
        .map_err(|err| anyhow!(err))
    });

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

    if resolved.mode == RuntimeMode::Validator {
        if let (Some(handle), Some(wallet)) = (&node_handle, &wallet_instance) {
            if let Some(shutdown_rx) = orchestrator_shutdown.take() {
                spawn_validator_daemon(
                    handle.clone(),
                    Arc::clone(wallet),
                    runtime_mode.clone(),
                    shutdown_rx,
                );
            } else {
                info!("validator mode requested but orchestrator shutdown channel unavailable");
            }
        } else {
            info!(
                "validator mode requested without both node and wallet; background tasks not started"
            );
        }
    }

    run_until_shutdown(
        node_task,
        p2p_task,
        api_task,
        orchestrator_instance,
        p2p_handle,
        gossip_task,
        wallet_runtime_handle,
    )
    .await
}

fn generate_config(path: PathBuf) -> Result<()> {
    let config = node_config_template_for_path(&path, RuntimeMode::Node);
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
        node_config_template_for_path(&config_path, RuntimeMode::Node)
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

fn load_or_init_node_config(path: &Path, mode: RuntimeMode) -> Result<NodeConfig> {
    if path.exists() {
        let config = NodeConfig::load(path)?;
        config.validate()?;
        Ok(config)
    } else {
        let config = node_config_template_for_path(path, mode);
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

fn node_config_template_for_path(path: &Path, mode: RuntimeMode) -> NodeConfig {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();

    match file_name {
        "validator.toml" => NodeConfig::for_validator(),
        "hybrid.toml" => NodeConfig::for_hybrid(),
        "node.toml" => NodeConfig::for_node(),
        _ => NodeConfig::for_mode(mode),
    }
}

impl StartArgs {
    fn resolve(&self) -> Result<ResolvedRuntime> {
        let mut mode = self.mode;
        let mut node_config = self.node_config.clone();
        let mut wallet_config = self.wallet_config.clone();

        if let Some(profile_name) = &self.profile {
            let profile = RuntimeProfile::load(profile_name)
                .map_err(|err| anyhow!("failed to load runtime profile '{profile_name}': {err}"))?;
            if let Some(profile_mode) = profile.mode() {
                mode = profile_mode;
            }
            if let Some(path) = profile.node_config_path() {
                node_config = Some(path);
            }
            if let Some(path) = profile.wallet_config_path() {
                wallet_config = Some(path);
            }
        }

        if mode.includes_node() && node_config.is_none() {
            if let Some(default_path) = mode.default_node_config_path() {
                node_config = Some(PathBuf::from(default_path));
            }
        }
        if mode.includes_wallet() && wallet_config.is_none() {
            if let Some(default_path) = mode.default_wallet_config_path() {
                wallet_config = Some(PathBuf::from(default_path));
            }
        }

        Ok(ResolvedRuntime {
            mode,
            node_config,
            wallet_config,
        })
    }
}

struct ResolvedRuntime {
    mode: RuntimeMode,
    node_config: Option<PathBuf>,
    wallet_config: Option<PathBuf>,
}

fn spawn_validator_daemon(
    node: NodeHandle,
    wallet: Arc<Wallet>,
    mode: Arc<RwLock<RuntimeMode>>,
    shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        validator_daemon(node, wallet, mode, shutdown_rx).await;
    });
}

async fn validator_daemon(
    node: NodeHandle,
    wallet: Arc<Wallet>,
    mode: Arc<RwLock<RuntimeMode>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    use tokio::time::{interval, Duration};
    use tracing::{info, warn};

    let mut ticker = interval(Duration::from_secs(3600));
    loop {
        tokio::select! {
            change = shutdown_rx.changed() => {
                match change {
                    Ok(_) => {
                        if *shutdown_rx.borrow() {
                            info!("validator daemon shutting down");
                            break;
                        }
                    }
                    Err(_) => {
                        info!("validator daemon shutdown channel closed");
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                let current_mode = *mode.read();
                if !current_mode.includes_node() || !current_mode.includes_wallet() {
                    continue;
                }

                match wallet.generate_uptime_proof() {
                    Ok(proof) => match node.submit_uptime_proof(proof.clone()) {
                        Ok(credited) => {
                            info!(
                                credited_hours = credited,
                                "validator uptime proof submitted"
                            );
                        }
                        Err(err) => {
                            warn!(?err, "failed to submit validator uptime proof");
                        }
                    },
                    Err(err) => warn!(?err, "failed to generate validator uptime proof"),
                }

                match node.validator_telemetry() {
                    Ok(snapshot) => {
                        info!(
                            height = snapshot.node.height,
                            pending_txs = snapshot.mempool.transactions,
                            "validator telemetry snapshot"
                        );
                    }
                    Err(err) => warn!(?err, "failed to collect validator telemetry"),
                }
            }
        }
    }
}

async fn run_until_shutdown(
    node_task: Option<JoinHandle<Result<()>>>,
    p2p_task: Option<JoinHandle<Result<()>>>,
    api_task: JoinHandle<Result<()>>,
    orchestrator: Option<Arc<PipelineOrchestrator>>,
    p2p_handle: Option<P2pHandle>,
    gossip_task: Option<JoinHandle<Result<()>>>,
    wallet_runtime: Option<WalletRuntimeHandle>,
) -> Result<()> {
    let (completion_tx, mut completion_rx) = mpsc::unbounded_channel::<Result<()>>();

    if let Some(task) = node_task {
        spawn_task_forwarder(&completion_tx, task);
    }
    if let Some(task) = p2p_task {
        spawn_task_forwarder(&completion_tx, task);
    }
    if let Some(task) = gossip_task {
        spawn_task_forwarder(&completion_tx, task);
    }
    spawn_task_forwarder(&completion_tx, api_task);

    drop(completion_tx);

    let mut shutdown_requested = false;

    let mut outcome = tokio::select! {
        Some(result) = completion_rx.recv() => result,
        _ = signal::ctrl_c() => {
            info!("shutdown signal received");
            shutdown_requested = true;
            Ok(())
        }
    };

    if let Some(orchestrator) = orchestrator.as_ref() {
        orchestrator.shutdown();
    }

    if let Some(handle) = wallet_runtime.as_ref() {
        handle
            .shutdown()
            .await
            .map_err(|err| anyhow!(err))?;
    }

    if shutdown_requested {
        if let Some(handle) = p2p_handle {
            handle
                .shutdown()
                .await
                .map_err(|err| anyhow!("failed to shut down p2p runtime: {err}"))?;
        }
    }

    while let Some(result) = completion_rx.recv().await {
        if outcome.is_ok() && result.is_err() {
            outcome = result;
        }
    }

    outcome?;
    Ok(())
}

fn spawn_task_forwarder(tx: &mpsc::UnboundedSender<Result<()>>, task: JoinHandle<Result<()>>) {
    let tx = tx.clone();
    tokio::spawn(async move {
        let result = match task.await {
            Ok(inner) => inner,
            Err(err) => Err(anyhow!("task join error: {err}")),
        };
        let _ = tx.send(result);
    });
}
