use std::env;
use std::fmt;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use clap::Args;
use opentelemetry::global;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::runtime::Tokio;
use opentelemetry_sdk::trace::{self, BatchConfig, Tracer};
use opentelemetry_sdk::Resource;
use parking_lot::RwLock;
use tokio::task::{JoinError, JoinHandle};
use tonic::metadata::{MetadataMap, MetadataValue};
use tracing::{error, info, info_span, warn};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::Layer;

use rpp_chain::api::ApiContext;
use rpp_chain::config::{NodeConfig, WalletConfig};
use rpp_chain::crypto::load_or_generate_keypair;
use rpp_chain::node::{Node, NodeHandle};
use rpp_chain::orchestration::PipelineOrchestrator;
use rpp_chain::runtime::RuntimeMode;
use rpp_chain::storage::Storage;
use rpp_chain::wallet::Wallet;

pub use rpp_chain::runtime::RuntimeMode;

pub type BootstrapResult<T> = std::result::Result<T, BootstrapError>;

#[derive(Debug)]
pub enum BootstrapError {
    Configuration(anyhow::Error),
    Startup(anyhow::Error),
    Runtime(anyhow::Error),
}

impl BootstrapError {
    pub fn configuration<E>(error: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::Configuration(error.into())
    }

    pub fn startup<E>(error: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::Startup(error.into())
    }

    pub fn runtime<E>(error: E) -> Self
    where
        E: Into<anyhow::Error>,
    {
        Self::Runtime(error.into())
    }

    pub fn exit_code(&self) -> i32 {
        match self {
            BootstrapError::Configuration(_) => 2,
            BootstrapError::Startup(_) => 3,
            BootstrapError::Runtime(_) => 4,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            BootstrapError::Configuration(_) => "configuration",
            BootstrapError::Startup(_) => "startup",
            BootstrapError::Runtime(_) => "runtime",
        }
    }

    pub fn source(&self) -> &anyhow::Error {
        match self {
            BootstrapError::Configuration(err)
            | BootstrapError::Startup(err)
            | BootstrapError::Runtime(err) => err,
        }
    }
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{0} error: {1}", self.kind(), self.source())
    }
}

impl std::error::Error for BootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source().as_ref())
    }
}

/// Shared CLI arguments used across runtime entrypoints.
#[derive(Debug, Clone, Args)]
pub struct RunArgs {
    /// Optional path to a node configuration file loaded before starting the runtime
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Optional path to a wallet configuration file loaded before starting the runtime
    #[arg(long, value_name = "PATH")]
    pub wallet_config: Option<PathBuf>,

    /// Override the data directory defined in the node configuration
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Override the RPC listen address defined in the node configuration
    #[arg(long, value_name = "SOCKET")]
    pub rpc_listen: Option<std::net::SocketAddr>,

    /// Override the RPC authentication token defined in the node configuration
    #[arg(long, value_name = "TOKEN")]
    pub rpc_auth_token: Option<String>,

    /// Override the telemetry endpoint defined in the node configuration
    #[arg(long, value_name = "URL")]
    pub telemetry_endpoint: Option<String>,

    /// Override the telemetry authentication token defined in the node configuration
    #[arg(long, value_name = "TOKEN")]
    pub telemetry_auth_token: Option<String>,

    /// Override the telemetry sample interval (seconds) defined in the node configuration
    #[arg(long, value_name = "SECONDS")]
    pub telemetry_sample_interval: Option<u64>,

    /// Override the log level (also respects RUST_LOG)
    #[arg(long, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Emit logs in JSON format
    #[arg(long)]
    pub log_json: bool,

    /// Validate configuration and exit without starting the runtime
    #[arg(long)]
    pub dry_run: bool,

    /// Persist the resulting configuration into the current working directory
    #[arg(long)]
    pub write_config: bool,
}

impl RunArgs {
    pub fn into_bootstrap_options(self, mode: RuntimeMode) -> BootstrapOptions {
        let RunArgs {
            config,
            wallet_config,
            data_dir,
            rpc_listen,
            rpc_auth_token,
            telemetry_endpoint,
            telemetry_auth_token,
            telemetry_sample_interval,
            log_level,
            log_json,
            dry_run,
            write_config,
        } = self;

        let node_config = if mode.includes_node() {
            config.clone()
        } else {
            None
        };

        let wallet_config = if mode.includes_wallet() {
            match mode {
                RuntimeMode::Wallet => wallet_config.or(config),
                _ => wallet_config,
            }
        } else {
            None
        };

        BootstrapOptions {
            node_config,
            wallet_config,
            data_dir,
            rpc_listen,
            rpc_auth_token,
            telemetry_endpoint,
            telemetry_auth_token,
            telemetry_sample_interval,
            log_level,
            log_json,
            dry_run,
            write_config,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BootstrapOptions {
    pub node_config: Option<PathBuf>,
    pub wallet_config: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub rpc_listen: Option<std::net::SocketAddr>,
    pub rpc_auth_token: Option<String>,
    pub telemetry_endpoint: Option<String>,
    pub telemetry_auth_token: Option<String>,
    pub telemetry_sample_interval: Option<u64>,
    pub log_level: Option<String>,
    pub log_json: bool,
    pub dry_run: bool,
    pub write_config: bool,
}

pub async fn bootstrap(mode: RuntimeMode, options: BootstrapOptions) -> BootstrapResult<()> {
    if let Ok(request) = env::var("RPP_NODE_TEST_FAILURE_MODE") {
        match request.as_str() {
            "startup" => {
                return Err(BootstrapError::startup(anyhow!(
                    "simulated pipeline startup failure"
                )));
            }
            "panic" => {
                panic!("simulated panic requested via RPP_NODE_TEST_FAILURE_MODE");
            }
            _ => {}
        }
    }

    let mut node_bundle =
        load_node_configuration(mode, &options).map_err(BootstrapError::configuration)?;
    if let Some(bundle) = node_bundle.as_mut() {
        apply_overrides(&mut bundle.value, &options);
    }
    let wallet_bundle =
        load_wallet_configuration(mode, &options).map_err(BootstrapError::configuration)?;

    ensure_listener_conflicts(mode, node_bundle.as_ref(), wallet_bundle.as_ref())
        .map_err(BootstrapError::configuration)?;

    let node_metadata = node_bundle
        .as_ref()
        .and_then(|bundle| bundle.metadata.as_ref().cloned());
    let wallet_metadata = wallet_bundle
        .as_ref()
        .and_then(|bundle| bundle.metadata.as_ref().cloned());

    let mut default_config = None;
    let tracing_config = if let Some(bundle) = node_bundle.as_ref() {
        &bundle.value
    } else {
        default_config = Some(NodeConfig::default());
        default_config.as_ref().unwrap()
    };

    let config_source = node_metadata
        .as_ref()
        .map(|metadata| metadata.source.as_str())
        .unwrap_or_else(|| {
            if mode.includes_node() {
                ConfigSource::Default.as_str()
            } else {
                "none"
            }
        });

    let _telemetry_guard = init_tracing(
        tracing_config,
        node_metadata.as_ref(),
        options.log_level.clone(),
        options.log_json,
        mode,
        config_source,
        options.dry_run,
    )
    .with_context(|| "failed to initialise logging")
    .map_err(BootstrapError::startup)?;

    info!(
        target = "bootstrap",
        mode = mode.as_str(),
        config_source = config_source,
        dry_run = options.dry_run,
        "bootstrap configuration resolved"
    );

    if let Some(metadata) = node_metadata.as_ref() {
        info!(
            target = "config",
            role = "node",
            source = metadata.source.as_str(),
            path = %metadata.path.display(),
            "resolved node configuration"
        );
    }
    if let Some(metadata) = wallet_metadata.as_ref() {
        info!(
            target = "config",
            role = "wallet",
            source = metadata.source.as_str(),
            path = %metadata.path.display(),
            "resolved wallet configuration"
        );
    }

    if options.write_config {
        if let Some(bundle) = node_bundle.as_ref() {
            let override_path = node_metadata
                .as_ref()
                .map(|metadata| metadata.path.as_path());
            persist_node_config(mode, &bundle.value, override_path)
                .map_err(BootstrapError::configuration)?;
        }
    }

    if options.dry_run {
        info!(
            mode = %mode.as_str(),
            node_config = node_metadata
                .as_ref()
                .map(|metadata| metadata.path.display().to_string()),
            node_config_source = node_metadata
                .as_ref()
                .map(|metadata| metadata.source.as_str()),
            wallet_config = wallet_metadata
                .as_ref()
                .map(|metadata| metadata.path.display().to_string()),
            wallet_config_source = wallet_metadata
                .as_ref()
                .map(|metadata| metadata.source.as_str()),
            "dry run completed"
        );
        return Ok(());
    }

    let runtime_mode = Arc::new(RwLock::new(mode));
    let mut node_handle: Option<NodeHandle> = None;
    let mut node_runtime: Option<JoinHandle<()>> = None;
    let mut rpc_addr: Option<std::net::SocketAddr> = None;
    let mut rpc_auth: Option<String> = None;
    let mut rpc_origin: Option<String> = None;
    let mut rpc_requests_per_minute: Option<NonZeroU64> = None;
    let mut orchestrator_instance: Option<Arc<PipelineOrchestrator>> = None;

    if let Some(bundle) = node_bundle.take() {
        let config = bundle.value;
        let preview_node = Node::new(config.clone())
            .context("failed to build node with the provided configuration")
            .map_err(BootstrapError::startup)?;
        info!(
            address = %preview_node.handle().address(),
            "node initialised"
        );
        drop(preview_node);

        let (handle, runtime) = NodeHandle::start(config.clone())
            .await
            .context("failed to start node runtime")
            .map_err(BootstrapError::startup)?;

        info!(address = %handle.address(), "node runtime started");
        info!(target = "rpc", listen = %config.rpc_listen, "rpc endpoint configured");
        if config.rollout.telemetry.enabled {
            if let Some(endpoint) = &config.rollout.telemetry.endpoint {
                info!(
                    target = "telemetry",
                    endpoint = %endpoint,
                    sample_interval_secs = config.rollout.telemetry.sample_interval_secs,
                    "telemetry endpoint configured"
                );
            } else {
                info!(
                    target = "telemetry",
                    sample_interval_secs = config.rollout.telemetry.sample_interval_secs,
                    "telemetry enabled without explicit endpoint"
                );
            }
        } else {
            info!(target = "telemetry", "telemetry disabled");
        }
        info!(
            target = "p2p",
            listen_addr = %config.p2p.listen_addr,
            "p2p endpoint configured"
        );

        rpc_addr = Some(config.rpc_listen);
        rpc_auth = config.rpc_auth_token.clone();
        rpc_origin = config.rpc_allowed_origin.clone();
        rpc_requests_per_minute = config.rpc_requests_per_minute.and_then(NonZeroU64::new);

        let p2p_handle = handle.p2p_handle();
        let (orchestrator, shutdown_rx) = PipelineOrchestrator::new(handle.clone(), p2p_handle);
        let orchestrator = Arc::new(orchestrator);
        orchestrator.spawn(shutdown_rx);
        info!("pipeline orchestrator started");
        orchestrator_instance = Some(orchestrator.clone());

        node_handle = Some(handle);
        node_runtime = Some(runtime);
    }

    let mut wallet_instance: Option<Arc<Wallet>> = None;
    if let Some(bundle) = wallet_bundle {
        let wallet_config = bundle.value;
        wallet_config
            .ensure_directories()
            .map_err(|err| BootstrapError::startup(anyhow!(err)))?;

        let storage = if let Some(handle) = node_handle.as_ref() {
            handle.storage()
        } else {
            Storage::open(&wallet_config.data_dir.join("db"))
                .map_err(|err| BootstrapError::startup(anyhow!(err)))?
        };
        let keypair = load_or_generate_keypair(&wallet_config.key_path)
            .map_err(|err| BootstrapError::startup(anyhow!(err)))?;
        let wallet = Arc::new(Wallet::new(storage, keypair));
        rpc_addr.get_or_insert(wallet_config.rpc_listen);
        wallet_instance = Some(wallet);
    }

    let rpc_addr = rpc_addr
        .ok_or_else(|| anyhow!("no runtime role selected"))
        .map_err(BootstrapError::configuration)?;
    if node_handle.is_none() {
        info!(target = "rpc", listen = %rpc_addr, "rpc endpoint configured");
    }

    let rpc_context = ApiContext::new(
        Arc::clone(&runtime_mode),
        node_handle.clone(),
        wallet_instance.clone(),
        orchestrator_instance.clone(),
        rpc_requests_per_minute,
        rpc_auth.is_some(),
    );

    let rpc_auth_token = rpc_auth.clone();
    let rpc_allowed_origin = rpc_origin.clone();
    let rpc_task = tokio::spawn(async move {
        if let Err(err) =
            rpp_chain::api::serve(rpc_context, rpc_addr, rpc_auth_token, rpc_allowed_origin).await
        {
            error!(?err, "rpc server terminated");
        }
    });

    if let Some(wallet) = &wallet_instance {
        info!(address = %wallet.address(), "wallet runtime initialised");
    }

    let outcome = match (node_handle.clone(), node_runtime) {
        (Some(handle), Some(runtime)) => wait_for_node_shutdown(handle, runtime).await,
        _ => wait_for_signal_shutdown().await,
    };

    rpc_task.abort();
    if let Err(err) = rpc_task.await {
        if !err.is_cancelled() {
            warn!(?err, "rpc server join failed");
        }
    }

    match outcome {
        ShutdownOutcome::Clean => Ok(()),
        ShutdownOutcome::Errored(err) => Err(BootstrapError::runtime(err)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigSource {
    CommandLine,
    Environment,
    Default,
}

impl ConfigSource {
    fn as_str(&self) -> &'static str {
        match self {
            ConfigSource::CommandLine => "cli",
            ConfigSource::Environment => "env",
            ConfigSource::Default => "default",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            ConfigSource::CommandLine => "the command line",
            ConfigSource::Environment => "the RPP_CONFIG environment variable",
            ConfigSource::Default => "the default search path",
        }
    }
}

#[derive(Clone)]
struct ConfigMetadata {
    path: PathBuf,
    source: ConfigSource,
}

impl ConfigMetadata {
    fn new(path: PathBuf, source: ConfigSource) -> Self {
        Self { path, source }
    }
}

#[derive(Clone)]
struct ResolvedConfigPath {
    path: PathBuf,
    source: ConfigSource,
}

impl ResolvedConfigPath {
    fn into_metadata(self) -> ConfigMetadata {
        ConfigMetadata::new(self.path, self.source)
    }
}

#[derive(Clone, Copy, Debug)]
enum ConfigRole {
    Node,
    Wallet,
}

impl ConfigRole {
    fn as_str(&self) -> &'static str {
        match self {
            ConfigRole::Node => "node",
            ConfigRole::Wallet => "wallet",
        }
    }
}

#[derive(Debug)]
pub enum ConfigurationError {
    Missing {
        role: ConfigRole,
        path: PathBuf,
        source: ConfigSource,
        suggestion: Option<String>,
    },
    Conflict {
        message: String,
    },
}

impl ConfigurationError {
    fn missing(
        role: ConfigRole,
        path: PathBuf,
        source: ConfigSource,
        template: Option<&'static str>,
    ) -> Self {
        let suggestion = template.map(|default| format!("cp {default} {}", path.display()));
        Self::Missing {
            role,
            path,
            source,
            suggestion,
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing {
                role,
                path,
                source,
                suggestion,
            } => {
                let base = format!(
                    "{} configuration not found at {} (resolved from {})",
                    role.as_str(),
                    path.display(),
                    source.description()
                );

                if let Some(suggestion) = suggestion {
                    write!(
                        f,
                        "{}; copy the default template with `{}`",
                        base, suggestion
                    )
                } else {
                    write!(f, "{}", base)
                }
            }
            Self::Conflict { message } => write!(f, "{}", message),
        }
    }
}

impl std::error::Error for ConfigurationError {}

#[derive(Clone)]
struct ConfigBundle<T> {
    value: T,
    metadata: Option<ConfigMetadata>,
}

fn ensure_listener_conflicts(
    mode: RuntimeMode,
    node_bundle: Option<&ConfigBundle<NodeConfig>>,
    wallet_bundle: Option<&ConfigBundle<WalletConfig>>,
) -> Result<()> {
    if !(mode.includes_node() && mode.includes_wallet()) {
        return Ok(());
    }

    let Some(node_bundle) = node_bundle else {
        return Ok(());
    };
    let Some(wallet_bundle) = wallet_bundle else {
        return Ok(());
    };

    let node_metadata = node_bundle.metadata.as_ref();
    let wallet_metadata = wallet_bundle.metadata.as_ref();
    let mut conflicts = Vec::new();

    let node_rpc = node_bundle.value.rpc_listen;
    let wallet_rpc = wallet_bundle.value.rpc_listen;
    if listeners_conflict(node_rpc, wallet_rpc) {
        let node_key = describe_config_key(ConfigRole::Node, node_metadata, "rpc_listen");
        let wallet_key = describe_config_key(ConfigRole::Wallet, wallet_metadata, "rpc_listen");
        conflicts.push(format!(
            "{node_key} ({node_rpc}) and {wallet_key} ({wallet_rpc}) reuse TCP port {}",
            node_rpc.port()
        ));
    }

    if let Some(port) = extract_tcp_port(&node_bundle.value.p2p.listen_addr) {
        if port != 0 && port == wallet_rpc.port() {
            let node_key = describe_config_key(ConfigRole::Node, node_metadata, "p2p.listen_addr");
            let wallet_key = describe_config_key(ConfigRole::Wallet, wallet_metadata, "rpc_listen");
            conflicts.push(format!(
                "{wallet_key} ({wallet_rpc}) reuses TCP port {port}, which is already reserved by {node_key} ({})",
                node_bundle.value.p2p.listen_addr
            ));
        }
    }

    if conflicts.is_empty() {
        Ok(())
    } else {
        let details = conflicts.join("; ");
        Err(ConfigurationError::conflict(format!("listener conflict: {details}")).into())
    }
}

fn describe_config_key(role: ConfigRole, metadata: Option<&ConfigMetadata>, key: &str) -> String {
    match metadata {
        Some(metadata) => format!(
            "{} configuration ({}::{key})",
            role.as_str(),
            metadata.path.display()
        ),
        None => format!("{} configuration (defaults::{key})", role.as_str()),
    }
}

fn listeners_conflict(node: std::net::SocketAddr, wallet: std::net::SocketAddr) -> bool {
    if node.port() != wallet.port() {
        return false;
    }

    if node.ip().is_unspecified() || wallet.ip().is_unspecified() {
        return true;
    }

    node.ip() == wallet.ip()
}

fn extract_tcp_port(multiaddr: &str) -> Option<u16> {
    let mut parts = multiaddr.split('/').filter(|segment| !segment.is_empty());
    while let Some(protocol) = parts.next() {
        let value = parts.next();
        if protocol.eq_ignore_ascii_case("tcp") {
            if let Some(port) = value {
                if let Ok(port) = port.parse::<u16>() {
                    return Some(port);
                }
            }
        }
    }
    None
}

#[derive(Debug)]
enum ShutdownEvent {
    Runtime(std::result::Result<(), JoinError>),
    CtrlC(std::io::Result<()>),
    #[cfg(unix)]
    SigTerm(Option<i32>),
}

#[derive(Debug)]
enum ShutdownOutcome {
    Clean,
    Errored(anyhow::Error),
}

async fn wait_for_node_shutdown(
    handle: NodeHandle,
    mut runtime: JoinHandle<()>,
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

async fn wait_for_signal_shutdown() -> ShutdownOutcome {
    #[cfg(unix)]
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(signal) => signal,
        Err(err) => return ShutdownOutcome::Errored(err.into()),
    };

    let shutdown_event = tokio::select! {
        result = tokio::signal::ctrl_c() => ShutdownEvent::CtrlC(result),
        #[cfg(unix)]
        result = sigterm.recv() => ShutdownEvent::SigTerm(result),
    };

    match shutdown_event {
        ShutdownEvent::CtrlC(result) => match result {
            Ok(()) => info!("received ctrl_c signal"),
            Err(err) => warn!(?err, "failed to listen for ctrl_c"),
        },
        #[cfg(unix)]
        ShutdownEvent::SigTerm(result) => match result {
            Some(_) => info!("received termination signal"),
            None => warn!("termination signal stream closed"),
        },
        ShutdownEvent::Runtime(_) => {}
    }

    ShutdownOutcome::Clean
}

fn load_node_configuration(
    mode: RuntimeMode,
    options: &BootstrapOptions,
) -> Result<Option<ConfigBundle<NodeConfig>>> {
    if !mode.includes_node() {
        return Ok(None);
    }

    let Some(mut resolved) = resolve_node_config_path(mode, options) else {
        return Ok(None);
    };

    if !resolved.path.exists() {
        let error = ConfigurationError::missing(
            ConfigRole::Node,
            resolved.path.clone(),
            resolved.source,
            mode.default_node_config_path(),
        );
        return Err(error.into());
    }

    let display_path = resolved.path.display().to_string();
    let config = NodeConfig::load(&resolved.path)
        .with_context(|| format!("failed to load configuration from {display_path}"))?;

    Ok(Some(ConfigBundle {
        value: config,
        metadata: Some(resolved.into_metadata()),
    }))
}

fn load_wallet_configuration(
    mode: RuntimeMode,
    options: &BootstrapOptions,
) -> Result<Option<ConfigBundle<WalletConfig>>> {
    if !mode.includes_wallet() {
        return Ok(None);
    }

    let Some(mut resolved) = resolve_wallet_config_path(mode, options) else {
        return Ok(None);
    };

    if !resolved.path.exists() {
        let error = ConfigurationError::missing(
            ConfigRole::Wallet,
            resolved.path.clone(),
            resolved.source,
            mode.default_wallet_config_path(),
        );
        return Err(error.into());
    }

    let display_path = resolved.path.display().to_string();
    let config = WalletConfig::load(&resolved.path)
        .map_err(|err| anyhow!(err))
        .with_context(|| format!("failed to load configuration from {display_path}"))?;

    Ok(Some(ConfigBundle {
        value: config,
        metadata: Some(resolved.into_metadata()),
    }))
}

fn resolve_node_config_path(
    mode: RuntimeMode,
    options: &BootstrapOptions,
) -> Option<ResolvedConfigPath> {
    resolve_config_path(options.node_config.clone(), mode.default_node_config_path())
}

fn resolve_wallet_config_path(
    mode: RuntimeMode,
    options: &BootstrapOptions,
) -> Option<ResolvedConfigPath> {
    resolve_config_path(
        options.wallet_config.clone(),
        mode.default_wallet_config_path(),
    )
}

fn resolve_config_path(
    cli_path: Option<PathBuf>,
    default_path: Option<&'static str>,
) -> Option<ResolvedConfigPath> {
    if let Some(path) = cli_path {
        return Some(ResolvedConfigPath {
            path,
            source: ConfigSource::CommandLine,
        });
    }

    if let Some(path) = env_config_path() {
        return Some(ResolvedConfigPath {
            path,
            source: ConfigSource::Environment,
        });
    }

    default_path.map(|path| ResolvedConfigPath {
        path: PathBuf::from(path),
        source: ConfigSource::Default,
    })
}

fn env_config_path() -> Option<PathBuf> {
    let raw = std::env::var("RPP_CONFIG").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn apply_overrides(config: &mut NodeConfig, options: &BootstrapOptions) {
    if let Some(dir) = options.data_dir.as_ref() {
        config.data_dir = dir.clone();
    }
    if let Some(addr) = options.rpc_listen {
        config.rpc_listen = addr;
    }
    if let Some(token) = options.rpc_auth_token.as_ref() {
        let token = token.trim();
        if token.is_empty() {
            config.rpc_auth_token = None;
        } else {
            config.rpc_auth_token = Some(token.to_string());
        }
    }
    if let Some(endpoint) = options.telemetry_endpoint.as_ref() {
        let endpoint = endpoint.trim();
        if endpoint.is_empty() {
            config.rollout.telemetry.endpoint = None;
            config.rollout.telemetry.enabled = false;
        } else {
            config.rollout.telemetry.endpoint = Some(endpoint.to_string());
            config.rollout.telemetry.enabled = true;
        }
    }
    if let Some(auth) = options.telemetry_auth_token.as_ref() {
        let token = auth.trim();
        if token.is_empty() {
            config.rollout.telemetry.auth_token = None;
        } else {
            config.rollout.telemetry.auth_token = Some(token.to_string());
        }
    }
    if let Some(interval) = options.telemetry_sample_interval {
        config.rollout.telemetry.sample_interval_secs = interval;
        if config.rollout.telemetry.endpoint.is_some() {
            config.rollout.telemetry.enabled = true;
        }
    }
}

fn persist_node_config(
    mode: RuntimeMode,
    config: &NodeConfig,
    override_path: Option<&Path>,
) -> Result<()> {
    let path = if let Some(path) = override_path {
        path.to_path_buf()
    } else {
        PathBuf::from(format!("{}.toml", mode.as_str()))
    };

    let resolved = if path.is_absolute() {
        path
    } else {
        env::current_dir()
            .context("failed to resolve current working directory")?
            .join(path)
    };

    config
        .save(&resolved)
        .with_context(|| format!("failed to persist configuration to {}", resolved.display()))?;
    info!(path = %resolved.display(), "persisted node configuration");
    Ok(())
}

fn init_tracing(
    config: &NodeConfig,
    metadata: Option<&ConfigMetadata>,
    log_level: Option<String>,
    json: bool,
    mode: RuntimeMode,
    config_source: &str,
    dry_run: bool,
) -> Result<Option<OtelGuard>> {
    let level = log_level.or_else(|| std::env::var("RUST_LOG").ok());
    let filter = match level {
        Some(level) => match EnvFilter::try_new(level) {
            Ok(filter) => filter,
            Err(err) => {
                eprintln!("invalid log level override ({err}), falling back to info");
                EnvFilter::new("info")
            }
        },
        None => EnvFilter::new("info"),
    };

    let fmt_layer = || {
        let layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_ansi(!json);
        if json {
            layer.json().flatten_event(true).boxed()
        } else {
            layer.boxed()
        }
    };

    if dry_run {
        tracing_subscriber::registry()
            .with(filter.clone())
            .with(fmt_layer())
            .try_init()?;

        let telemetry_span = info_span!(
            "node.telemetry.init",
            otlp_enabled = false,
            dry_run = true,
            mode = mode.as_str(),
            config_source = config_source
        );
        let _span_guard = telemetry_span.enter();
        info!(
            target = "telemetry",
            otlp_enabled = false,
            dry_run = true,
            mode = mode.as_str(),
            config_source = config_source,
            "tracing initialised"
        );
        return Ok(None);
    }

    match build_otlp_layer(config, metadata, mode, config_source)? {
        Some(OtlpLayer {
            layer,
            guard,
            endpoint,
        }) => {
            tracing_subscriber::registry()
                .with(filter.clone())
                .with(fmt_layer())
                .with(layer)
                .try_init()?;

            let telemetry_span = info_span!(
                "node.telemetry.init",
                otlp_enabled = true,
                otlp_endpoint = endpoint.as_str(),
                dry_run = false,
                mode = mode.as_str(),
                config_source = config_source
            );
            let _span_guard = telemetry_span.enter();
            info!(
                target = "telemetry",
                otlp_enabled = true,
                otlp_endpoint = endpoint,
                dry_run = false,
                mode = mode.as_str(),
                config_source = config_source,
                "tracing initialised"
            );
            Ok(Some(guard))
        }
        None => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer())
                .try_init()?;

            let telemetry_span = info_span!(
                "node.telemetry.init",
                otlp_enabled = false,
                dry_run = false,
                mode = mode.as_str(),
                config_source = config_source
            );
            let _span_guard = telemetry_span.enter();
            info!(
                target = "telemetry",
                otlp_enabled = false,
                dry_run = false,
                mode = mode.as_str(),
                config_source = config_source,
                "tracing initialised"
            );
            Ok(None)
        }
    }
}

struct OtelGuard;

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Err(err) = global::shutdown_tracer_provider() {
            eprintln!("failed to shutdown otlp tracer provider: {err}");
        }
    }
}

struct OtlpLayer {
    layer: OpenTelemetryLayer<tracing_subscriber::Registry, Tracer>,
    guard: OtelGuard,
    endpoint: String,
}

struct OtlpSettings {
    endpoint: String,
    auth_header: Option<String>,
    timeout: Duration,
}

fn build_otlp_layer(
    config: &NodeConfig,
    metadata: Option<&ConfigMetadata>,
    mode: RuntimeMode,
    config_source: &str,
) -> Result<Option<OtlpLayer>> {
    let Some(settings) = otlp_settings(config)? else {
        return Ok(None);
    };

    let mut exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint(settings.endpoint.clone())
        .with_timeout(settings.timeout);

    if let Some(header) = settings.auth_header.as_ref() {
        let mut metadata = MetadataMap::new();
        let value = MetadataValue::from_str(header)
            .map_err(|err| anyhow!("invalid telemetry auth token: {err}"))?;
        metadata.insert("authorization", value);
        exporter = exporter.with_metadata(metadata);
    }

    let exporter = exporter.build_span_exporter()?;
    let batch_config = BatchConfig::default()
        .with_max_queue_size(2048)
        .with_max_export_batch_size(512)
        .with_max_export_timeout(settings.timeout);

    let mut attributes = vec![
        KeyValue::new("service.name", "rpp"),
        KeyValue::new("service.component", "rpp-node"),
        KeyValue::new("service.namespace", "rpp"),
        KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
        KeyValue::new("rpp.mode", mode.as_str()),
        KeyValue::new("rpp.config_source", config_source.to_string()),
        KeyValue::new(
            "rpp.rollout.release_channel",
            format!("{:?}", config.rollout.release_channel),
        ),
        KeyValue::new(
            "rpp.telemetry.sample_interval_secs",
            config.rollout.telemetry.sample_interval_secs as i64,
        ),
        KeyValue::new(
            "rpp.telemetry.redact_logs",
            config.rollout.telemetry.redact_logs,
        ),
    ];

    if let Some(metadata) = metadata {
        attributes.push(KeyValue::new(
            "rpp.config.node.source",
            metadata.source.as_str(),
        ));
        attributes.push(KeyValue::new(
            "rpp.config.node.path",
            metadata.path.display().to_string(),
        ));
    }

    let resource = Resource::new(attributes);

    let provider = trace::TracerProvider::builder()
        .with_config(trace::Config::default().with_resource(resource))
        .with_batch_config(batch_config)
        .with_batch_exporter(exporter, Tokio)
        .build();

    let tracer = provider.tracer("rpp-node", Some(env!("CARGO_PKG_VERSION")));
    global::set_tracer_provider(provider);

    let layer = tracing_opentelemetry::layer().with_tracer(tracer);
    Ok(Some(OtlpLayer {
        layer,
        guard: OtelGuard,
        endpoint: settings.endpoint,
    }))
}

fn otlp_settings(config: &NodeConfig) -> Result<Option<OtlpSettings>> {
    let telemetry = &config.rollout.telemetry;

    let endpoint_override = normalize_option(std::env::var("RPP_NODE_OTLP_ENDPOINT").ok());
    let env_endpoint = normalize_option(std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok());
    let endpoint = endpoint_override
        .clone()
        .or_else(|| normalize_option(telemetry.endpoint.clone()))
        .or(env_endpoint.clone());

    let telemetry_enabled =
        telemetry.enabled || endpoint_override.is_some() || env_endpoint.is_some();

    let Some(endpoint) = endpoint else {
        if telemetry_enabled {
            anyhow::bail!("telemetry endpoint required when OTLP is enabled");
        }
        return Ok(None);
    };

    let auth_header = normalize_option(std::env::var("RPP_NODE_OTLP_AUTH_TOKEN").ok())
        .or_else(|| normalize_option(telemetry.auth_token.clone()))
        .map(
            |token| match token.to_ascii_lowercase().starts_with("bearer ") {
                true => token,
                false => format!("Bearer {token}"),
            },
        );

    let timeout_ms = std::env::var("RPP_NODE_OTLP_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(telemetry.timeout_ms);

    Ok(Some(OtlpSettings {
        endpoint,
        auth_header,
        timeout: Duration::from_millis(timeout_ms),
    }))
}

fn normalize_option(value: Option<String>) -> Option<String> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}
