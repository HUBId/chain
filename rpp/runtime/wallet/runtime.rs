use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use axum::serve;
use axum::Router;
use parking_lot::Mutex;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::errors::{ChainError, ChainResult};
use crate::runtime::telemetry::metrics::{RuntimeMetrics, WalletRpcMethod};
use crate::wallet::wallet::Wallet;
use rpp_wallet::node_client::NodeClient;

use super::rpc::{AuthToken, WalletSecurityContext, WalletSecurityPaths};
use super::sync::{SyncCheckpoint, SyncProvider};

/// Trait implemented by types that expose wallet functionality to the runtime.
pub trait WalletService: Send + Sync {
    fn address(&self) -> String;

    fn attach_node_client(&self, _client: Arc<dyn NodeClient>) -> ChainResult<()> {
        Ok(())
    }
}

impl WalletService for Wallet {
    fn address(&self) -> String {
        self.address().to_string()
    }

    fn attach_node_client(&self, _client: Arc<dyn NodeClient>) -> ChainResult<()> {
        Ok(())
    }
}

/// Connector responsible for wiring the wallet runtime to a node handle or proxy.
pub trait NodeConnector<W: WalletService + ?Sized>: Send + Sync {
    fn attach(&self, wallet: &W) -> ChainResult<NodeAttachment>;
}

struct WalletRuntimeState {
    metrics: Arc<RuntimeMetrics>,
    shutdown_tx: watch::Sender<bool>,
    watch_task: Mutex<Option<JoinHandle<()>>>,
    sync_task: Mutex<Option<JoinHandle<()>>>,
    http_task: Mutex<Option<JoinHandle<()>>>,
    checkpoint: Option<SyncCheckpoint>,
    attached_to_node: bool,
}

impl WalletRuntimeState {
    async fn shutdown(&self) -> ChainResult<()> {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.watch_task.lock().take() {
            match handle.await {
                Ok(()) => {
                    self.metrics.record_wallet_runtime_watch_stopped();
                }
                Err(err) => {
                    self.metrics.record_wallet_runtime_watch_stopped();
                    return Err(ChainError::Config(format!(
                        "wallet runtime task failed: {err}"
                    )));
                }
            }
        }
        if let Some(handle) = self.sync_task.lock().take() {
            match handle.await {
                Ok(()) => {
                    self.metrics.record_wallet_sync_driver_stopped();
                }
                Err(err) => {
                    self.metrics.record_wallet_sync_driver_stopped();
                    return Err(ChainError::Config(format!(
                        "wallet sync driver failed: {err}"
                    )));
                }
            }
        }
        if let Some(handle) = self.http_task.lock().take() {
            if let Err(err) = handle.await {
                return Err(ChainError::Config(format!(
                    "wallet RPC server task failed: {err}"
                )));
            }
        }
        Ok(())
    }
}

/// Configuration describing how the wallet runtime should be initialised.
#[derive(Clone, Debug)]
pub struct WalletRuntimeConfig {
    pub listen_addr: SocketAddr,
    pub allowed_origin: Option<String>,
    pub auth_token: Option<AuthToken>,
    pub requests_per_minute: Option<NonZeroU64>,
    security: WalletSecurityConfig,
}

impl WalletRuntimeConfig {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            allowed_origin: None,
            auth_token: None,
            requests_per_minute: None,
            security: WalletSecurityConfig::default(),
        }
    }

    pub fn set_security_paths(&mut self, paths: WalletSecurityPaths) {
        self.security.set_paths(paths);
    }

    pub fn security_paths(&self) -> Option<&WalletSecurityPaths> {
        self.security.paths()
    }

    pub fn ensure_security_context(&mut self) -> ChainResult<()> {
        self.security.ensure_context()
    }

    pub fn security_context(&self) -> Arc<WalletSecurityContext> {
        self.security.context()
    }
}

#[derive(Clone, Debug)]
struct WalletSecurityConfig {
    paths: Option<WalletSecurityPaths>,
    context: Arc<WalletSecurityContext>,
    initialised: bool,
}

impl Default for WalletSecurityConfig {
    fn default() -> Self {
        Self {
            paths: None,
            context: Arc::new(WalletSecurityContext::empty()),
            initialised: false,
        }
    }
}

impl WalletSecurityConfig {
    fn set_paths(&mut self, paths: WalletSecurityPaths) {
        self.paths = Some(paths);
        self.initialised = false;
    }

    fn paths(&self) -> Option<&WalletSecurityPaths> {
        self.paths.as_ref()
    }

    fn ensure_context(&mut self) -> ChainResult<()> {
        if self.initialised {
            return Ok(());
        }

        if let Some(paths) = &self.paths {
            paths.ensure()?;
            let context = WalletSecurityContext::load_from_store(paths.rbac_store())?;
            self.context = Arc::new(context);
        } else {
            self.context = Arc::new(WalletSecurityContext::empty());
        }

        self.initialised = true;
        Ok(())
    }

    fn context(&self) -> Arc<WalletSecurityContext> {
        Arc::clone(&self.context)
    }
}

/// Handle referencing a running wallet runtime instance.
#[derive(Clone)]
pub struct GenericWalletRuntimeHandle<W: WalletService + 'static> {
    wallet: Arc<W>,
    address: String,
    config: WalletRuntimeConfig,
    state: Arc<WalletRuntimeState>,
}

pub type WalletRuntimeHandle = GenericWalletRuntimeHandle<Wallet>;

impl<W: WalletService + 'static> GenericWalletRuntimeHandle<W> {
    pub fn wallet(&self) -> Arc<W> {
        Arc::clone(&self.wallet)
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }

    pub fn allowed_origin(&self) -> Option<&String> {
        self.config.allowed_origin.as_ref()
    }

    pub fn auth_token(&self) -> Option<&AuthToken> {
        self.config.auth_token.as_ref()
    }

    pub fn requests_per_minute(&self) -> Option<NonZeroU64> {
        self.config.requests_per_minute
    }

    pub fn security_context(&self) -> Arc<WalletSecurityContext> {
        self.config.security_context()
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn attached_to_node(&self) -> bool {
        self.state.attached_to_node
    }

    pub fn sync_checkpoint(&self) -> Option<SyncCheckpoint> {
        self.state.checkpoint.clone()
    }

    pub async fn shutdown(&self) -> ChainResult<()> {
        self.state.shutdown().await
    }
}

/// Wallet runtime orchestrator spawning background tasks and telemetry reporting.
pub struct WalletRuntime;

/// Handle returned by [`NodeConnector::attach`] containing runtime integrations.
pub struct NodeAttachment {
    node_client: Option<Arc<dyn NodeClient>>,
}

impl NodeAttachment {
    pub fn new(node_client: Option<Arc<dyn NodeClient>>) -> Self {
        Self { node_client }
    }

    pub fn node_client(&self) -> Option<Arc<dyn NodeClient>> {
        self.node_client.as_ref().map(Arc::clone)
    }
}

impl Default for NodeAttachment {
    fn default() -> Self {
        Self { node_client: None }
    }
}

/// Background worker driving wallet synchronisation with the node.
pub trait SyncDriver: Send + 'static {
    fn spawn(
        self: Box<Self>,
        metrics: Arc<RuntimeMetrics>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> ChainResult<JoinHandle<()>>;
}

impl WalletRuntime {
    pub fn start<W>(
        wallet: Arc<W>,
        mut config: WalletRuntimeConfig,
        metrics: Arc<RuntimeMetrics>,
        sync_provider: Box<dyn SyncProvider>,
        sync_driver: Option<Box<dyn SyncDriver>>,
        connector: Option<Box<dyn NodeConnector<W>>>,
        rpc_router: Option<Router>,
    ) -> ChainResult<GenericWalletRuntimeHandle<W>>
    where
        W: WalletService + 'static,
    {
        config.ensure_security_context()?;
        let address = wallet.address();
        let checkpoint = sync_provider.latest_checkpoint();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let metrics_clone = Arc::clone(&metrics);
        let runtime_address = address.clone();
        let mut runtime_shutdown_rx = shutdown_rx.clone();
        let watch_task = tokio::spawn(async move {
            metrics_clone.record_wallet_rpc_latency(
                WalletRpcMethod::RuntimeStatus,
                Duration::from_millis(0),
            );
            loop {
                if *runtime_shutdown_rx.borrow() {
                    break;
                }
                if runtime_shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
            debug!("wallet runtime loop stopped", address = %runtime_address);
        });
        metrics.record_wallet_runtime_watch_started();

        let sync_task = if let Some(driver) = sync_driver {
            let task = driver.spawn(Arc::clone(&metrics), shutdown_rx.clone())?;
            metrics.record_wallet_sync_driver_started();
            Some(task)
        } else {
            None
        };

        let (http_task, resolved_listen_addr) = if let Some(router) = rpc_router {
            let std_listener = StdTcpListener::bind(config.listen_addr).map_err(|err| {
                ChainError::Config(format!(
                    "failed to bind wallet RPC listener at {}: {err}",
                    config.listen_addr
                ))
            })?;
            std_listener.set_nonblocking(true).map_err(|err| {
                ChainError::Config(format!("failed to configure wallet RPC listener: {err}"))
            })?;
            let listener = TokioTcpListener::from_std(std_listener).map_err(|err| {
                ChainError::Config(format!("failed to initialise wallet RPC listener: {err}"))
            })?;
            let listen_addr = listener.local_addr().map_err(|err| {
                ChainError::Config(format!(
                    "failed to determine wallet RPC listen address: {err}"
                ))
            })?;
            let mut shutdown_rx_http = shutdown_rx.clone();
            let service = router.into_make_service();
            let server = serve(listener, service).with_graceful_shutdown(async move {
                loop {
                    if *shutdown_rx_http.borrow() {
                        break;
                    }
                    if shutdown_rx_http.changed().await.is_err() {
                        break;
                    }
                }
            });
            let task = tokio::spawn(async move {
                if let Err(err) = server.await {
                    warn!(?err, "wallet RPC server terminated with error");
                }
            });
            info!(listen = %listen_addr, "wallet runtime RPC server listening");
            (Some(task), listen_addr)
        } else {
            (None, config.listen_addr)
        };
        config.listen_addr = resolved_listen_addr;

        let attached_to_node = if let Some(connector) = connector {
            let attachment = connector.attach(wallet.as_ref())?;
            if let Some(node_client) = attachment.node_client() {
                wallet.attach_node_client(node_client)?;
            }
            true
        } else {
            false
        };

        if let Some(checkpoint) = checkpoint.as_ref() {
            info!(%address, %checkpoint, "wallet runtime sync checkpoint established");
        } else {
            info!(%address, "wallet runtime started without checkpoint");
        }

        let state = WalletRuntimeState {
            metrics: Arc::clone(&metrics),
            shutdown_tx,
            watch_task: Mutex::new(Some(watch_task)),
            sync_task: Mutex::new(sync_task),
            http_task: Mutex::new(http_task),
            checkpoint,
            attached_to_node,
        };

        Ok(GenericWalletRuntimeHandle {
            wallet,
            address,
            config,
            state: Arc::new(state),
        })
    }
}
