use std::convert::Infallible;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::serve;
use axum::Router;
use parking_lot::Mutex;
use tokio::net::TcpListener as TokioTcpListener;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
#[cfg(feature = "wallet_rpc_mtls")]
use tokio::task::JoinSet;
use tower::ServiceExt;
use tracing::{debug, info, warn};

use crate::errors::{ChainError, ChainResult};
use crate::runtime::config::WalletRpcSecurityCaFingerprint;
use crate::runtime::telemetry::metrics::{RuntimeMetrics, WalletRpcMethod};
#[cfg(feature = "wallet-integration")]
use rpp_wallet::runtime::lifecycle::{EmbeddedNodeLifecycle, EmbeddedNodeStatus};
#[cfg(feature = "wallet-integration")]
use rpp_wallet::wallet::Wallet;
pub use rpp_wallet_interface::WalletService;
use rpp_wallet_interface::{NodeClient, WalletService, WalletServiceError};

#[cfg(feature = "wallet_rpc_mtls")]
use super::rpc::WalletClientCertificates;
use super::rpc::{
    AuthToken, WalletRbacStore, WalletSecurityBinding, WalletSecurityContext, WalletSecurityPaths,
};

#[cfg(feature = "wallet_rpc_mtls")]
use std::fs;
#[cfg(feature = "wallet_rpc_mtls")]
use std::io::BufReader;

use super::sync::{SyncCheckpoint, SyncProvider, SyncUpdateReceiver, SyncUpdateSender};
#[cfg(feature = "wallet_rpc_mtls")]
use hyper::body::Incoming;
#[cfg(feature = "wallet_rpc_mtls")]
use hyper::service::service_fn;
#[cfg(feature = "wallet_rpc_mtls")]
use hyper::Request;
#[cfg(feature = "wallet_rpc_mtls")]
use hyper_util::rt::{TokioExecutor, TokioIo};
#[cfg(feature = "wallet_rpc_mtls")]
use hyper_util::server::conn::auto::Builder as HyperConnBuilder;
#[cfg(feature = "wallet_rpc_mtls")]
use rustls::crypto::aws_lc_rs;
#[cfg(feature = "wallet_rpc_mtls")]
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
#[cfg(feature = "wallet_rpc_mtls")]
use rustls::server::{ClientCertVerifier, WebPkiClientVerifier};
#[cfg(feature = "wallet_rpc_mtls")]
use rustls::{RootCertStore, ServerConfig};
#[cfg(feature = "wallet_rpc_mtls")]
use rustls_pemfile::{certs, ec_private_keys, pkcs8_private_keys, rsa_private_keys};
#[cfg(feature = "wallet_rpc_mtls")]
use tokio_rustls::TlsAcceptor;

/// Connector responsible for wiring the wallet runtime to a node handle or proxy.
pub trait NodeConnector<W: WalletService + ?Sized>: Send + Sync {
    fn attach(&self, wallet: &W) -> ChainResult<NodeAttachment>;
}

struct WalletRuntimeState {
    metrics: Arc<RuntimeMetrics>,
    shutdown_tx: watch::Sender<bool>,
    watch_task: Mutex<Option<JoinHandle<()>>>,
    sync_task: Mutex<Option<JoinHandle<()>>>,
    sync_update_task: Mutex<Option<JoinHandle<()>>>,
    http_task: Mutex<Option<JoinHandle<()>>>,
    checkpoint: Arc<Mutex<Option<SyncCheckpoint>>>,
    attached_to_node: bool,
    wallet_ready: Arc<AtomicBool>,
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
        if let Some(handle) = self.sync_update_task.lock().take() {
            let _ = handle.await;
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
    rpc_security: WalletRpcSecurityRuntimeConfig,
    audit: WalletAuditRuntimeConfig,
    zsi_enabled: bool,
    #[cfg(feature = "wallet-integration")]
    embedded_node: Option<EmbeddedNodeLifecycle>,
}

impl WalletRuntimeConfig {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            allowed_origin: None,
            auth_token: None,
            requests_per_minute: None,
            security: WalletSecurityConfig::default(),
            rpc_security: WalletRpcSecurityRuntimeConfig::default(),
            audit: WalletAuditRuntimeConfig::default(),
            zsi_enabled: false,
            #[cfg(feature = "wallet-integration")]
            embedded_node: None,
        }
    }

    pub fn set_security_paths(&mut self, paths: WalletSecurityPaths) {
        if self.audit.directory().is_none() {
            if let Some(wallet_dir) = paths.root().parent() {
                self.audit.set_directory(wallet_dir.join("audit"));
            }
        }
        self.security.set_paths(paths);
    }

    pub fn set_security_bindings(&mut self, bindings: Vec<WalletSecurityBinding>) {
        self.security.set_bindings(bindings);
    }

    pub fn set_security_settings(&mut self, settings: WalletRpcSecurityRuntimeConfig) {
        self.rpc_security = settings;
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

    pub fn security_settings(&self) -> &WalletRpcSecurityRuntimeConfig {
        &self.rpc_security
    }

    pub fn set_zsi_enabled(&mut self, enabled: bool) {
        self.zsi_enabled = enabled;
    }

    #[cfg(feature = "wallet-integration")]
    pub fn set_embedded_node(&mut self, lifecycle: EmbeddedNodeLifecycle) {
        self.embedded_node = Some(lifecycle);
    }

    #[cfg(feature = "wallet-integration")]
    pub fn embedded_node(&self) -> Option<&EmbeddedNodeLifecycle> {
        self.embedded_node.as_ref()
    }

    #[cfg(feature = "wallet-integration")]
    fn take_embedded_node(&mut self) -> Option<EmbeddedNodeLifecycle> {
        self.embedded_node.take()
    }

    pub fn zsi_enabled(&self) -> bool {
        self.zsi_enabled
    }

    pub fn set_audit_settings(&mut self, settings: WalletAuditRuntimeConfig) {
        self.audit = settings;
    }

    pub fn audit_settings(&self) -> &WalletAuditRuntimeConfig {
        &self.audit
    }

    pub fn audit_settings_mut(&mut self) -> &mut WalletAuditRuntimeConfig {
        &mut self.audit
    }
}

#[derive(Clone, Debug, Default)]
pub struct WalletRpcSecurityRuntimeConfig {
    enabled: bool,
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
    ca_certificate: Option<PathBuf>,
    ca_fingerprints: Vec<WalletRpcSecurityCaFingerprint>,
}

impl WalletRpcSecurityRuntimeConfig {
    pub fn new(
        enabled: bool,
        certificate: Option<PathBuf>,
        private_key: Option<PathBuf>,
        ca_certificate: Option<PathBuf>,
        ca_fingerprints: Vec<WalletRpcSecurityCaFingerprint>,
    ) -> Self {
        Self {
            enabled,
            certificate,
            private_key,
            ca_certificate,
            ca_fingerprints,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn certificate(&self) -> Option<&Path> {
        self.certificate.as_deref()
    }

    pub fn private_key(&self) -> Option<&Path> {
        self.private_key.as_deref()
    }

    pub fn ca_certificate(&self) -> Option<&Path> {
        self.ca_certificate.as_deref()
    }

    pub fn ca_fingerprints(&self) -> &[WalletRpcSecurityCaFingerprint] {
        &self.ca_fingerprints
    }
}

#[derive(Clone, Debug, Default)]
pub struct WalletAuditRuntimeConfig {
    enabled: bool,
    retention_days: u64,
    directory: Option<PathBuf>,
}

impl WalletAuditRuntimeConfig {
    pub fn new(enabled: bool, retention_days: u64, directory: Option<PathBuf>) -> Self {
        Self {
            enabled,
            retention_days,
            directory,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn retention_days(&self) -> u64 {
        self.retention_days
    }

    pub fn set_retention_days(&mut self, days: u64) {
        self.retention_days = days;
    }

    pub fn directory(&self) -> Option<&Path> {
        self.directory.as_deref()
    }

    pub fn set_directory(&mut self, directory: PathBuf) {
        self.directory = Some(directory);
    }

    pub fn retention_duration(&self) -> Duration {
        let seconds = self
            .retention_days
            .checked_mul(24 * 60 * 60)
            .unwrap_or(u64::MAX);
        Duration::from_secs(seconds)
    }
}

#[derive(Clone, Debug)]
struct WalletSecurityConfig {
    paths: Option<WalletSecurityPaths>,
    context: Arc<WalletSecurityContext>,
    initialised: bool,
    bindings: Vec<WalletSecurityBinding>,
}

impl Default for WalletSecurityConfig {
    fn default() -> Self {
        Self {
            paths: None,
            context: Arc::new(WalletSecurityContext::empty()),
            initialised: false,
            bindings: Vec::new(),
        }
    }
}

impl WalletSecurityConfig {
    fn set_paths(&mut self, paths: WalletSecurityPaths) {
        self.paths = Some(paths);
        self.initialised = false;
    }

    fn set_bindings(&mut self, bindings: Vec<WalletSecurityBinding>) {
        self.bindings = bindings;
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
            let store = WalletRbacStore::load(paths.rbac_store())?;
            if !self.bindings.is_empty() {
                store.apply_bindings(&self.bindings);
                store.save()?;
            }
            let context = WalletSecurityContext::from_store(store);
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
    #[cfg(feature = "wallet-integration")]
    embedded_node: Option<EmbeddedNodeLifecycle>,
}

#[cfg(feature = "wallet-integration")]
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
        self.state.checkpoint.lock().clone()
    }

    pub async fn shutdown(&self) -> ChainResult<()> {
        self.state.shutdown().await?;
        #[cfg(feature = "wallet-integration")]
        if let Some(node) = self.embedded_node.as_ref() {
            node.stop().map_err(|err| {
                ChainError::Config(format!("embedded node shutdown failed: {err}"))
            })?;
        }
        Ok(())
    }

    #[cfg(feature = "wallet-integration")]
    pub fn embedded_node_status(&self) -> Option<EmbeddedNodeStatus> {
        self.embedded_node.as_ref().map(|node| node.status())
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
        updates_tx: SyncUpdateSender,
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
        #[cfg(feature = "wallet-integration")]
        let mut embedded_node = config.take_embedded_node();

        #[cfg(feature = "wallet-integration")]
        if let Some(lifecycle) = embedded_node.as_ref() {
            lifecycle.start().map_err(|err| {
                ChainError::Config(format!("failed to start embedded node: {err}"))
            })?;
        }
        let address = wallet.address();
        let checkpoint = sync_provider.latest_checkpoint();
        let checkpoint_store = Arc::new(Mutex::new(checkpoint.clone()));
        let wallet_ready = Arc::new(AtomicBool::new(false));
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

        let (sync_task, sync_update_task) = if let Some(driver) = sync_driver {
            let (sync_update_tx, sync_update_rx) = mpsc::unbounded_channel();
            let update_task = spawn_sync_update_listener(
                Arc::clone(&metrics),
                Arc::clone(&checkpoint_store),
                Arc::clone(&wallet_ready),
                shutdown_rx.clone(),
                sync_update_rx,
            );
            let task = driver.spawn(Arc::clone(&metrics), shutdown_rx.clone(), sync_update_tx)?;
            metrics.record_wallet_sync_driver_started();
            (Some(task), Some(update_task))
        } else {
            (None, None)
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

            if config.security_settings().enabled() {
                #[cfg(feature = "wallet_rpc_mtls")]
                {
                    let tls_acceptor = build_wallet_tls_acceptor(config.security_settings())?;
                    let tls_router = router.clone();
                    let mut shutdown_rx_http = shutdown_rx.clone();
                    let task = tokio::spawn(async move {
                        let mut listener = listener;
                        let mut make_service =
                            tls_router.into_make_service_with_connect_info::<SocketAddr>();
                        let mut tasks: JoinSet<()> = JoinSet::new();
                        loop {
                            let mut shutdown_future = wait_for_shutdown(shutdown_rx_http.clone());
                            tokio::pin!(shutdown_future);
                            tokio::select! {
                                _ = &mut shutdown_future => {
                                    break;
                                }
                                accept_result = listener.accept() => {
                                    let (stream, remote_addr) = match accept_result {
                                        Ok(value) => value,
                                        Err(err) => {
                                            warn!(?err, "failed to accept wallet RPC TLS connection");
                                            continue;
                                        }
                                    };

                                    let tower_service = unwrap_infallible(make_service.call(remote_addr).await);
                                    let acceptor = tls_acceptor.clone();
                                    let mut shutdown_conn = shutdown_rx_http.clone();
                                    tasks.spawn(async move {
                                        let tls_stream = match acceptor.accept(stream).await {
                                            Ok(tls_stream) => tls_stream,
                                            Err(err) => {
                                                warn!(?remote_addr, error = %err, "wallet RPC TLS handshake failed");
                                                return;
                                            }
                                        };

                                        let client_certs = tls_stream
                                            .get_ref()
                                            .1
                                            .peer_certificates()
                                            .map(|chain| {
                                                WalletClientCertificates::from_der(
                                                    chain.iter().map(|cert| cert.as_ref()),
                                                )
                                            })
                                            .unwrap_or_else(WalletClientCertificates::empty);
                                        let client_certs = Arc::new(client_certs);

                                        let hyper_service = service_fn(move |mut request: Request<Incoming>| {
                                            let service = tower_service.clone();
                                            let client_certs = Arc::clone(&client_certs);
                                            async move {
                                                if !client_certs.is_empty() {
                                                    request
                                                        .extensions_mut()
                                                        .insert(Arc::clone(&client_certs));
                                                }
                                                service.oneshot(request).await
                                            }
                                        });

                                        let mut conn = HyperConnBuilder::new(TokioExecutor::new())
                                            .serve_connection_with_upgrades(
                                                TokioIo::new(tls_stream),
                                                hyper_service,
                                            );
                                        tokio::pin!(conn);
                                        let mut shutdown_future = wait_for_shutdown(shutdown_conn.clone());
                                        tokio::pin!(shutdown_future);
                                        tokio::select! {
                                            result = &mut conn => {
                                                if let Err(err) = result {
                                                    warn!(?remote_addr, error = %err, "wallet RPC TLS connection terminated with error");
                                                }
                                            }
                                            _ = &mut shutdown_future => {
                                                conn.as_mut().graceful_shutdown();
                                                if let Err(err) = conn.await {
                                                    warn!(?remote_addr, error = %err, "wallet RPC TLS connection terminated during shutdown");
                                                }
                                            }
                                        }
                                    });
                                }
                            }
                        }

                        while tasks.join_next().await.is_some() {}
                    });
                    info!(listen = %listen_addr, "wallet runtime RPC server listening (tls)");
                    (Some(task), listen_addr)
                }
                #[cfg(not(feature = "wallet_rpc_mtls"))]
                {
                    return Err(ChainError::Config(
                        "wallet RPC TLS support requires enabling the `wallet_rpc_mtls` feature"
                            .into(),
                    ));
                }
            } else {
                let mut shutdown_rx_http = shutdown_rx.clone();
                let service = router.into_make_service();
                let server = serve(listener, service)
                    .with_graceful_shutdown(wait_for_shutdown(shutdown_rx_http));
                let task = tokio::spawn(async move {
                    if let Err(err) = server.await {
                        warn!(?err, "wallet RPC server terminated with error");
                    }
                });
                info!(listen = %listen_addr, "wallet runtime RPC server listening");
                (Some(task), listen_addr)
            }
        } else {
            (None, config.listen_addr)
        };
        config.listen_addr = resolved_listen_addr;

        let attached_to_node = if let Some(connector) = connector {
            let attachment = connector.attach(wallet.as_ref())?;
            if let Some(node_client) = attachment.node_client() {
                wallet
                    .attach_node_client(node_client)
                    .map_err(|err| wallet_service_error(err))?;
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

        let state = Arc::new(WalletRuntimeState {
            metrics: Arc::clone(&metrics),
            shutdown_tx,
            watch_task: Mutex::new(Some(watch_task)),
            sync_task: Mutex::new(sync_task),
            sync_update_task: Mutex::new(sync_update_task),
            http_task: Mutex::new(http_task),
            checkpoint: Arc::clone(&checkpoint_store),
            attached_to_node,
            wallet_ready: Arc::clone(&wallet_ready),
        });

        wallet_ready.store(true, Ordering::SeqCst);

        Ok(GenericWalletRuntimeHandle {
            wallet,
            address,
            config,
            state,
            #[cfg(feature = "wallet-integration")]
            embedded_node,
        })
    }
}

fn spawn_sync_update_listener(
    metrics: Arc<RuntimeMetrics>,
    checkpoint: Arc<Mutex<Option<SyncCheckpoint>>>,
    wallet_ready: Arc<AtomicBool>,
    mut shutdown_rx: watch::Receiver<bool>,
    mut sync_update_rx: SyncUpdateReceiver,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                maybe_update = sync_update_rx.recv() => {
                    let Some(update) = maybe_update else {
                        break;
                    };

                    if !wallet_ready.load(Ordering::SeqCst) {
                        continue;
                    }

                    {
                        let mut checkpoint_guard = checkpoint.lock();
                        *checkpoint_guard = Some(update.checkpoint.clone());
                    }

                    metrics.record_wallet_sync_wallet_height(update.checkpoint.height);
                    metrics.record_wallet_sync_chain_tip_height(update.chain_tip_height);
                    metrics.record_wallet_sync_lag_blocks(
                        update
                            .chain_tip_height
                            .saturating_sub(update.checkpoint.height),
                    );
                    metrics.record_wallet_last_successful_sync(update.applied_at);
                }
            }
        }
    })
}

fn unwrap_infallible<T>(result: Result<T, Infallible>) -> T {
    match result {
        Ok(value) => value,
        Err(err) => match err {},
    }
}

fn wallet_service_error(err: WalletServiceError) -> ChainError {
    ChainError::Config(format!("wallet service error: {err}"))
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        if shutdown_rx.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(all(test, feature = "wallet-integration"))]
mod tests {
    use super::*;
    use crate::runtime::telemetry::metrics::WalletSyncSnapshot;
    use crate::runtime::wallet::sync::{DeterministicSync, SyncProvider, SyncUpdate};
    use axum::extract::State;
    use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::Duration as TokioDuration;

    use crate::rpc::api::{health_ready, ApiContext, HealthSubsystemStatus};

    #[derive(Clone)]
    struct TestWallet {
        address: String,
    }

    impl WalletService for TestWallet {
        fn address(&self) -> String {
            self.address.clone()
        }
    }

    #[derive(Clone)]
    struct TestSyncDriver {
        update: SyncUpdate,
    }

    impl SyncDriver for TestSyncDriver {
        fn spawn(
            self: Box<Self>,
            _metrics: Arc<RuntimeMetrics>,
            mut shutdown_rx: watch::Receiver<bool>,
            updates_tx: SyncUpdateSender,
        ) -> ChainResult<JoinHandle<()>> {
            let update = self.update.clone();
            Ok(tokio::spawn(async move {
                let _ = updates_tx.send(update);
                wait_for_shutdown(shutdown_rx).await;
            }))
        }
    }

    fn test_metrics() -> Arc<RuntimeMetrics> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("wallet-runtime-test");
        Arc::new(RuntimeMetrics::from_meter_for_testing(&meter))
    }

    fn test_runtime_config() -> WalletRuntimeConfig {
        WalletRuntimeConfig::new(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
    }

    #[tokio::test]
    async fn runtime_records_sync_progress_in_metrics_snapshot() {
        let metrics = test_metrics();
        let sync_provider: Box<dyn SyncProvider> =
            Box::new(DeterministicSync::new("metrics").with_height(7));
        let checkpoint = sync_provider
            .latest_checkpoint()
            .expect("checkpoint available");
        let update = SyncUpdate::new(checkpoint.clone(), 10);

        let runtime = WalletRuntime::start(
            Arc::new(TestWallet {
                address: "test-wallet".to_string(),
            }),
            test_runtime_config(),
            Arc::clone(&metrics),
            sync_provider,
            Some(Box::new(TestSyncDriver {
                update: update.clone(),
            })),
            None,
            None,
        )
        .expect("runtime starts");

        tokio::time::sleep(TokioDuration::from_millis(50)).await;

        assert_eq!(runtime.sync_checkpoint(), Some(checkpoint));

        let snapshot = metrics.wallet_sync_snapshot();
        assert_eq!(
            snapshot,
            WalletSyncSnapshot {
                wallet_height: Some(update.checkpoint.height),
                chain_tip_height: Some(update.chain_tip_height),
                lag_blocks: Some(update.chain_tip_height - update.checkpoint.height),
                last_success_timestamp: snapshot.last_success_timestamp,
            }
        );
        assert!(snapshot.last_success_timestamp.is_some());

        runtime.shutdown().await.expect("runtime shutdown");
    }

    #[tokio::test]
    async fn readiness_response_surfaces_wallet_sync_metrics() {
        let metrics = test_metrics();
        let sync_provider: Box<dyn SyncProvider> =
            Box::new(DeterministicSync::new("health").with_height(3));
        let checkpoint = sync_provider
            .latest_checkpoint()
            .expect("checkpoint available");
        let update = SyncUpdate::new(checkpoint.clone(), 6);

        let runtime = WalletRuntime::start(
            Arc::new(TestWallet {
                address: "health-wallet".to_string(),
            }),
            test_runtime_config(),
            Arc::clone(&metrics),
            sync_provider,
            Some(Box::new(TestSyncDriver {
                update: update.clone(),
            })),
            None,
            None,
        )
        .expect("runtime starts");

        tokio::time::sleep(TokioDuration::from_millis(50)).await;

        let snapshot = metrics.wallet_sync_snapshot();
        let subsystem_status = HealthSubsystemStatus {
            zk_ready: true,
            pruning_available: true,
            snapshots_available: true,
            wallet_signer_ready: true,
            wallet_connected: true,
            wallet_key_cache_ready: true,
            wallet_synced_height: snapshot.wallet_height,
            wallet_chain_tip: snapshot.chain_tip_height,
            wallet_sync_lag: snapshot.lag_blocks,
            wallet_last_sync_timestamp: snapshot.last_success_timestamp,
        };

        let mode = Arc::new(parking_lot::RwLock::new(crate::runtime::RuntimeMode::Node));
        let context = ApiContext::new(
            Arc::clone(&mode),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            false,
        )
        .with_metrics(metrics)
        .with_test_node_ready(true)
        .with_test_subsystem_status(subsystem_status.clone());

        let (status, axum::Json(response)) = health_ready(State(context)).await;

        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(response.subsystems, subsystem_status);
        assert!(response.subsystems.wallet_last_sync_timestamp.is_some());

        runtime.shutdown().await.expect("runtime shutdown");
    }
}

#[cfg(feature = "wallet_rpc_mtls")]
fn build_wallet_tls_acceptor(
    settings: &WalletRpcSecurityRuntimeConfig,
) -> ChainResult<TlsAcceptor> {
    let certificate_path = settings.certificate().ok_or_else(|| {
        ChainError::Config("wallet RPC security requires a certificate path".into())
    })?;
    let private_key_path = settings.private_key().ok_or_else(|| {
        ChainError::Config("wallet RPC security requires a private key path".into())
    })?;
    let ca_path = settings.ca_certificate().ok_or_else(|| {
        ChainError::Config("wallet RPC security requires a client CA certificate".into())
    })?;

    let certificates = load_certificates(certificate_path)?;
    let private_key = load_private_key(private_key_path)?;
    let verifier = build_client_verifier(ca_path)?;

    let _ = aws_lc_rs::default_provider().install_default();

    let mut builder = ServerConfig::builder()
        .with_safe_default_protocol_versions()
        .map_err(|err| {
            ChainError::Config(format!("failed to configure TLS protocol versions: {err}"))
        })?;

    builder = builder.with_client_cert_verifier(verifier);

    let mut server_config = builder
        .with_single_cert(certificates, private_key)
        .map_err(|err| ChainError::Config(format!("failed to build TLS server config: {err}")))?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

#[cfg(feature = "wallet_rpc_mtls")]
fn load_certificates(path: &Path) -> ChainResult<Vec<CertificateDer<'static>>> {
    let bytes = fs::read(path)
        .map_err(|err| ChainError::Config(format!("failed to read {path:?}: {err}")))?;
    let mut reader = BufReader::new(bytes.as_slice());
    let certs = certs(&mut reader).map_err(|err| {
        ChainError::Config(format!("failed to parse certificates from {path:?}: {err}"))
    })?;
    Ok(certs
        .into_iter()
        .map(|cert| CertificateDer::from(cert).into_owned())
        .collect())
}

#[cfg(feature = "wallet_rpc_mtls")]
fn load_private_key(path: &Path) -> ChainResult<PrivateKeyDer<'static>> {
    let bytes = fs::read(path)
        .map_err(|err| ChainError::Config(format!("failed to read {path:?}: {err}")))?;

    let mut reader = BufReader::new(bytes.as_slice());
    if let Some(key) = pkcs8_private_keys(&mut reader)
        .map_err(|err| {
            ChainError::Config(format!("failed to parse private key from {path:?}: {err}"))
        })?
        .into_iter()
        .next()
    {
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key));
        return Ok(key.clone_key());
    }

    let mut reader = BufReader::new(bytes.as_slice());
    if let Some(key) = rsa_private_keys(&mut reader)
        .map_err(|err| {
            ChainError::Config(format!("failed to parse private key from {path:?}: {err}"))
        })?
        .into_iter()
        .next()
    {
        let key = PrivateKeyDer::from(PrivatePkcs1KeyDer::from(key));
        return Ok(key.clone_key());
    }

    let mut reader = BufReader::new(bytes.as_slice());
    if let Some(key) = ec_private_keys(&mut reader)
        .map_err(|err| {
            ChainError::Config(format!("failed to parse private key from {path:?}: {err}"))
        })?
        .into_iter()
        .next()
    {
        let key = PrivateKeyDer::from(PrivateSec1KeyDer::from(key));
        return Ok(key.clone_key());
    }

    Err(ChainError::Config(format!(
        "no valid private key found in {path:?}"
    )))
}

#[cfg(feature = "wallet_rpc_mtls")]
fn build_client_verifier(ca_path: &Path) -> ChainResult<Arc<dyn ClientCertVerifier>> {
    let ca_certs = load_certificates(ca_path)?;
    let mut roots = RootCertStore::empty();
    for cert in &ca_certs {
        roots
            .add(cert.clone())
            .map_err(|err| ChainError::Config(format!("invalid client CA certificate: {err}")))?;
    }

    let roots = Arc::new(roots);
    WebPkiClientVerifier::builder(roots).build().map_err(|err| {
        ChainError::Config(format!(
            "failed to build client certificate verifier: {err}"
        ))
    })
}
