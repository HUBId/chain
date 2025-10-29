use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info};

use crate::errors::{ChainError, ChainResult};
use crate::runtime::telemetry::metrics::{RuntimeMetrics, WalletRpcMethod};
use crate::wallet::wallet::Wallet;

use super::rpc::AuthToken;
use super::sync::{SyncCheckpoint, SyncProvider};

/// Trait implemented by types that expose wallet functionality to the runtime.
pub trait WalletService: Send + Sync {
    fn address(&self) -> String;
}

impl WalletService for Wallet {
    fn address(&self) -> String {
        self.address().to_string()
    }
}

/// Connector responsible for wiring the wallet runtime to a node handle or proxy.
pub trait NodeConnector<W: WalletService + ?Sized>: Send + Sync {
    fn attach(&self, wallet: &W) -> ChainResult<()>;
}

struct WalletRuntimeState {
    shutdown_tx: watch::Sender<bool>,
    task: Mutex<Option<JoinHandle<()>>>,
    checkpoint: Option<SyncCheckpoint>,
    attached_to_node: bool,
}

impl WalletRuntimeState {
    async fn shutdown(&self) -> ChainResult<()> {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.task.lock().take() {
            handle
                .await
                .map_err(|err| ChainError::Config(format!("wallet runtime task failed: {err}")))?;
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
}

impl WalletRuntimeConfig {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            allowed_origin: None,
            auth_token: None,
            requests_per_minute: None,
        }
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

impl WalletRuntime {
    pub fn start<W>(
        wallet: Arc<W>,
        config: WalletRuntimeConfig,
        metrics: Arc<RuntimeMetrics>,
        sync_provider: Box<dyn SyncProvider>,
        connector: Option<Box<dyn NodeConnector<W>>>,
    ) -> ChainResult<GenericWalletRuntimeHandle<W>>
    where
        W: WalletService + 'static,
    {
        let address = wallet.address();
        let checkpoint = sync_provider.latest_checkpoint();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let metrics_clone = Arc::clone(&metrics);
        let runtime_address = address.clone();
        let task = tokio::spawn(async move {
            metrics_clone
                .record_wallet_rpc_latency(WalletRpcMethod::Status, Duration::from_millis(0));
            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                if shutdown_rx.changed().await.is_err() {
                    break;
                }
            }
            debug!("wallet runtime loop stopped", address = %runtime_address);
        });

        let attached_to_node = if let Some(connector) = connector {
            connector.attach(wallet.as_ref())?;
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
            shutdown_tx,
            task: Mutex::new(Some(task)),
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
