use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Error;
use clap::{ArgAction, Args};

pub use rpp_wallet_interface::runtime_config::RuntimeMode;

pub type BootstrapResult<T> = Result<T, BootstrapError>;

#[derive(Debug, Clone, Default, Args)]
pub struct PruningCliOverrides {
    /// Override the pruning cadence (seconds between scheduled runs)
    #[arg(long = "pruning-cadence-secs", value_name = "SECONDS")]
    pub cadence_secs: Option<u64>,

    /// Override the pruning retention depth (number of finalized blocks to keep hydrated)
    #[arg(long = "pruning-retention-depth", value_name = "BLOCKS")]
    pub retention_depth: Option<u64>,

    /// Pause automatic pruning cycles on startup
    #[arg(long = "pruning-pause", action = ArgAction::SetTrue)]
    pub pause: bool,

    /// Resume automatic pruning cycles on startup
    #[arg(long = "pruning-resume", action = ArgAction::SetTrue)]
    pub resume: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PruningOverrides {
    pub cadence_secs: Option<u64>,
    pub retention_depth: Option<u64>,
    pub emergency_pause: Option<bool>,
}

impl PruningCliOverrides {
    pub fn into_overrides(self) -> PruningOverrides {
        let PruningCliOverrides {
            cadence_secs,
            retention_depth,
            pause,
            resume,
        } = self;

        let mut emergency_pause = None;
        if pause {
            emergency_pause = Some(true);
        }
        if resume {
            emergency_pause = Some(false);
        }

        PruningOverrides {
            cadence_secs,
            retention_depth,
            emergency_pause,
        }
    }
}

/// Shared CLI arguments used across runtime entrypoints.
#[derive(Debug, Clone, Args)]
pub struct RuntimeOptions {
    /// Optional path to a node configuration file loaded before starting the runtime.
    /// The runtime does not watch for changes; restart after editing the file.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Optional path to a combined hybrid configuration file loaded before starting the runtime.
    /// Falls back to `--config` when unspecified.
    #[arg(long, value_name = "PATH")]
    pub hybrid_config: Option<PathBuf>,

    /// Optional path to a wallet configuration file loaded before starting the runtime.
    /// The runtime does not watch for changes; restart after editing the file.
    #[arg(long, value_name = "PATH")]
    pub wallet_config: Option<PathBuf>,

    /// Override the data directory defined in the node configuration
    #[arg(long, value_name = "PATH")]
    pub data_dir: Option<PathBuf>,

    /// Override the RPC listen address defined in the node configuration
    #[arg(long, value_name = "SOCKET")]
    pub rpc_listen: Option<SocketAddr>,

    /// Override the RPC authentication token defined in the node configuration
    #[arg(long, value_name = "TOKEN")]
    pub rpc_auth_token: Option<String>,

    /// Override the RPC allowed origin defined in the node configuration
    #[arg(long, value_name = "ORIGIN")]
    pub rpc_allowed_origin: Option<String>,

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

    /// (Deprecated) Logs are always emitted in structured JSON format
    #[arg(long)]
    pub log_json: bool,

    /// Validate configuration and exit without starting the runtime
    #[arg(long)]
    pub dry_run: bool,

    /// Persist the resulting configuration into the current working directory
    #[arg(long)]
    pub write_config: bool,

    /// Override the io-uring ring size defined in the node configuration
    #[arg(
        long = "storage-ring-size",
        value_name = "ENTRIES",
        env = "RPP_NODE_STORAGE_RING_SIZE"
    )]
    pub storage_ring_size: Option<u32>,

    #[command(flatten)]
    pub pruning: PruningCliOverrides,

    /// Launch the wallet alongside an embedded node using the hybrid runtime profile.
    #[arg(long = "with-node", action = ArgAction::SetTrue)]
    pub with_node: bool,
}

impl RuntimeOptions {
    pub fn into_bootstrap_options(self, mode: RuntimeMode) -> BootstrapOptions {
        let RuntimeOptions {
            config,
            hybrid_config,
            wallet_config,
            data_dir,
            rpc_listen,
            rpc_auth_token,
            rpc_allowed_origin,
            telemetry_endpoint,
            telemetry_auth_token,
            telemetry_sample_interval,
            log_level,
            log_json,
            dry_run,
            write_config,
            storage_ring_size,
            pruning,
            with_node: _,
        } = self;

        let hybrid_config = hybrid_config.or(config.clone());
        let node_config = if mode.includes_node() {
            if mode == RuntimeMode::Hybrid {
                hybrid_config.clone()
            } else {
                config.clone()
            }
        } else {
            None
        };

        let wallet_config = if mode.includes_wallet() {
            match mode {
                RuntimeMode::Wallet => wallet_config.or(config),
                RuntimeMode::Hybrid => wallet_config.or(hybrid_config),
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
            rpc_allowed_origin,
            telemetry_endpoint,
            telemetry_auth_token,
            telemetry_sample_interval,
            log_level,
            log_json,
            dry_run,
            write_config,
            storage_ring_size,
            pruning: pruning.into_overrides(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BootstrapOptions {
    pub node_config: Option<PathBuf>,
    pub wallet_config: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub rpc_listen: Option<SocketAddr>,
    pub rpc_auth_token: Option<String>,
    pub rpc_allowed_origin: Option<String>,
    pub telemetry_endpoint: Option<String>,
    pub telemetry_auth_token: Option<String>,
    pub telemetry_sample_interval: Option<u64>,
    pub log_level: Option<String>,
    pub log_json: bool,
    pub dry_run: bool,
    pub write_config: bool,
    pub storage_ring_size: Option<u32>,
    pub pruning: PruningOverrides,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapErrorKind {
    Configuration,
    Startup,
    Runtime,
}

impl BootstrapErrorKind {
    pub const fn exit_code(self) -> i32 {
        match self {
            BootstrapErrorKind::Configuration => 2,
            BootstrapErrorKind::Startup => 3,
            BootstrapErrorKind::Runtime => 4,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            BootstrapErrorKind::Configuration => "configuration",
            BootstrapErrorKind::Startup => "startup",
            BootstrapErrorKind::Runtime => "runtime",
        }
    }
}

impl fmt::Display for BootstrapErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub enum BootstrapError {
    Configuration(Error),
    Startup(Error),
    Runtime(Error),
}

impl BootstrapError {
    pub fn configuration<E>(error: E) -> Self
    where
        E: Into<Error>,
    {
        Self::Configuration(error.into())
    }

    pub fn startup<E>(error: E) -> Self
    where
        E: Into<Error>,
    {
        Self::Startup(error.into())
    }

    pub fn runtime<E>(error: E) -> Self
    where
        E: Into<Error>,
    {
        Self::Runtime(error.into())
    }

    pub fn exit_code(&self) -> i32 {
        self.kind().exit_code()
    }

    pub fn kind(&self) -> BootstrapErrorKind {
        match self {
            BootstrapError::Configuration(_) => BootstrapErrorKind::Configuration,
            BootstrapError::Startup(_) => BootstrapErrorKind::Startup,
            BootstrapError::Runtime(_) => BootstrapErrorKind::Runtime,
        }
    }

    pub fn inner(&self) -> &Error {
        match self {
            BootstrapError::Configuration(err)
            | BootstrapError::Startup(err)
            | BootstrapError::Runtime(err) => err,
        }
    }
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{0} error: {1}", self.kind(), self.inner())
    }
}

impl std::error::Error for BootstrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner().as_ref())
    }
}
