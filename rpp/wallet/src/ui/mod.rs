use iced::Settings;

use crate::rpc::client::WalletRpcClient;

mod app;
pub mod commands;
pub mod components;
pub mod error_map;
pub mod routes;
pub mod tabs;

pub use app::WalletApp;

use std::path::PathBuf;
use std::time::Duration;

/// Flags supplied by the binary entrypoint when launching the GUI.
#[derive(Debug, Clone)]
pub struct WalletGuiFlags {
    /// Pre-configured RPC client used to communicate with the wallet daemon.
    pub client: WalletRpcClient,
    /// Optional configuration file path surfaced to the operator.
    pub config_path: Option<PathBuf>,
    /// Interval used when polling the daemon for sync status updates.
    pub sync_poll_interval: Duration,
}

/// Launches the wallet GUI using the provided flags.
pub fn launch(flags: WalletGuiFlags) -> iced::Result {
    WalletApp::run(Settings::with_flags(flags))
}
