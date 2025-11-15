#![allow(clippy::needless_return)]

#[cfg(not(feature = "wallet_gui"))]
fn main() {
    eprintln!("The wallet GUI is disabled. Rebuild with --features wallet_gui to enable it.");
    std::process::exit(1);
}

#[cfg(feature = "wallet_gui")]
fn main() -> iced::Result {
    use std::path::PathBuf;
    use std::time::Duration;

    use clap::Parser;

    use rpp_wallet::rpc::client::WalletRpcClient;
    use rpp_wallet::ui::{self, WalletGuiFlags};

    const DEFAULT_RPC_ENDPOINT: &str = "http://127.0.0.1:9090";

    #[derive(Debug, Parser)]
    #[command(name = "rpp-wallet-gui", about = "RPP wallet graphical interface")]
    struct Options {
        /// URL of the wallet RPC endpoint (without the trailing /rpc path).
        #[arg(long, value_name = "URL", env = "RPP_WALLET_RPC_ENDPOINT", default_value = DEFAULT_RPC_ENDPOINT)]
        endpoint: String,
        /// Bearer token used to authenticate with the wallet RPC (if enabled).
        #[arg(long, value_name = "TOKEN", env = "RPP_WALLET_RPC_AUTH_TOKEN")]
        auth_token: Option<String>,
        /// Timeout for RPC requests in seconds.
        #[arg(long, value_name = "SECONDS", default_value = "30")]
        timeout: u64,
        /// Optional wallet configuration file path surfaced in the UI.
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Interval (in seconds) used when polling sync status updates.
        #[arg(long, value_name = "SECONDS", default_value = "5")]
        sync_interval: u64,
    }

    let options = Options::parse();
    let client = match WalletRpcClient::from_endpoint(
        &options.endpoint,
        options.auth_token.clone(),
        None,
        Duration::from_secs(options.timeout),
    ) {
        Ok(client) => client,
        Err(error) => {
            eprintln!("Failed to initialise wallet RPC client: {error}");
            std::process::exit(2);
        }
    };

    let flags = WalletGuiFlags {
        client,
        config_path: options.config,
        sync_poll_interval: Duration::from_secs(options.sync_interval.max(1)),
    };

    ui::launch(flags)
}
