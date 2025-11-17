use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::Path;

pub mod config {
    use super::{anyhow, fs, Context, Path, Result};
    pub use rpp_wallet_interface::runtime_config::*;

    /// Extension trait providing convenience helpers around [`WalletConfig`].
    pub trait WalletConfigExt {
        /// Load and validate a wallet configuration from disk.
        fn load(path: &Path) -> Result<Self>
        where
            Self: Sized;
    }

    impl WalletConfigExt for WalletConfig {
        fn load(path: &Path) -> Result<Self> {
            let content = fs::read_to_string(path)
                .with_context(|| format!("unable to read wallet config {}", path.display()))?;
            let config: Self = toml::from_str(&content)
                .with_context(|| format!("unable to parse wallet config {}", path.display()))?;
            config
                .validate()
                .map_err(|err| anyhow!("invalid wallet config {}: {err}", path.display()))?;
            Ok(config)
        }
    }
}

pub mod node {
    pub use rpp_wallet_interface::runtime_config::MempoolStatus;
}

pub mod telemetry {
    pub use rpp_wallet_interface::runtime_telemetry::*;
}

pub mod wallet {
    pub use rpp_wallet_interface::runtime_wallet::*;
}

pub use rpp_wallet_interface::runtime_config::RuntimeMode;
