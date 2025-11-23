use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::Path;

pub mod config {
    use super::{anyhow, fs, Context, Path, Result};
    pub use rpp_wallet_interface::runtime_config::*;
    use serde::de::DeserializeOwned;
    use serde_ignored;

    /// Extension trait providing convenience helpers around [`WalletConfig`].
    pub trait WalletConfigExt {
        /// Load and validate a wallet configuration from disk.
        fn load(path: &Path) -> Result<Self>
        where
            Self: Sized;
    }

    pub(crate) fn parse_strict_wallet_config<T: DeserializeOwned>(
        content: &str,
        path: &Path,
    ) -> Result<T> {
        let mut unknown_keys = Vec::new();
        let mut deserializer = toml::de::Deserializer::new(content);

        let value = serde_ignored::deserialize(&mut deserializer, |path| {
            unknown_keys.push(path.to_string());
        })
        .with_context(|| format!("unable to parse wallet config {}", path.display()))?;

        if !unknown_keys.is_empty() {
            return Err(anyhow!(
                "invalid wallet config {}: unknown configuration key(s): {}",
                path.display(),
                unknown_keys.join(", ")
            ));
        }

        Ok(value)
    }

    impl WalletConfigExt for WalletConfig {
        fn load(path: &Path) -> Result<Self> {
            let content = fs::read_to_string(path)
                .with_context(|| format!("unable to read wallet config {}", path.display()))?;
            let config: Self = parse_strict_wallet_config(&content, path)?;
            config
                .validate()
                .map_err(|err| anyhow!("invalid wallet config {}: {err}", path.display()))?;
            Ok(config)
        }
    }
}

pub mod lifecycle;

pub mod node {
    pub use rpp_wallet_interface::runtime_config::MempoolStatus;
}

pub mod telemetry {
    pub use rpp_wallet_interface::runtime_telemetry::*;
}

pub mod wallet {
    pub use rpp_wallet_interface::runtime_wallet::*;
}

#[cfg(test)]
mod tests {
    use super::config::{parse_strict_wallet_config, WalletConfig};
    use super::config::{WalletProverBackend, WalletProverSettings};
    use std::path::Path;

    #[test]
    fn wallet_config_defaults_include_prover_backend_controls() {
        let config = parse_strict_wallet_config::<WalletConfig>("", Path::new("defaults"))
            .expect("defaults parse");

        let WalletProverSettings {
            enabled,
            backend,
            require_proof,
            allow_broadcast_without_proof,
            ..
        } = config.wallet.prover;

        assert!(enabled);
        assert_eq!(backend, WalletProverBackend::Mock);
        assert!(!require_proof);
        assert!(!allow_broadcast_without_proof);
    }

    #[test]
    fn wallet_config_rejects_unknown_prover_fields() {
        let toml = r#"
[wallet.prover]
enabled = true
backend = "mock"
unknown_toggle = true
"#;

        let err = parse_strict_wallet_config::<WalletConfig>(toml, Path::new("unknown"))
            .expect_err("unknown keys should fail");
        let message = err.to_string();
        assert!(message.contains("unknown configuration key"), "{message}");
        assert!(
            message.contains("wallet.prover.unknown_toggle"),
            "unexpected message: {message}"
        );
    }
}

pub use lifecycle::{
    EmbeddedNodeCommand, EmbeddedNodeError, EmbeddedNodeLifecycle, EmbeddedNodeStatus,
};
pub use rpp_wallet_interface::runtime_config::RuntimeMode;
