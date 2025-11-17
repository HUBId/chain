use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::{ChainError, ChainResult};
pub use rpp_wallet_interface::runtime_config::RuntimeMode;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct RuntimeProfileConfig {
    mode: Option<RuntimeMode>,
    node_config: Option<PathBuf>,
    wallet_config: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct RuntimeProfile {
    config: RuntimeProfileConfig,
    base_dir: PathBuf,
}

impl RuntimeProfile {
    pub fn load(name: &str) -> ChainResult<Self> {
        let profiles_dir = Path::new("config").join("profiles");
        let path = profiles_dir.join(format!("{name}.toml"));
        Self::load_from_path(&path)
    }

    pub fn load_from_path(path: &Path) -> ChainResult<Self> {
        if !path.exists() {
            return Err(ChainError::Config(format!(
                "runtime profile '{}' not found at {}",
                path.file_stem()
                    .and_then(|value| value.to_str())
                    .unwrap_or("unknown"),
                path.display()
            )));
        }
        let content = fs::read_to_string(path)?;
        let config: RuntimeProfileConfig = toml::from_str(&content).map_err(|err| {
            ChainError::Config(format!(
                "unable to parse runtime profile {}: {err}",
                path.display()
            ))
        })?;
        let base_dir = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Ok(Self { config, base_dir })
    }

    pub fn mode(&self) -> Option<RuntimeMode> {
        self.config.mode
    }

    pub fn node_config_path(&self) -> Option<PathBuf> {
        self.config
            .node_config
            .as_ref()
            .map(|path| self.resolve_path(path))
    }

    pub fn wallet_config_path(&self) -> Option<PathBuf> {
        self.config
            .wallet_config
            .as_ref()
            .map(|path| self.resolve_path(path))
    }

    fn resolve_path(&self, path: &PathBuf) -> PathBuf {
        if path.is_absolute() {
            path.clone()
        } else {
            self.base_dir.join(path)
        }
    }
}

pub mod node_runtime;
pub mod supervisor;
pub mod telemetry;
pub mod wallet_security;

#[cfg(feature = "wallet-integration")]
pub mod wallet;

pub use telemetry::metrics::{
    init_runtime_metrics, ConsensusStage, ProofKind, ProofRpcMethod, ProofVerificationBackend,
    ProofVerificationKind, ProofVerificationOutcome, ProofVerificationStage, RpcMethod, RpcResult,
    RuntimeMetrics, RuntimeMetricsGuard, WalFlushOutcome,
};

#[cfg(feature = "wallet-integration")]
pub use telemetry::metrics::WalletRpcMethod;
pub use telemetry::TelemetryExporterBuilder;
pub mod vrf_gossip;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn load_profile_from_relative_paths() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let profile_path = temp_dir.path().join("validator.toml");
        let mut file = fs::File::create(&profile_path).expect("profile file");
        writeln!(
            file,
            "mode = \"validator\"\nnode_config = \"../validator.toml\"\nwallet_config = \"../wallet.toml\""
        )
        .expect("write profile");
        drop(file);

        let profile = RuntimeProfile::load_from_path(&profile_path).expect("load profile");
        assert_eq!(profile.mode(), Some(RuntimeMode::Validator));
        assert_eq!(
            profile.node_config_path().expect("node path"),
            profile_path.parent().unwrap().join("../validator.toml")
        );
        assert_eq!(
            profile.wallet_config_path().expect("wallet path"),
            profile_path.parent().unwrap().join("../wallet.toml")
        );
    }

    #[test]
    fn missing_profile_returns_error() {
        let result = RuntimeProfile::load_from_path(Path::new("/tmp/does/not/exist.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn node_modes_use_expected_default_config_paths() {
        let expectations = [
            (RuntimeMode::Node, "config/node.toml"),
            (RuntimeMode::Hybrid, "config/hybrid.toml"),
            (RuntimeMode::Validator, "config/validator.toml"),
        ];

        for (mode, expected) in expectations {
            let resolved = mode.default_node_config_path().expect("node config path");
            assert_eq!(resolved, expected);
            assert_template_exists(resolved);
        }
    }

    #[test]
    fn wallet_modes_use_expected_default_config_paths() {
        let expectations = [
            (RuntimeMode::Wallet, "config/wallet.toml"),
            (RuntimeMode::Hybrid, "config/wallet.toml"),
            (RuntimeMode::Validator, "config/wallet.toml"),
        ];

        for (mode, expected) in expectations {
            let resolved = mode
                .default_wallet_config_path()
                .expect("wallet config path");
            assert_eq!(resolved, expected);
            assert_template_exists(resolved);
        }
    }

    #[test]
    fn wallet_mode_has_no_node_default_path() {
        assert!(RuntimeMode::Wallet.default_node_config_path().is_none());
    }

    #[test]
    fn node_mode_has_no_wallet_default_path() {
        assert!(RuntimeMode::Node.default_wallet_config_path().is_none());
    }

    fn assert_template_exists(relative: &str) {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root");
        let absolute = workspace_root.join(relative);
        assert!(
            absolute.exists(),
            "expected template {relative} to exist at {}",
            absolute.display()
        );
    }
}
