use std::fs;
use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::errors::{ChainError, ChainResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Node,
    Wallet,
    Hybrid,
    Validator,
}

impl RuntimeMode {
    pub fn includes_node(self) -> bool {
        matches!(
            self,
            RuntimeMode::Node | RuntimeMode::Hybrid | RuntimeMode::Validator
        )
    }

    pub fn includes_wallet(self) -> bool {
        matches!(
            self,
            RuntimeMode::Wallet | RuntimeMode::Hybrid | RuntimeMode::Validator
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeMode::Node => "node",
            RuntimeMode::Wallet => "wallet",
            RuntimeMode::Hybrid => "hybrid",
            RuntimeMode::Validator => "validator",
        }
    }
}

impl Default for RuntimeMode {
    fn default() -> Self {
        RuntimeMode::Node
    }
}

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
pub mod telemetry;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_profile_from_relative_paths() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let profile_path = temp_dir.path().join("validator.toml");
        let mut file = fs::File::create(&profile_path).expect("profile file");
        writeln!(
            file,
            "mode = \"validator\"\nnode_config = \"../node.toml\"\nwallet_config = \"../wallet.toml\""
        )
        .expect("write profile");
        drop(file);

        let profile = RuntimeProfile::load_from_path(&profile_path).expect("load profile");
        assert_eq!(profile.mode(), Some(RuntimeMode::Validator));
        assert_eq!(
            profile.node_config_path().expect("node path"),
            profile_path.parent().unwrap().join("../node.toml")
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
}
