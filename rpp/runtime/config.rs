use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::{ChainError, ChainResult};
use crate::ledger::DEFAULT_EPOCH_LENGTH;
use crate::reputation::{ReputationParams, ReputationWeights, TierThresholds};
use crate::types::Stake;

const QUEUE_WEIGHT_SUM_TOLERANCE: f64 = 1e-6;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct P2pConfig {
    pub listen_addr: String,
    pub bootstrap_peers: Vec<String>,
    pub heartbeat_interval_ms: u64,
    pub gossip_enabled: bool,
    #[serde(default = "default_peerstore_path")]
    pub peerstore_path: PathBuf,
    #[serde(default = "default_gossip_state_path")]
    pub gossip_path: Option<PathBuf>,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/7600".to_string(),
            bootstrap_peers: Vec::new(),
            heartbeat_interval_ms: 5_000,
            gossip_enabled: true,
            peerstore_path: default_peerstore_path(),
            gossip_path: default_gossip_state_path(),
        }
    }
}

pub const NODE_CONFIG_VERSION: &str = "1.0";

fn default_node_config_version() -> String {
    NODE_CONFIG_VERSION.to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    #[serde(default = "default_node_config_version")]
    pub config_version: String,
    pub data_dir: PathBuf,
    pub key_path: PathBuf,
    #[serde(default = "default_p2p_key_path")]
    pub p2p_key_path: PathBuf,
    pub vrf_key_path: PathBuf,
    #[serde(default = "default_snapshot_dir")]
    pub snapshot_dir: PathBuf,
    #[serde(default = "default_proof_cache_dir")]
    pub proof_cache_dir: PathBuf,
    pub rpc_listen: SocketAddr,
    #[serde(default)]
    pub rpc_auth_token: Option<String>,
    #[serde(default)]
    pub rpc_allowed_origin: Option<String>,
    #[serde(default)]
    pub rpc_requests_per_minute: Option<u64>,
    pub block_time_ms: u64,
    pub max_block_transactions: usize,
    #[serde(default = "default_max_block_identity_registrations")]
    pub max_block_identity_registrations: usize,
    pub mempool_limit: usize,
    #[serde(default = "default_epoch_length")]
    pub epoch_length: u64,
    #[serde(default = "default_target_validator_count")]
    pub target_validator_count: usize,
    #[serde(default = "default_max_proof_size_bytes")]
    pub max_proof_size_bytes: usize,
    #[serde(default)]
    pub rollout: RolloutConfig,
    #[serde(default)]
    pub p2p: P2pConfig,
    pub genesis: GenesisConfig,
    #[serde(default)]
    pub reputation: ReputationConfig,
    #[serde(default)]
    pub queue_weights: QueueWeightsConfig,
}

fn default_max_block_identity_registrations() -> usize {
    32
}

fn default_epoch_length() -> u64 {
    DEFAULT_EPOCH_LENGTH
}

fn default_target_validator_count() -> usize {
    100
}

fn default_snapshot_dir() -> PathBuf {
    PathBuf::from("./data/snapshots")
}

fn default_proof_cache_dir() -> PathBuf {
    PathBuf::from("./data/proofs")
}

fn default_p2p_key_path() -> PathBuf {
    PathBuf::from("./keys/p2p.toml")
}

fn default_peerstore_path() -> PathBuf {
    PathBuf::from("./data/p2p/peerstore.json")
}

fn default_gossip_path() -> PathBuf {
    PathBuf::from("./data/p2p/gossip.json")
}

fn default_gossip_state_path() -> Option<PathBuf> {
    Some(default_gossip_path())
}

fn default_max_proof_size_bytes() -> usize {
    4 * 1024 * 1024
}

impl NodeConfig {
    pub fn load(path: &Path) -> ChainResult<Self> {
        let content = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)
            .map_err(|err| ChainError::Config(format!("unable to parse config: {err}")))?;
        config.validate()?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> ChainResult<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        self.validate()?;
        let encoded = toml::to_string_pretty(self)
            .map_err(|err| ChainError::Config(format!("unable to encode config: {err}")))?;
        fs::write(path, encoded)?;
        Ok(())
    }

    pub fn ensure_directories(&self) -> ChainResult<()> {
        fs::create_dir_all(&self.data_dir)?;
        if let Some(parent) = self.key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = self.p2p_key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = self.vrf_key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&self.snapshot_dir)?;
        fs::create_dir_all(&self.proof_cache_dir)?;
        if let Some(parent) = self.p2p.peerstore_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(path) = self.p2p.gossip_path.as_ref() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
        }
        Ok(())
    }

    pub fn reputation_params(&self) -> ReputationParams {
        self.reputation.reputation_params()
    }

    pub fn validate(&self) -> ChainResult<()> {
        let version = self.config_version.trim();
        if version.is_empty() {
            return Err(ChainError::Config(
                "node configuration requires config_version to be set".into(),
            ));
        }
        if version != NODE_CONFIG_VERSION {
            return Err(ChainError::Config(format!(
                "node configuration config_version {version} is not supported; expected {NODE_CONFIG_VERSION}"
            )));
        }
        if self.block_time_ms == 0 {
            return Err(ChainError::Config(
                "node configuration requires block_time_ms to be greater than 0".into(),
            ));
        }
        if self.max_block_transactions == 0 {
            return Err(ChainError::Config(
                "node configuration requires max_block_transactions to be greater than 0".into(),
            ));
        }
        if self.max_block_identity_registrations == 0 {
            return Err(ChainError::Config(
                "node configuration requires max_block_identity_registrations to be greater than 0"
                    .into(),
            ));
        }
        if self.mempool_limit == 0 {
            return Err(ChainError::Config(
                "node configuration requires mempool_limit to be greater than 0".into(),
            ));
        }
        if self.epoch_length == 0 {
            return Err(ChainError::Config(
                "node configuration requires epoch_length to be greater than 0".into(),
            ));
        }
        if self.target_validator_count == 0 {
            return Err(ChainError::Config(
                "node configuration requires target_validator_count to be greater than 0".into(),
            ));
        }
        if self.max_proof_size_bytes == 0 {
            return Err(ChainError::Config(
                "node configuration requires max_proof_size_bytes to be greater than 0".into(),
            ));
        }
        if let Some(token) = &self.rpc_auth_token {
            if token.trim().is_empty() {
                return Err(ChainError::Config(
                    "node configuration rpc_auth_token must not be empty".into(),
                ));
            }
        }
        if let Some(origin) = &self.rpc_allowed_origin {
            if origin.trim().is_empty() {
                return Err(ChainError::Config(
                    "node configuration rpc_allowed_origin must not be empty".into(),
                ));
            }
        }
        if let Some(limit) = self.rpc_requests_per_minute {
            if limit == 0 {
                return Err(ChainError::Config(
                    "node configuration rpc_requests_per_minute must be greater than 0".into(),
                ));
            }
        }
        self.queue_weights.validate()?;
        Ok(())
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        let mut p2p = P2pConfig::default();
        p2p.peerstore_path = default_peerstore_path();
        p2p.gossip_path = default_gossip_state_path();
        Self {
            config_version: default_node_config_version(),
            data_dir: PathBuf::from("./data"),
            key_path: PathBuf::from("./keys/node.toml"),
            p2p_key_path: default_p2p_key_path(),
            vrf_key_path: PathBuf::from("./keys/vrf.toml"),
            snapshot_dir: default_snapshot_dir(),
            proof_cache_dir: default_proof_cache_dir(),
            rpc_listen: "127.0.0.1:7070".parse().expect("valid socket addr"),
            rpc_auth_token: None,
            rpc_allowed_origin: None,
            rpc_requests_per_minute: None,
            block_time_ms: 5_000,
            max_block_transactions: 512,
            max_block_identity_registrations: default_max_block_identity_registrations(),
            mempool_limit: 8_192,
            epoch_length: default_epoch_length(),
            target_validator_count: default_target_validator_count(),
            max_proof_size_bytes: default_max_proof_size_bytes(),
            rollout: RolloutConfig::default(),
            p2p,
            genesis: GenesisConfig::default(),
            reputation: ReputationConfig::default(),
            queue_weights: QueueWeightsConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct QueueWeightsConfig {
    pub priority: f64,
    pub fee: f64,
}

impl QueueWeightsConfig {
    pub fn validate(&self) -> ChainResult<()> {
        if self.priority.is_nan() || self.fee.is_nan() {
            return Err(ChainError::Config(
                "queue_weights priority and fee must be finite numbers".into(),
            ));
        }
        if self.priority < 0.0 {
            return Err(ChainError::Config(
                "queue_weights.priority must be greater than or equal to 0.0".into(),
            ));
        }
        if self.fee < 0.0 {
            return Err(ChainError::Config(
                "queue_weights.fee must be greater than or equal to 0.0".into(),
            ));
        }
        let sum = self.priority + self.fee;
        if (sum - 1.0).abs() > QUEUE_WEIGHT_SUM_TOLERANCE {
            return Err(ChainError::Config(
                "queue_weights priority and fee must sum to 1.0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for QueueWeightsConfig {
    fn default() -> Self {
        Self {
            priority: 0.7,
            fee: 0.3,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ReputationConfig {
    pub tier_thresholds: TierThresholds,
    pub weights: Option<ReputationWeights>,
}

impl ReputationConfig {
    pub fn reputation_params(&self) -> ReputationParams {
        let weights = self
            .weights
            .clone()
            .unwrap_or_else(ReputationWeights::default);
        ReputationParams {
            weights,
            tier_thresholds: self.tier_thresholds.clone(),
            ..ReputationParams::default()
        }
    }
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            tier_thresholds: TierThresholds::default(),
            weights: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reputation_config_applies_weight_overrides() {
        let custom = ReputationWeights::new(0.5, 0.2, 0.2, 0.05, 0.05).unwrap();
        let config = ReputationConfig {
            weights: Some(custom.clone()),
            ..Default::default()
        };

        let params = config.reputation_params();
        assert!((params.weights.validation() - custom.validation()).abs() < f64::EPSILON);
        assert!((params.weights.decay() - custom.decay()).abs() < f64::EPSILON);

        let default_params = ReputationConfig::default().reputation_params();
        assert!(
            (default_params.weights.validation() - ReputationWeights::default().validation()).abs()
                < f64::EPSILON
        );
    }

    #[test]
    fn node_config_validation_accepts_defaults() {
        let config = NodeConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn node_config_validation_rejects_mismatched_config_version() {
        let mut config = NodeConfig::default();
        config.config_version = "2.0".to_string();
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("config_version"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn node_config_validation_rejects_missing_config_version() {
        let mut config = NodeConfig::default();
        config.config_version.clear();
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("config_version"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn node_config_validation_rejects_zero_block_time() {
        let mut config = NodeConfig::default();
        config.block_time_ms = 0;
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("block_time_ms"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn node_config_validation_rejects_zero_mempool_limit() {
        let mut config = NodeConfig::default();
        config.mempool_limit = 0;
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("mempool_limit"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn node_config_validation_rejects_invalid_queue_weights() {
        let mut config = NodeConfig::default();
        config.queue_weights.priority = 0.8;
        config.queue_weights.fee = 0.3;
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("queue_weights"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub data_dir: PathBuf,
    pub key_path: PathBuf,
    #[serde(default = "default_wallet_rpc_listen")]
    pub rpc_listen: SocketAddr,
    #[serde(default)]
    pub node: WalletNodeRuntimeConfig,
}

fn default_wallet_rpc_listen() -> SocketAddr {
    "127.0.0.1:9090".parse().expect("valid socket addr")
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletNodeRuntimeConfig {
    /// Enable an embedded node alongside the wallet runtime.
    pub embedded: bool,
    /// Gossip peers the wallet should connect to when running in client mode.
    pub gossip_endpoints: Vec<String>,
}

impl WalletConfig {
    pub fn load(path: &Path) -> ChainResult<Self> {
        let content = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)
            .map_err(|err| ChainError::Config(format!("unable to parse wallet config: {err}")))?;
        config.validate()?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> ChainResult<()> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        self.validate()?;
        let encoded = toml::to_string_pretty(self)
            .map_err(|err| ChainError::Config(format!("unable to encode wallet config: {err}")))?;
        fs::write(path, encoded)?;
        Ok(())
    }

    pub fn ensure_directories(&self) -> ChainResult<()> {
        fs::create_dir_all(&self.data_dir)?;
        if let Some(parent) = self.key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(())
    }

    fn validate(&self) -> ChainResult<()> {
        if !self.node.embedded && self.node.gossip_endpoints.is_empty() {
            return Err(ChainError::Config(
                "wallet node runtime requires gossip endpoints when embedded node is disabled"
                    .into(),
            ));
        }
        if self
            .node
            .gossip_endpoints
            .iter()
            .any(|endpoint| endpoint.trim().is_empty())
        {
            return Err(ChainError::Config(
                "wallet node runtime gossip endpoints must not be empty".into(),
            ));
        }
        Ok(())
    }
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            key_path: PathBuf::from("./keys/wallet.toml"),
            rpc_listen: default_wallet_rpc_listen(),
            node: WalletNodeRuntimeConfig {
                embedded: false,
                gossip_endpoints: vec!["/ip4/127.0.0.1/tcp/7600".to_string()],
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub chain_id: String,
    pub accounts: Vec<GenesisAccount>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    Development,
    Testnet,
    Canary,
    Mainnet,
}

impl Default for ReleaseChannel {
    fn default() -> Self {
        ReleaseChannel::Development
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeatureGates {
    pub pruning: bool,
    pub recursive_proofs: bool,
    pub reconstruction: bool,
    pub consensus_enforcement: bool,
}

impl Default for FeatureGates {
    fn default() -> Self {
        Self {
            pruning: true,
            recursive_proofs: true,
            reconstruction: true,
            consensus_enforcement: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub auth_token: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_retry_max")]
    pub retry_max: u64,
    #[serde(default = "default_sample_interval_secs")]
    pub sample_interval_secs: u64,
    #[serde(default = "default_redact_logs")]
    pub redact_logs: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            auth_token: None,
            timeout_ms: default_timeout_ms(),
            retry_max: default_retry_max(),
            sample_interval_secs: default_sample_interval_secs(),
            redact_logs: default_redact_logs(),
        }
    }
}

fn default_timeout_ms() -> u64 {
    5_000
}

fn default_retry_max() -> u64 {
    3
}

fn default_sample_interval_secs() -> u64 {
    30
}

fn default_redact_logs() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RolloutConfig {
    pub release_channel: ReleaseChannel,
    pub feature_gates: FeatureGates,
    pub telemetry: TelemetryConfig,
}

impl Default for RolloutConfig {
    fn default() -> Self {
        Self {
            release_channel: ReleaseChannel::default(),
            feature_gates: FeatureGates::default(),
            telemetry: TelemetryConfig::default(),
        }
    }
}

impl Default for GenesisConfig {
    fn default() -> Self {
        Self {
            chain_id: "rpp-local".to_string(),
            accounts: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAccount {
    pub address: String,
    pub balance: u128,
    pub stake: String,
}

impl GenesisAccount {
    pub fn stake_value(&self) -> ChainResult<Stake> {
        self.stake
            .parse()
            .map_err(|_| ChainError::Config("invalid genesis stake".to_string()))
    }
}
