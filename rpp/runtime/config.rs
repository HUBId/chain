use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

use rpp_p2p::TierLevel;

#[cfg(feature = "vendor_electrs")]
use rpp_wallet::config::ElectrsConfig;

use crate::consensus_engine::state::{TreasuryAccounts, WitnessPoolWeights};
use crate::crypto::{
    DynVrfKeyStore, FilesystemKeystoreConfig, FilesystemVrfKeyStore, HsmKeystoreConfig,
    VaultKeystoreConfig, VaultVrfKeyStore, VrfKeyIdentifier, VrfKeypair,
};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::DEFAULT_EPOCH_LENGTH;
use crate::reputation::{ReputationParams, ReputationWeights, TierThresholds, TimetokeParams};
use crate::runtime::RuntimeMode;
use crate::types::Stake;

const QUEUE_WEIGHT_SUM_TOLERANCE: f64 = 1e-6;
const MALACHITE_CONFIG_VERSION_REQ: &str = ">=1.0.0, <2.0.0";
const MALACHITE_CONFIG_VERSION_DEFAULT: &str = "1.0.0";
const MALACHITE_CONFIG_FILE: &str = "malachite.toml";
const DEFAULT_MALACHITE_CONFIG_PATH: &str = "config/malachite.toml";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SecretsConfig {
    pub backend: SecretsBackendConfig,
}

impl SecretsConfig {
    pub fn build_keystore(&self) -> ChainResult<DynVrfKeyStore> {
        self.backend.build_keystore()
    }

    pub fn vrf_identifier(&self, configured: &Path) -> ChainResult<VrfKeyIdentifier> {
        self.backend.vrf_identifier(configured)
    }

    pub fn ensure_directories(&self, configured: &Path) -> ChainResult<()> {
        self.backend.ensure_directories(configured)
    }

    pub fn validate_with_path(&self, configured: &Path) -> ChainResult<()> {
        self.backend.validate_with_path(configured)
    }

    pub fn load_or_generate_vrf_keypair(&self, configured: &Path) -> ChainResult<VrfKeypair> {
        let identifier = self.vrf_identifier(configured)?;
        let store = self.build_keystore()?;
        store.load_or_generate(&identifier)
    }
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            backend: SecretsBackendConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum SecretsBackendConfig {
    Filesystem(FilesystemKeystoreConfig),
    Vault(VaultKeystoreConfig),
    Hsm(HsmKeystoreConfig),
}

impl Default for SecretsBackendConfig {
    fn default() -> Self {
        Self::Filesystem(FilesystemKeystoreConfig::default())
    }
}

impl SecretsBackendConfig {
    fn build_keystore(&self) -> ChainResult<DynVrfKeyStore> {
        match self {
            Self::Filesystem(config) => Ok(Arc::new(FilesystemVrfKeyStore::new(config.clone()))),
            Self::Vault(config) => Ok(Arc::new(VaultVrfKeyStore::new(config.clone())?)),
            Self::Hsm(_) => Err(ChainError::Config(
                "HSM secrets backend is not available in this build; configure `filesystem` or `vault`".into(),
            )),
        }
    }

    fn vrf_identifier(&self, configured: &Path) -> ChainResult<VrfKeyIdentifier> {
        match self {
            Self::Filesystem(config) => {
                Ok(VrfKeyIdentifier::filesystem(config.resolve(configured)))
            }
            Self::Vault(_) | Self::Hsm(_) => {
                let raw = configured.to_string_lossy();
                let trimmed = raw.trim_matches('/');
                if trimmed.is_empty() {
                    Err(ChainError::Config(
                        "secrets backend requires `vrf_key_path` to define a non-empty identifier"
                            .into(),
                    ))
                } else {
                    Ok(VrfKeyIdentifier::remote(trimmed.to_string()))
                }
            }
        }
    }

    fn ensure_directories(&self, configured: &Path) -> ChainResult<()> {
        match self {
            Self::Filesystem(config) => {
                let path = config.resolve(configured);
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                Ok(())
            }
            Self::Vault(_) | Self::Hsm(_) => Ok(()),
        }
    }

    fn validate_with_path(&self, configured: &Path) -> ChainResult<()> {
        match self {
            Self::Filesystem(_) => Ok(()),
            Self::Vault(config) => {
                config.validate()?;
                let raw = configured.to_string_lossy();
                if raw.trim_matches('/').is_empty() {
                    return Err(ChainError::Config(
                        "vault secrets backend requires `vrf_key_path` to reference a KV path"
                            .into(),
                    ));
                }
                Ok(())
            }
            Self::Hsm(_) => Err(ChainError::Config(
                "HSM secrets backend is not implemented; configure `filesystem` or `vault`".into(),
            )),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct MalachiteConfig {
    pub config_version: String,
    pub validator: ValidatorSelectionConfig,
    pub reputation: MalachiteReputationConfig,
    pub rewards: MalachiteRewardsConfig,
    pub proof: MalachiteProofConfig,
    pub network: MalachiteNetworkConfig,
}

impl MalachiteConfig {
    pub fn load_from_path(path: &Path) -> ChainResult<Self> {
        match fs::read_to_string(path) {
            Ok(content) => {
                let mut config: Self = toml::from_str(&content).map_err(|err| {
                    ChainError::Config(format!("unable to parse malachite config: {err}"))
                })?;
                config.validate()?;
                Ok(config)
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                let mut config = Self::default();
                config.validate()?;
                Ok(config)
            }
            Err(err) => Err(err.into()),
        }
    }

    pub fn load_default() -> ChainResult<Self> {
        Self::load_from_path(Path::new(DEFAULT_MALACHITE_CONFIG_PATH))
    }

    pub fn validate(&self) -> ChainResult<()> {
        let version = self
            .config_version
            .trim()
            .parse::<Version>()
            .map_err(|err| {
                ChainError::Config(format!(
                    "malachite configuration has invalid config_version `{}`: {err}",
                    self.config_version
                ))
            })?;
        let requirement = VersionReq::parse(MALACHITE_CONFIG_VERSION_REQ)
            .expect("static version requirement must be valid");
        if !requirement.matches(&version) {
            return Err(ChainError::Config(format!(
                "malachite configuration config_version {} is incompatible; expected {}",
                version, MALACHITE_CONFIG_VERSION_REQ
            )));
        }

        self.validator.validate()?;
        self.reputation.validate()?;
        self.rewards.validate()?;
        self.proof.validate()?;
        self.network.validate()?;
        Ok(())
    }
}

impl Default for MalachiteConfig {
    fn default() -> Self {
        Self {
            config_version: MALACHITE_CONFIG_VERSION_DEFAULT.to_string(),
            validator: ValidatorSelectionConfig::default(),
            reputation: MalachiteReputationConfig::default(),
            rewards: MalachiteRewardsConfig::default(),
            proof: MalachiteProofConfig::default(),
            network: MalachiteNetworkConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ValidatorSelectionConfig {
    pub validator_set_size: usize,
    pub witness_count: usize,
    pub vrf_threshold_curve: String,
    pub epoch_duration_secs: u64,
    pub round_timeout_ms: u64,
    pub max_round_extensions: u32,
}

impl ValidatorSelectionConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.validator_set_size == 0 {
            return Err(ChainError::Config(
                "malachite validator.validator_set_size must be greater than 0".into(),
            ));
        }
        if self.witness_count == 0 {
            return Err(ChainError::Config(
                "malachite validator.witness_count must be greater than 0".into(),
            ));
        }
        if self.vrf_threshold_curve.trim().is_empty() {
            return Err(ChainError::Config(
                "malachite validator.vrf_threshold_curve must not be empty".into(),
            ));
        }
        if self.epoch_duration_secs == 0 {
            return Err(ChainError::Config(
                "malachite validator.epoch_duration_secs must be greater than 0".into(),
            ));
        }
        if self.round_timeout_ms == 0 {
            return Err(ChainError::Config(
                "malachite validator.round_timeout_ms must be greater than 0".into(),
            ));
        }
        if self.max_round_extensions == 0 {
            return Err(ChainError::Config(
                "malachite validator.max_round_extensions must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for ValidatorSelectionConfig {
    fn default() -> Self {
        Self {
            validator_set_size: 100,
            witness_count: 16,
            vrf_threshold_curve: "linear:v0.6-b0.2".to_string(),
            epoch_duration_secs: 86_400,
            round_timeout_ms: 6_000,
            max_round_extensions: 3,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct MalachiteReputationConfig {
    pub tier_thresholds: TierThresholds,
    pub weights: ReputationWeights,
    pub decay_interval_secs: u64,
    pub decay_factor: f64,
    pub snapshot_interval_secs: u64,
    pub max_snapshot_age_secs: u64,
    pub timetoke: MalachiteTimetokeConfig,
}

impl MalachiteReputationConfig {
    fn validate(&self) -> ChainResult<()> {
        self.weights.validate().map_err(|err| {
            ChainError::Config(format!("malachite reputation.weights invalid: {err}"))
        })?;
        if self.decay_interval_secs == 0 {
            return Err(ChainError::Config(
                "malachite reputation.decay_interval_secs must be greater than 0".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.decay_factor) {
            return Err(ChainError::Config(
                "malachite reputation.decay_factor must be within [0.0, 1.0]".into(),
            ));
        }
        if self.snapshot_interval_secs == 0 {
            return Err(ChainError::Config(
                "malachite reputation.snapshot_interval_secs must be greater than 0".into(),
            ));
        }
        if self.max_snapshot_age_secs == 0 {
            return Err(ChainError::Config(
                "malachite reputation.max_snapshot_age_secs must be greater than 0".into(),
            ));
        }
        self.timetoke.validate()?;
        Ok(())
    }

    pub fn reputation_params(&self) -> ReputationParams {
        ReputationParams {
            weights: self.weights.clone(),
            tier_thresholds: self.tier_thresholds.clone(),
            decay_interval_secs: self.decay_interval_secs,
            decay_factor: self.decay_factor,
        }
    }

    pub fn timetoke_params(&self) -> TimetokeParams {
        TimetokeParams {
            minimum_window_secs: self.timetoke.minimum_window_secs,
            accrual_cap_hours: self.timetoke.accrual_cap_hours,
            decay_interval_secs: self.timetoke.decay_interval_secs,
            decay_step_hours: self.timetoke.decay_step_hours,
            sync_interval_secs: self.timetoke.sync_interval_secs,
        }
    }
}

impl Default for MalachiteReputationConfig {
    fn default() -> Self {
        let reputation = ReputationParams::default();
        let timetoke = TimetokeParams::default();
        Self {
            tier_thresholds: reputation.tier_thresholds,
            weights: reputation.weights,
            decay_interval_secs: reputation.decay_interval_secs,
            decay_factor: reputation.decay_factor,
            snapshot_interval_secs: 600,
            max_snapshot_age_secs: 3_600,
            timetoke: MalachiteTimetokeConfig {
                minimum_window_secs: timetoke.minimum_window_secs,
                accrual_cap_hours: timetoke.accrual_cap_hours,
                decay_interval_secs: timetoke.decay_interval_secs,
                decay_step_hours: timetoke.decay_step_hours,
                sync_interval_secs: timetoke.sync_interval_secs,
            },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct MalachiteTimetokeConfig {
    pub minimum_window_secs: u64,
    pub accrual_cap_hours: u64,
    pub decay_interval_secs: u64,
    pub decay_step_hours: u64,
    pub sync_interval_secs: u64,
}

impl MalachiteTimetokeConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.minimum_window_secs == 0 {
            return Err(ChainError::Config(
                "malachite reputation.timetoke.minimum_window_secs must be greater than 0".into(),
            ));
        }
        if self.accrual_cap_hours == 0 {
            return Err(ChainError::Config(
                "malachite reputation.timetoke.accrual_cap_hours must be greater than 0".into(),
            ));
        }
        if self.decay_interval_secs == 0 {
            return Err(ChainError::Config(
                "malachite reputation.timetoke.decay_interval_secs must be greater than 0".into(),
            ));
        }
        if self.decay_step_hours == 0 {
            return Err(ChainError::Config(
                "malachite reputation.timetoke.decay_step_hours must be greater than 0".into(),
            ));
        }
        if self.sync_interval_secs == 0 {
            return Err(ChainError::Config(
                "malachite reputation.timetoke.sync_interval_secs must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for MalachiteTimetokeConfig {
    fn default() -> Self {
        let params = TimetokeParams::default();
        Self {
            minimum_window_secs: params.minimum_window_secs,
            accrual_cap_hours: params.accrual_cap_hours,
            decay_interval_secs: params.decay_interval_secs,
            decay_step_hours: params.decay_step_hours,
            sync_interval_secs: params.sync_interval_secs,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct MalachiteRewardsConfig {
    pub base_block_reward: u64,
    pub leader_bonus_pct: f64,
    pub witness_reward_pct: f64,
    pub double_sign_penalty: u64,
    pub fake_proof_penalty: u64,
    pub inactivity_penalty: u64,
    pub treasury_accounts: TreasuryAccountsConfig,
    pub witness_pool_weights: WitnessPoolWeightsConfig,
}

impl MalachiteRewardsConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.base_block_reward == 0 {
            return Err(ChainError::Config(
                "malachite rewards.base_block_reward must be greater than 0".into(),
            ));
        }
        for (name, value) in [
            ("leader_bonus_pct", self.leader_bonus_pct),
            ("witness_reward_pct", self.witness_reward_pct),
        ] {
            if !(0.0..=1.0).contains(&value) {
                return Err(ChainError::Config(format!(
                    "malachite rewards.{name} must be within [0.0, 1.0]"
                )));
            }
        }
        if self.double_sign_penalty == 0 {
            return Err(ChainError::Config(
                "malachite rewards.double_sign_penalty must be greater than 0".into(),
            ));
        }
        if self.fake_proof_penalty == 0 {
            return Err(ChainError::Config(
                "malachite rewards.fake_proof_penalty must be greater than 0".into(),
            ));
        }
        if self.inactivity_penalty == 0 {
            return Err(ChainError::Config(
                "malachite rewards.inactivity_penalty must be greater than 0".into(),
            ));
        }
        self.treasury_accounts.validate()?;
        self.witness_pool_weights.validate()?;
        Ok(())
    }

    pub fn treasury_accounts(&self) -> TreasuryAccounts {
        TreasuryAccounts::new(
            self.treasury_accounts.validator.clone(),
            self.treasury_accounts.witness.clone(),
            self.treasury_accounts.fee_pool.clone(),
        )
    }

    pub fn witness_pool_weights(&self) -> WitnessPoolWeights {
        WitnessPoolWeights::new(
            self.witness_pool_weights.treasury,
            self.witness_pool_weights.fees,
        )
    }
}

impl Default for MalachiteRewardsConfig {
    fn default() -> Self {
        Self {
            base_block_reward: 100_000_000,
            leader_bonus_pct: 0.15,
            witness_reward_pct: 0.25,
            double_sign_penalty: 50_000_000,
            fake_proof_penalty: 50_000_000,
            inactivity_penalty: 25_000_000,
            treasury_accounts: TreasuryAccountsConfig::default(),
            witness_pool_weights: WitnessPoolWeightsConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TreasuryAccountsConfig {
    pub validator: String,
    pub witness: String,
    pub fee_pool: String,
}

impl TreasuryAccountsConfig {
    fn validate(&self) -> ChainResult<()> {
        for (label, value) in [
            ("validator", &self.validator),
            ("witness", &self.witness),
            ("fee_pool", &self.fee_pool),
        ] {
            if value.trim().is_empty() {
                return Err(ChainError::Config(format!(
                    "malachite rewards.treasury_accounts.{label} must not be empty"
                )));
            }
        }
        Ok(())
    }
}

impl Default for TreasuryAccountsConfig {
    fn default() -> Self {
        Self {
            validator: "treasury-validator".into(),
            witness: "treasury-witness".into(),
            fee_pool: "treasury-fees".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WitnessPoolWeightsConfig {
    pub treasury: f64,
    pub fees: f64,
}

impl WitnessPoolWeightsConfig {
    fn validate(&self) -> ChainResult<()> {
        for (label, value) in [("treasury", self.treasury), ("fees", self.fees)] {
            if value < 0.0 {
                return Err(ChainError::Config(format!(
                    "malachite rewards.witness_pool_weights.{label} must be non-negative"
                )));
            }
        }
        let total = self.treasury + self.fees;
        if total <= 0.0 {
            return Err(ChainError::Config(
                "malachite rewards.witness_pool_weights must define positive weights".into(),
            ));
        }
        Ok(())
    }
}

impl Default for WitnessPoolWeightsConfig {
    fn default() -> Self {
        Self {
            treasury: 0.7,
            fees: 0.3,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct MalachiteProofConfig {
    pub proof_batch_size: usize,
    pub proof_cache_ttl_secs: u64,
    pub max_recursive_depth: u32,
}

impl MalachiteProofConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.proof_batch_size == 0 {
            return Err(ChainError::Config(
                "malachite proof.proof_batch_size must be greater than 0".into(),
            ));
        }
        if self.proof_cache_ttl_secs == 0 {
            return Err(ChainError::Config(
                "malachite proof.proof_cache_ttl_secs must be greater than 0".into(),
            ));
        }
        if self.max_recursive_depth == 0 {
            return Err(ChainError::Config(
                "malachite proof.max_recursive_depth must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for MalachiteProofConfig {
    fn default() -> Self {
        Self {
            proof_batch_size: 64,
            proof_cache_ttl_secs: 900,
            max_recursive_depth: 4,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct MalachiteNetworkConfig {
    pub gossip_fanout: usize,
    pub max_channel_buffer: usize,
    pub rate_limit_per_channel: u64,
    pub max_block_size_bytes: usize,
    pub max_votes_per_round: usize,
}

impl MalachiteNetworkConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.gossip_fanout == 0 {
            return Err(ChainError::Config(
                "malachite network.gossip_fanout must be greater than 0".into(),
            ));
        }
        if self.max_channel_buffer == 0 {
            return Err(ChainError::Config(
                "malachite network.max_channel_buffer must be greater than 0".into(),
            ));
        }
        if self.rate_limit_per_channel == 0 {
            return Err(ChainError::Config(
                "malachite network.rate_limit_per_channel must be greater than 0".into(),
            ));
        }
        if self.max_block_size_bytes == 0 {
            return Err(ChainError::Config(
                "malachite network.max_block_size_bytes must be greater than 0".into(),
            ));
        }
        if self.max_votes_per_round == 0 {
            return Err(ChainError::Config(
                "malachite network.max_votes_per_round must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for MalachiteNetworkConfig {
    fn default() -> Self {
        Self {
            gossip_fanout: 12,
            max_channel_buffer: 1_024,
            rate_limit_per_channel: 128,
            max_block_size_bytes: 2_097_152,
            max_votes_per_round: 500,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct P2pConfig {
    pub listen_addr: String,
    pub bootstrap_peers: Vec<String>,
    pub heartbeat_interval_ms: u64,
    pub gossip_enabled: bool,
    pub gossip_rate_limit_per_sec: u64,
    pub replay_window_size: usize,
    #[serde(default = "default_peerstore_path")]
    pub peerstore_path: PathBuf,
    #[serde(default = "default_gossip_state_path")]
    pub gossip_path: Option<PathBuf>,
    #[serde(default)]
    pub allowlist: Vec<P2pAllowlistEntry>,
    #[serde(default)]
    pub blocklist: Vec<String>,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/7600".to_string(),
            bootstrap_peers: Vec::new(),
            heartbeat_interval_ms: 5_000,
            gossip_enabled: true,
            gossip_rate_limit_per_sec: default_gossip_rate_limit_per_sec(),
            replay_window_size: default_replay_window_size(),
            peerstore_path: default_peerstore_path(),
            gossip_path: default_gossip_state_path(),
            allowlist: Vec::new(),
            blocklist: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2pAllowlistEntry {
    pub peer_id: String,
    pub tier: TierLevel,
}

impl P2pConfig {
    pub fn validate(&self) -> ChainResult<()> {
        if self.gossip_rate_limit_per_sec == 0 {
            return Err(ChainError::Config(
                "p2p.gossip_rate_limit_per_sec must be greater than 0".into(),
            ));
        }
        if self.replay_window_size == 0 {
            return Err(ChainError::Config(
                "p2p.replay_window_size must be greater than 0".into(),
            ));
        }
        Ok(())
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
    #[serde(default)]
    pub secrets: SecretsConfig,
    #[serde(default = "default_snapshot_dir")]
    pub snapshot_dir: PathBuf,
    #[serde(default = "default_proof_cache_dir")]
    pub proof_cache_dir: PathBuf,
    #[serde(default = "default_consensus_pipeline_path")]
    pub consensus_pipeline_path: PathBuf,
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
    #[serde(skip)]
    pub malachite: MalachiteConfig,
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

fn default_gossip_rate_limit_per_sec() -> u64 {
    128
}

fn default_replay_window_size() -> usize {
    1_024
}

fn default_consensus_pipeline_path() -> PathBuf {
    PathBuf::from("./data/p2p/consensus_pipeline.json")
}

fn default_max_proof_size_bytes() -> usize {
    4 * 1024 * 1024
}

impl NodeConfig {
    pub fn for_mode(mode: RuntimeMode) -> Self {
        match mode {
            RuntimeMode::Hybrid => Self::for_hybrid(),
            RuntimeMode::Validator => Self::for_validator(),
            RuntimeMode::Node | RuntimeMode::Wallet => Self::for_node(),
        }
    }

    pub fn for_node() -> Self {
        Self::default()
    }

    pub fn for_hybrid() -> Self {
        let mut config = Self::default();
        config.apply_hybrid_defaults();
        config
    }

    pub fn for_validator() -> Self {
        let mut config = Self::default();
        config.apply_validator_defaults();
        config
    }

    fn apply_hybrid_defaults(&mut self) {
        self.rollout.telemetry.enabled = true;
        self.rollout.telemetry.sample_interval_secs = 30;
        self.p2p.heartbeat_interval_ms = 4_000;
        self.p2p.gossip_rate_limit_per_sec = 192;
        self.malachite.proof.proof_batch_size = 96;
        self.malachite.proof.proof_cache_ttl_secs = 720;
        self.malachite.proof.max_recursive_depth = 5;
    }

    fn apply_validator_defaults(&mut self) {
        self.rollout.telemetry.enabled = true;
        self.rollout.telemetry.sample_interval_secs = 15;
        self.rollout.release_channel = ReleaseChannel::Testnet;
        self.p2p.heartbeat_interval_ms = 3_000;
        self.p2p.gossip_rate_limit_per_sec = 256;
        self.malachite.proof.proof_batch_size = 128;
        self.malachite.proof.proof_cache_ttl_secs = 600;
        self.malachite.proof.max_recursive_depth = 6;
    }

    pub fn load(path: &Path) -> ChainResult<Self> {
        let content = fs::read_to_string(path)?;
        let mut config: Self = toml::from_str(&content)
            .map_err(|err| ChainError::Config(format!("unable to parse config: {err}")))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let malachite_path = base.join(MALACHITE_CONFIG_FILE);
        config.malachite = MalachiteConfig::load_from_path(&malachite_path)?;
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
        self.secrets.ensure_directories(&self.vrf_key_path)?;
        fs::create_dir_all(&self.snapshot_dir)?;
        fs::create_dir_all(&self.proof_cache_dir)?;
        if let Some(parent) = self.consensus_pipeline_path.parent() {
            fs::create_dir_all(parent)?;
        }
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
        self.reputation
            .reputation_params(&self.malachite.reputation)
    }

    pub fn validator_set_size(&self) -> usize {
        self.malachite.validator.validator_set_size
    }

    pub fn timetoke_params(&self) -> TimetokeParams {
        self.malachite.reputation.timetoke_params()
    }

    pub fn load_or_generate_vrf_keypair(&self) -> ChainResult<VrfKeypair> {
        self.secrets
            .load_or_generate_vrf_keypair(&self.vrf_key_path)
    }

    pub fn validate(&self) -> ChainResult<()> {
        self.malachite.validate()?;
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
        self.p2p.validate()?;
        self.secrets.validate_with_path(&self.vrf_key_path)?;
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
            secrets: SecretsConfig::default(),
            snapshot_dir: default_snapshot_dir(),
            proof_cache_dir: default_proof_cache_dir(),
            consensus_pipeline_path: default_consensus_pipeline_path(),
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
            malachite: MalachiteConfig::default(),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier_thresholds: Option<TierThresholds>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weights: Option<ReputationWeights>,
}

impl ReputationConfig {
    pub fn reputation_params(&self, defaults: &MalachiteReputationConfig) -> ReputationParams {
        let mut params = defaults.reputation_params();
        if let Some(thresholds) = &self.tier_thresholds {
            params.tier_thresholds = thresholds.clone();
        }
        if let Some(weights) = &self.weights {
            params.weights = weights.clone();
        }
        params
    }
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            tier_thresholds: None,
            weights: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn reputation_config_applies_weight_overrides() {
        let custom = ReputationWeights::new(0.5, 0.2, 0.2, 0.05, 0.05).unwrap();
        let config = ReputationConfig {
            weights: Some(custom.clone()),
            ..Default::default()
        };
        let defaults = MalachiteReputationConfig::default();

        let params = config.reputation_params(&defaults);
        assert!((params.weights.validation() - custom.validation()).abs() < f64::EPSILON);
        assert!((params.weights.decay() - custom.decay()).abs() < f64::EPSILON);

        let default_params = ReputationConfig::default().reputation_params(&defaults);
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

    #[test]
    fn malachite_config_uses_defaults_when_missing() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("missing.toml");
        let config = MalachiteConfig::load_from_path(&missing).expect("default malachite config");
        assert_eq!(
            config.validator.validator_set_size,
            ValidatorSelectionConfig::default().validator_set_size
        );
    }

    #[test]
    fn malachite_config_rejects_incompatible_version() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("malachite.toml");
        fs::write(
            &path,
            r#"config_version = "2.0.0"

[validator]
validator_set_size = 100
witness_count = 16
vrf_threshold_curve = "curve"
epoch_duration_secs = 3600
round_timeout_ms = 1000
max_round_extensions = 1
"#,
        )
        .expect("write malachite config");

        let error = MalachiteConfig::load_from_path(&path).expect_err("version check should fail");
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
    fn node_config_loads_adjacent_malachite_file() {
        let dir = tempdir().expect("tempdir");
        let node_path = dir.path().join("node.toml");
        let malachite_path = dir.path().join("malachite.toml");

        let mut node = NodeConfig::default();
        node.save(&node_path).expect("write node config");

        fs::write(
            &malachite_path,
            r#"config_version = "1.0.0"

[validator]
validator_set_size = 77
witness_count = 16
vrf_threshold_curve = "curve"
epoch_duration_secs = 7200
round_timeout_ms = 2000
max_round_extensions = 2
"#,
        )
        .expect("write malachite config");

        let loaded = NodeConfig::load(&node_path).expect("load node config");
        assert_eq!(loaded.validator_set_size(), 77);
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
    #[cfg(feature = "vendor_electrs")]
    #[serde(default = "default_wallet_electrs_config")]
    pub electrs: Option<ElectrsConfig>,
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
    pub fn for_mode(mode: RuntimeMode) -> Self {
        match mode {
            RuntimeMode::Hybrid => Self::for_hybrid(),
            RuntimeMode::Validator => Self::for_validator(),
            RuntimeMode::Node | RuntimeMode::Wallet => Self::for_wallet(),
        }
    }

    pub fn for_wallet() -> Self {
        Self::default()
    }

    pub fn for_hybrid() -> Self {
        let mut config = Self::default();
        config.apply_hybrid_defaults();
        config
    }

    pub fn for_validator() -> Self {
        let mut config = Self::default();
        config.apply_hybrid_defaults();
        config.apply_validator_defaults();
        config
    }

    fn apply_hybrid_defaults(&mut self) {
        self.node.embedded = false;
        if self.node.gossip_endpoints.is_empty() {
            self.node
                .gossip_endpoints
                .push("/ip4/127.0.0.1/tcp/7600".to_string());
        }

        #[cfg(feature = "vendor_electrs")]
        if let Some(electrs) = self.electrs.as_mut() {
            electrs.features.runtime = true;
            electrs.features.tracker = true;
            electrs.cache.telemetry.enabled = true;
            electrs.tracker.telemetry_endpoint = SocketAddr::from(([127, 0, 0, 1], 9_200));
            electrs.tracker.notifications.p2p = true;
            electrs.p2p.enabled = true;
            electrs.p2p.metrics_endpoint = SocketAddr::from(([127, 0, 0, 1], 9_300));
            electrs.p2p.network_id = "rpp-hybrid".to_string();
            electrs.network = rpp_wallet::config::NetworkSelection::Testnet;
        }
    }

    fn apply_validator_defaults(&mut self) {
        #[cfg(feature = "vendor_electrs")]
        if let Some(electrs) = self.electrs.as_mut() {
            electrs.cache.telemetry.enabled = true;
            electrs.tracker.telemetry_endpoint = SocketAddr::from(([127, 0, 0, 1], 9_250));
            electrs.p2p.metrics_endpoint = SocketAddr::from(([127, 0, 0, 1], 9_350));
            electrs.p2p.network_id = "rpp-validator".to_string();
            electrs.tracker.notifications.topic = "/rpp/gossip/finality/1.0.0".to_string();
        }
    }

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
        #[cfg(feature = "vendor_electrs")]
        self.ensure_electrs_directories()?;
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
        #[cfg(feature = "vendor_electrs")]
        self.validate_electrs()?;
        Ok(())
    }

    #[cfg(feature = "vendor_electrs")]
    fn ensure_electrs_directories(&self) -> ChainResult<()> {
        if let Some(electrs) = self.electrs.as_ref() {
            if electrs.features.runtime || electrs.features.tracker {
                fs::create_dir_all(self.electrs_firewood_dir())?;
                fs::create_dir_all(self.electrs_index_dir())?;
            }
        }
        Ok(())
    }

    #[cfg(feature = "vendor_electrs")]
    fn validate_electrs(&self) -> ChainResult<()> {
        if let Some(electrs) = self.electrs.as_ref() {
            if electrs.features.tracker && !electrs.features.runtime {
                return Err(ChainError::Config(
                    "wallet electrs tracker feature requires the runtime feature".into(),
                ));
            }
            self.ensure_electrs_directories()?;
        }
        Ok(())
    }

    #[cfg(feature = "vendor_electrs")]
    pub fn electrs_firewood_dir(&self) -> PathBuf {
        self.data_dir.join("electrs").join("firewood")
    }

    #[cfg(feature = "vendor_electrs")]
    pub fn electrs_index_dir(&self) -> PathBuf {
        self.data_dir.join("electrs").join("index")
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
            #[cfg(feature = "vendor_electrs")]
            electrs: default_wallet_electrs_config(),
        }
    }
}

#[cfg(feature = "vendor_electrs")]
fn default_wallet_electrs_config() -> Option<ElectrsConfig> {
    Some(ElectrsConfig::default())
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
#[serde(default, deny_unknown_fields)]
pub struct FeatureGates {
    pub pruning: bool,
    pub recursive_proofs: bool,
    pub reconstruction: bool,
    pub consensus_enforcement: bool,
    pub malachite_consensus: bool,
    pub timetoke_rewards: bool,
    pub witness_network: bool,
}

impl FeatureGates {
    pub fn advertise(&self) -> BTreeMap<String, bool> {
        BTreeMap::from([
            ("pruning".to_string(), self.pruning),
            ("recursive_proofs".to_string(), self.recursive_proofs),
            ("reconstruction".to_string(), self.reconstruction),
            (
                "consensus_enforcement".to_string(),
                self.consensus_enforcement,
            ),
            ("malachite_consensus".to_string(), self.malachite_consensus),
            ("timetoke_rewards".to_string(), self.timetoke_rewards),
            ("witness_network".to_string(), self.witness_network),
        ])
    }

    pub fn from_advertisement(advertisement: &BTreeMap<String, bool>) -> ChainResult<Self> {
        let mut gates = Self::default();
        for (key, value) in advertisement {
            match key.as_str() {
                "pruning" => gates.pruning = *value,
                "recursive_proofs" => gates.recursive_proofs = *value,
                "reconstruction" => gates.reconstruction = *value,
                "consensus_enforcement" => gates.consensus_enforcement = *value,
                "malachite_consensus" => gates.malachite_consensus = *value,
                "timetoke_rewards" => gates.timetoke_rewards = *value,
                "witness_network" => gates.witness_network = *value,
                other => {
                    return Err(ChainError::Config(format!(
                        "unknown feature gate `{other}` in announcement"
                    )));
                }
            }
        }
        Ok(gates)
    }
}

impl Default for FeatureGates {
    fn default() -> Self {
        Self {
            pruning: true,
            recursive_proofs: true,
            reconstruction: true,
            consensus_enforcement: true,
            malachite_consensus: false,
            timetoke_rewards: false,
            witness_network: false,
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
