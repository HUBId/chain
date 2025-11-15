use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hex;
use http::Uri;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};

use rpp_p2p::{
    GossipTopic, ReputationHeuristics, TierLevel, TopicPermission, WitnessChannelConfig,
    WitnessPipelineConfig,
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;

#[cfg(feature = "vendor_electrs")]
use rpp_wallet::config::electrs::ElectrsConfig;
use rpp_wallet::config::wallet::{
    WalletEngineConfig as WalletEngineSettings, WalletFeeConfig as WalletFeeSettings,
    WalletPolicyConfig as WalletPolicySettings, WalletProverConfig as WalletProverSettings,
};

use crate::consensus_engine::governance::TimetokeRewardGovernance;
use crate::consensus_engine::state::{TreasuryAccounts, WitnessPoolWeights};
use crate::crypto::{
    DynVrfKeyStore, FilesystemKeystoreConfig, FilesystemVrfKeyStore, HsmKeystoreConfig,
    VaultKeystoreConfig, VaultVrfKeyStore, VrfKeyIdentifier, VrfKeypair,
};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::DEFAULT_EPOCH_LENGTH;
use crate::reputation::{ReputationParams, ReputationWeights, TierThresholds, TimetokeParams};
use crate::runtime::wallet::rpc::{
    WalletIdentity, WalletRole, WalletRoleSet, WalletSecurityBinding, WalletSecurityPaths,
};
use crate::runtime::wallet::runtime::{WalletAuditRuntimeConfig, WalletRpcSecurityRuntimeConfig};
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
    pub witness_count: usize,
    pub vrf: ValidatorVrfConfig,
    pub epoch_duration_secs: u64,
    pub round_timeout_ms: u64,
    pub max_round_extensions: u32,
}

impl ValidatorSelectionConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.witness_count == 0 {
            return Err(ChainError::Config(
                "malachite validator.witness_count must be greater than 0".into(),
            ));
        }
        self.vrf.validate()?;
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
            witness_count: 16,
            vrf: ValidatorVrfConfig::default(),
            epoch_duration_secs: 86_400,
            round_timeout_ms: 6_000,
            max_round_extensions: 3,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ValidatorVrfConfig {
    pub threshold: VrfThresholdConfig,
}

impl ValidatorVrfConfig {
    fn validate(&self) -> ChainResult<()> {
        self.threshold.validate()
    }
}

impl Default for ValidatorVrfConfig {
    fn default() -> Self {
        Self {
            threshold: VrfThresholdConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct VrfThresholdConfig {
    pub curve: String,
    pub target_validator_count: usize,
}

impl VrfThresholdConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.curve.trim().is_empty() {
            return Err(ChainError::Config(
                "malachite validator.vrf.threshold.curve must not be empty".into(),
            ));
        }
        if self.target_validator_count == 0 {
            return Err(ChainError::Config(
                "malachite validator.vrf.threshold.target_validator_count must be greater than 0"
                    .into(),
            ));
        }
        Ok(())
    }
}

impl Default for VrfThresholdConfig {
    fn default() -> Self {
        Self {
            curve: "linear:v0.6-b0.2".to_string(),
            target_validator_count: 100,
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
    pub witness_proof_buffer: usize,
    pub witness_meta_buffer: usize,
    pub witness_proof_rate_limit: u64,
    pub witness_meta_rate_limit: u64,
    pub witness_rate_interval_ms: u64,
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
        if self.witness_proof_buffer == 0 {
            return Err(ChainError::Config(
                "malachite network.witness_proof_buffer must be greater than 0".into(),
            ));
        }
        if self.witness_meta_buffer == 0 {
            return Err(ChainError::Config(
                "malachite network.witness_meta_buffer must be greater than 0".into(),
            ));
        }
        if self.witness_proof_rate_limit == 0 {
            return Err(ChainError::Config(
                "malachite network.witness_proof_rate_limit must be greater than 0".into(),
            ));
        }
        if self.witness_meta_rate_limit == 0 {
            return Err(ChainError::Config(
                "malachite network.witness_meta_rate_limit must be greater than 0".into(),
            ));
        }
        if self.witness_rate_interval_ms == 0 {
            return Err(ChainError::Config(
                "malachite network.witness_rate_interval_ms must be greater than 0".into(),
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

    pub fn witness_pipelines(&self) -> WitnessPipelineConfig {
        let interval = Duration::from_millis(self.witness_rate_interval_ms);
        WitnessPipelineConfig {
            proofs: WitnessChannelConfig::new(
                self.witness_proof_buffer,
                interval,
                self.witness_proof_rate_limit,
            ),
            meta: WitnessChannelConfig::new(
                self.witness_meta_buffer,
                interval,
                self.witness_meta_rate_limit,
            ),
        }
    }
}

impl Default for MalachiteNetworkConfig {
    fn default() -> Self {
        Self {
            gossip_fanout: 12,
            max_channel_buffer: 1_024,
            rate_limit_per_channel: 128,
            witness_proof_buffer: 256,
            witness_meta_buffer: 128,
            witness_proof_rate_limit: 128,
            witness_meta_rate_limit: 64,
            witness_rate_interval_ms: 250,
            max_block_size_bytes: 2_097_152,
            max_votes_per_round: 500,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ReputationHeuristicsConfig {
    pub vote_timeout_penalty: f64,
    pub proof_relay_penalty: f64,
    pub gossip_backpressure_penalty: f64,
    pub gossip_backpressure_threshold: usize,
}

impl Default for ReputationHeuristicsConfig {
    fn default() -> Self {
        Self {
            vote_timeout_penalty: 0.4,
            proof_relay_penalty: 0.6,
            gossip_backpressure_penalty: 0.25,
            gossip_backpressure_threshold: 4,
        }
    }
}

impl From<&ReputationHeuristicsConfig> for ReputationHeuristics {
    fn from(config: &ReputationHeuristicsConfig) -> Self {
        Self {
            vote_timeout_penalty: config.vote_timeout_penalty,
            proof_relay_penalty: config.proof_relay_penalty,
            gossip_backpressure_penalty: config.gossip_backpressure_penalty,
            gossip_backpressure_threshold: config.gossip_backpressure_threshold,
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
    #[serde(default)]
    pub reputation_heuristics: ReputationHeuristicsConfig,
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
            reputation_heuristics: ReputationHeuristicsConfig::default(),
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

    pub fn reputation_heuristics(&self) -> ReputationHeuristics {
        ReputationHeuristics::from(&self.reputation_heuristics)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct TopicTierConfig {
    pub subscribe: TierLevel,
    pub publish: TierLevel,
}

impl TopicTierConfig {
    fn for_topic(topic: GossipTopic) -> Self {
        let permission = TopicPermission::default_for(topic);
        Self {
            subscribe: permission.subscribe,
            publish: permission.publish,
        }
    }

    fn blocks() -> Self {
        Self::for_topic(GossipTopic::Blocks)
    }

    fn votes() -> Self {
        Self::for_topic(GossipTopic::Votes)
    }

    fn proofs() -> Self {
        Self::for_topic(GossipTopic::Proofs)
    }

    fn vrf_proofs() -> Self {
        Self::for_topic(GossipTopic::VrfProofs)
    }

    fn snapshots() -> Self {
        Self::for_topic(GossipTopic::Snapshots)
    }

    fn meta() -> Self {
        Self::for_topic(GossipTopic::Meta)
    }

    fn vrf_meta() -> Self {
        Self::for_topic(GossipTopic::VrfMeta)
    }

    fn witness_proofs() -> Self {
        Self::for_topic(GossipTopic::WitnessProofs)
    }

    fn witness_meta() -> Self {
        Self::for_topic(GossipTopic::WitnessMeta)
    }

    pub fn to_permission(&self) -> TopicPermission {
        TopicPermission {
            subscribe: self.subscribe,
            publish: self.publish,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AdmissionDefaultsConfig {
    #[serde(default = "TopicTierConfig::blocks")]
    pub blocks: TopicTierConfig,
    #[serde(default = "TopicTierConfig::votes")]
    pub votes: TopicTierConfig,
    #[serde(default = "TopicTierConfig::proofs")]
    pub proofs: TopicTierConfig,
    #[serde(default = "TopicTierConfig::vrf_proofs")]
    pub vrf_proofs: TopicTierConfig,
    #[serde(default = "TopicTierConfig::snapshots")]
    pub snapshots: TopicTierConfig,
    #[serde(default = "TopicTierConfig::meta")]
    pub meta: TopicTierConfig,
    #[serde(default = "TopicTierConfig::vrf_meta")]
    pub vrf_meta: TopicTierConfig,
    #[serde(default = "TopicTierConfig::witness_proofs")]
    pub witness_proofs: TopicTierConfig,
    #[serde(default = "TopicTierConfig::witness_meta")]
    pub witness_meta: TopicTierConfig,
}

impl Default for AdmissionDefaultsConfig {
    fn default() -> Self {
        Self {
            blocks: TopicTierConfig::blocks(),
            votes: TopicTierConfig::votes(),
            proofs: TopicTierConfig::proofs(),
            vrf_proofs: TopicTierConfig::vrf_proofs(),
            snapshots: TopicTierConfig::snapshots(),
            meta: TopicTierConfig::meta(),
            vrf_meta: TopicTierConfig::vrf_meta(),
            witness_proofs: TopicTierConfig::witness_proofs(),
            witness_meta: TopicTierConfig::witness_meta(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct AdmissionSigningConfig {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_key: Option<String>,
    #[serde(default)]
    pub trust_store: BTreeMap<String, String>,
}

impl AdmissionSigningConfig {
    fn validate(&self) -> ChainResult<()> {
        if !self.enabled {
            return Ok(());
        }
        let path = self.key_path.as_ref().ok_or_else(|| {
            ChainError::Config("network.admission.signing.key_path must be configured".into())
        })?;
        if path.as_os_str().is_empty() {
            return Err(ChainError::Config(
                "network.admission.signing.key_path must not be empty".into(),
            ));
        }
        let key_id = self.active_key.as_ref().ok_or_else(|| {
            ChainError::Config("network.admission.signing.active_key must be configured".into())
        })?;
        if key_id.trim().is_empty() {
            return Err(ChainError::Config(
                "network.admission.signing.active_key must not be empty".into(),
            ));
        }
        if !self.trust_store.contains_key(key_id) {
            return Err(ChainError::Config(format!(
                "network.admission.signing.trust_store missing entry for `{key_id}`"
            )));
        }
        Ok(())
    }
}

impl Default for AdmissionSigningConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            key_path: None,
            active_key: None,
            trust_store: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WormRetentionModeConfig {
    Compliance,
    Governance,
}

impl Default for WormRetentionModeConfig {
    fn default() -> Self {
        Self::Compliance
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WormExportTargetConfig {
    Command {
        program: PathBuf,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    S3 {
        #[serde(skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
        region: String,
        bucket: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        prefix: Option<String>,
        access_key: String,
        secret_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        session_token: Option<String>,
        #[serde(default)]
        path_style: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct NetworkAdmissionWormConfig {
    pub enabled: bool,
    pub required: bool,
    pub retention_days: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_max_days: Option<u64>,
    pub retention_mode: WormRetentionModeConfig,
    pub require_signatures: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<WormExportTargetConfig>,
}

impl Default for NetworkAdmissionWormConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            required: false,
            retention_days: 90,
            retention_max_days: None,
            retention_mode: WormRetentionModeConfig::Compliance,
            require_signatures: true,
            target: None,
        }
    }
}

impl NetworkAdmissionWormConfig {
    fn validate(&self, signing_enabled: bool) -> ChainResult<()> {
        if self.required && !self.enabled {
            return Err(ChainError::Config(
                "network.admission.worm_export.required cannot be true when disabled".into(),
            ));
        }
        if self.retention_days == 0 {
            return Err(ChainError::Config(
                "network.admission.worm_export.retention_days must be greater than 0".into(),
            ));
        }
        if let Some(max) = self.retention_max_days {
            if max < self.retention_days {
                return Err(ChainError::Config(
                    "network.admission.worm_export.retention_max_days must be >= retention_days"
                        .into(),
                ));
            }
        }
        if (self.enabled || self.required) && self.target.is_none() {
            return Err(ChainError::Config(
                "network.admission.worm_export.target must be configured when enabled".into(),
            ));
        }
        if self.require_signatures && !signing_enabled {
            return Err(ChainError::Config(
                "network.admission.worm_export.require_signatures requires admission signing"
                    .into(),
            ));
        }
        if let Some(target) = &self.target {
            match target {
                WormExportTargetConfig::Command { program, .. } => {
                    if program.as_os_str().is_empty() {
                        return Err(ChainError::Config(
                            "network.admission.worm_export.target.program must not be empty".into(),
                        ));
                    }
                }
                WormExportTargetConfig::S3 {
                    endpoint,
                    region,
                    bucket,
                    access_key,
                    secret_key,
                    ..
                } => {
                    if region.trim().is_empty() {
                        return Err(ChainError::Config(
                            "network.admission.worm_export.target.region must not be empty".into(),
                        ));
                    }
                    if bucket.trim().is_empty() {
                        return Err(ChainError::Config(
                            "network.admission.worm_export.target.bucket must not be empty".into(),
                        ));
                    }
                    if access_key.trim().is_empty() {
                        return Err(ChainError::Config(
                            "network.admission.worm_export.target.access_key must not be empty"
                                .into(),
                        ));
                    }
                    if secret_key.trim().is_empty() {
                        return Err(ChainError::Config(
                            "network.admission.worm_export.target.secret_key must not be empty"
                                .into(),
                        ));
                    }
                    if endpoint
                        .as_ref()
                        .map(|value| value.trim().is_empty())
                        .unwrap_or(false)
                    {
                        return Err(ChainError::Config(
                            "network.admission.worm_export.target.endpoint must not be empty"
                                .into(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct NetworkAdmissionConfig {
    pub policy_path: PathBuf,
    pub audit_retention_days: u64,
    pub backup_dir: PathBuf,
    pub backup_retention_days: u64,
    pub defaults: AdmissionDefaultsConfig,
    pub signing: AdmissionSigningConfig,
    pub worm_export: NetworkAdmissionWormConfig,
}

impl NetworkAdmissionConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.policy_path.as_os_str().is_empty() {
            return Err(ChainError::Config(
                "network.admission.policy_path must not be empty".into(),
            ));
        }
        if self.audit_retention_days == 0 {
            return Err(ChainError::Config(
                "network.admission.audit_retention_days must be greater than 0".into(),
            ));
        }
        if self.backup_dir.as_os_str().is_empty() {
            return Err(ChainError::Config(
                "network.admission.backup_dir must not be empty".into(),
            ));
        }
        if self.backup_retention_days == 0 {
            return Err(ChainError::Config(
                "network.admission.backup_retention_days must be greater than 0".into(),
            ));
        }
        self.signing.validate()?;
        self.worm_export.validate(self.signing.enabled)?;
        Ok(())
    }
}

impl Default for NetworkAdmissionConfig {
    fn default() -> Self {
        Self {
            policy_path: default_admission_policy_path(),
            audit_retention_days: 30,
            backup_dir: default_admission_backup_dir(),
            backup_retention_days: 30,
            defaults: AdmissionDefaultsConfig::default(),
            signing: AdmissionSigningConfig::default(),
            worm_export: NetworkAdmissionWormConfig::default(),
        }
    }
}

fn default_admission_policy_path() -> PathBuf {
    PathBuf::from("./data/p2p/admission_policies.json")
}

fn default_admission_backup_dir() -> PathBuf {
    PathBuf::from("./data/p2p/admission/backups")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub p2p: P2pConfig,
    pub rpc: NetworkRpcConfig,
    pub tls: NetworkTlsConfig,
    pub limits: NetworkLimitsConfig,
    pub admission: NetworkAdmissionConfig,
}

impl NetworkConfig {
    fn validate(&self) -> ChainResult<()> {
        self.p2p.validate()?;
        self.rpc.validate()?;
        self.tls.validate()?;
        self.limits.validate()?;
        self.admission.validate()?;
        Ok(())
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            p2p: P2pConfig::default(),
            rpc: NetworkRpcConfig::default(),
            tls: NetworkTlsConfig::default(),
            limits: NetworkLimitsConfig::default(),
            admission: NetworkAdmissionConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkRpcConfig {
    pub listen: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_origin: Option<String>,
}

impl NetworkRpcConfig {
    fn validate(&self) -> ChainResult<()> {
        if let Some(token) = &self.auth_token {
            if token.trim().is_empty() {
                return Err(ChainError::Config(
                    "network.rpc.auth_token must not be empty".into(),
                ));
            }
        }
        if let Some(origin) = &self.allowed_origin {
            if origin.trim().is_empty() {
                return Err(ChainError::Config(
                    "network.rpc.allowed_origin must not be empty".into(),
                ));
            }
        }
        Ok(())
    }
}

impl Default for NetworkRpcConfig {
    fn default() -> Self {
        Self {
            listen: default_network_rpc_listen(),
            auth_token: None,
            allowed_origin: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkTlsConfig {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ca: Option<PathBuf>,
    pub require_client_auth: bool,
}

impl NetworkTlsConfig {
    fn validate(&self) -> ChainResult<()> {
        if !self.enabled {
            return Ok(());
        }

        let certificate = self
            .certificate
            .as_ref()
            .ok_or_else(|| {
                ChainError::Config(
                    "network.tls.certificate must be configured when TLS is enabled".into(),
                )
            })?
            .clone();
        let private_key = self
            .private_key
            .as_ref()
            .ok_or_else(|| {
                ChainError::Config(
                    "network.tls.private_key must be configured when TLS is enabled".into(),
                )
            })?
            .clone();

        validate_tls_path("network.tls.certificate", &certificate)?;
        validate_tls_path("network.tls.private_key", &private_key)?;

        if self.require_client_auth {
            let client_ca = self
                .client_ca
                .as_ref()
                .ok_or_else(|| {
                    ChainError::Config(
                        "network.tls.client_ca must be configured when client authentication is required"
                            .into(),
                    )
                })?
                .clone();
            validate_tls_path("network.tls.client_ca", &client_ca)?;
        } else if let Some(path) = &self.client_ca {
            validate_tls_path("network.tls.client_ca", path)?;
        }

        Ok(())
    }
}

impl Default for NetworkTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            certificate: None,
            private_key: None,
            client_ca: None,
            require_client_auth: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkLimitsConfig {
    pub header_read_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub write_timeout_ms: u64,
    pub max_header_bytes: usize,
    pub max_body_bytes: usize,
    pub per_ip_token_bucket: NetworkTokenBucketConfig,
}

impl NetworkLimitsConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.header_read_timeout_ms == 0 {
            return Err(ChainError::Config(
                "network.limits.header_read_timeout_ms must be greater than 0".into(),
            ));
        }
        if self.read_timeout_ms == 0 {
            return Err(ChainError::Config(
                "network.limits.read_timeout_ms must be greater than 0".into(),
            ));
        }
        if self.write_timeout_ms == 0 {
            return Err(ChainError::Config(
                "network.limits.write_timeout_ms must be greater than 0".into(),
            ));
        }
        if self.max_header_bytes == 0 {
            return Err(ChainError::Config(
                "network.limits.max_header_bytes must be greater than 0".into(),
            ));
        }
        if self.max_body_bytes == 0 {
            return Err(ChainError::Config(
                "network.limits.max_body_bytes must be greater than 0".into(),
            ));
        }
        self.per_ip_token_bucket
            .validate("network.limits.per_ip_token_bucket")
    }
}

impl Default for NetworkLimitsConfig {
    fn default() -> Self {
        Self {
            header_read_timeout_ms: 5_000,
            read_timeout_ms: 15_000,
            write_timeout_ms: 15_000,
            max_header_bytes: 16 * 1024,
            max_body_bytes: 2 * 1024 * 1024,
            per_ip_token_bucket: NetworkTokenBucketConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkTokenBucketConfig {
    pub enabled: bool,
    pub burst: u64,
    pub replenish_per_minute: u64,
}

impl NetworkTokenBucketConfig {
    fn validate(&self, label: &str) -> ChainResult<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.burst == 0 {
            return Err(ChainError::Config(format!(
                "{label}.burst must be greater than 0"
            )));
        }
        if self.replenish_per_minute == 0 {
            return Err(ChainError::Config(format!(
                "{label}.replenish_per_minute must be greater than 0"
            )));
        }
        Ok(())
    }
}

impl Default for NetworkTokenBucketConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            burst: 120,
            replenish_per_minute: 60,
        }
    }
}

fn validate_tls_path(label: &str, path: &Path) -> ChainResult<()> {
    if path.as_os_str().is_empty() {
        return Err(ChainError::Config(format!(
            "{label} must not be an empty path"
        )));
    }

    let metadata = fs::metadata(path).map_err(|err| {
        ChainError::Config(format!(
            "{label} ({}) could not be accessed: {err}",
            path.display()
        ))
    })?;

    if !metadata.is_file() {
        return Err(ChainError::Config(format!(
            "{label} ({}) must be a file",
            path.display()
        )));
    }

    Ok(())
}

fn default_network_rpc_listen() -> SocketAddr {
    "127.0.0.1:7070".parse().expect("socket addr")
}

pub const NODE_CONFIG_VERSION: &str = "1.0";

fn default_node_config_version() -> String {
    NODE_CONFIG_VERSION.to_string()
}

pub const DEFAULT_PRUNING_CADENCE_SECS: u64 = 30;
pub const DEFAULT_PRUNING_RETENTION_DEPTH: u64 = 128;
pub const DEFAULT_ADMISSION_RECONCILER_CADENCE_SECS: u64 = 60;
pub const DEFAULT_ADMISSION_RECONCILER_ALERT_THRESHOLD: u64 = 1;
pub const DEFAULT_ADMISSION_RECONCILER_AUDIT_LAG_SECS: u64 = 300;
pub const DEFAULT_SNAPSHOT_VALIDATOR_CADENCE_SECS: u64 = 300;

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
    #[serde(default = "default_timetoke_snapshot_key_path")]
    pub timetoke_snapshot_key_path: PathBuf,
    #[serde(default = "default_proof_cache_dir")]
    pub proof_cache_dir: PathBuf,
    #[serde(default = "default_consensus_pipeline_path")]
    pub consensus_pipeline_path: PathBuf,
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
    pub network: NetworkConfig,
    pub genesis: GenesisConfig,
    #[serde(default)]
    pub reputation: ReputationConfig,
    #[serde(default)]
    pub queue_weights: QueueWeightsConfig,
    #[serde(skip)]
    pub malachite: MalachiteConfig,
    #[serde(default)]
    pub storage: FirewoodStorageConfig,
    #[serde(default)]
    pub pruning: PruningConfig,
    #[serde(default)]
    pub admission_reconciler: AdmissionReconcilerConfig,
    #[serde(default)]
    pub snapshot_validator: SnapshotValidatorConfig,
    #[serde(default)]
    pub governance: GovernanceConfig,
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

fn default_timetoke_snapshot_key_path() -> PathBuf {
    PathBuf::from("./keys/timetoke_snapshot.toml")
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewoodSyncPolicyConfig {
    Always,
    Deferred,
}

impl Default for FirewoodSyncPolicyConfig {
    fn default() -> Self {
        Self::Always
    }
}

pub const MIN_STORAGE_RING_SIZE: u32 = 2;
pub const MAX_STORAGE_RING_SIZE: u32 = 4096;
const DEFAULT_STORAGE_RING_SIZE: u32 = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewoodStorageConfig {
    pub snapshot_dir: PathBuf,
    pub proof_dir: PathBuf,
    pub sync_policy: FirewoodSyncPolicyConfig,
    pub commit_io_budget_bytes: u64,
    pub compaction_io_budget_bytes: u64,
    pub ring_size: u32,
}

impl FirewoodStorageConfig {
    pub fn snapshot_dir_or(&self, fallback: &Path) -> PathBuf {
        if self.snapshot_dir == PathBuf::default() {
            fallback.to_path_buf()
        } else {
            self.snapshot_dir.clone()
        }
    }

    pub fn proof_dir_or(&self, fallback: &Path) -> PathBuf {
        if self.proof_dir == PathBuf::default() {
            fallback.to_path_buf()
        } else {
            self.proof_dir.clone()
        }
    }
}

impl Default for FirewoodStorageConfig {
    fn default() -> Self {
        Self {
            snapshot_dir: default_snapshot_dir(),
            proof_dir: PathBuf::from("./data/proofs"),
            sync_policy: FirewoodSyncPolicyConfig::Always,
            commit_io_budget_bytes: 64 * 1024 * 1024,
            compaction_io_budget_bytes: 128 * 1024 * 1024,
            ring_size: DEFAULT_STORAGE_RING_SIZE,
        }
    }
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
        self.network.p2p.heartbeat_interval_ms = 4_000;
        self.network.p2p.gossip_rate_limit_per_sec = 192;
        self.malachite.proof.proof_batch_size = 96;
        self.malachite.proof.proof_cache_ttl_secs = 720;
        self.malachite.proof.max_recursive_depth = 5;
    }

    fn apply_validator_defaults(&mut self) {
        self.rollout.telemetry.enabled = true;
        self.rollout.telemetry.sample_interval_secs = 15;
        self.rollout.release_channel = ReleaseChannel::Testnet;
        self.network.p2p.heartbeat_interval_ms = 3_000;
        self.network.p2p.gossip_rate_limit_per_sec = 256;
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
        if let Some(parent) = self.timetoke_snapshot_key_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::create_dir_all(&self.snapshot_dir)?;
        fs::create_dir_all(&self.proof_cache_dir)?;
        if let Some(parent) = self.consensus_pipeline_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = self.network.p2p.peerstore_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = self.network.admission.policy_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        if let Some(path) = self.network.p2p.gossip_path.as_ref() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::create_dir_all(&self.storage.snapshot_dir)?;
        fs::create_dir_all(&self.storage.proof_dir)?;
        Ok(())
    }

    pub fn reputation_params(&self) -> ReputationParams {
        self.reputation
            .reputation_params(&self.malachite.reputation)
    }

    pub fn validator_set_size(&self) -> usize {
        self.malachite
            .validator
            .vrf
            .threshold
            .target_validator_count
    }

    pub fn timetoke_params(&self) -> TimetokeParams {
        self.malachite.reputation.timetoke_params()
    }

    pub fn timetoke_rewards_governance(&self) -> TimetokeRewardGovernance {
        self.governance.timetoke_rewards_governance()
    }

    pub fn load_or_generate_vrf_keypair(&self) -> ChainResult<VrfKeypair> {
        self.secrets
            .load_or_generate_vrf_keypair(&self.vrf_key_path)
    }

    pub fn load_timetoke_snapshot_signing_key(&self) -> ChainResult<SigningKey> {
        read_signing_key(&self.timetoke_snapshot_key_path)
            .map_err(|err| ChainError::Config(format!("timetoke snapshot signing key: {err}")))
    }

    pub fn load_or_generate_timetoke_snapshot_signing_key(&self) -> ChainResult<SigningKey> {
        if self.timetoke_snapshot_key_path.exists() {
            return self.load_timetoke_snapshot_signing_key();
        }
        let mut rng = OsRng;
        let signing = SigningKey::generate(&mut rng);
        let verifying = signing.verifying_key();
        let stored = StoredSigningKey {
            secret_key: hex::encode(signing.to_bytes()),
            public_key: Some(hex::encode(verifying.to_bytes())),
        };
        let encoded = toml::to_string(&stored).map_err(|err| {
            ChainError::Config(format!(
                "unable to encode timetoke snapshot signing key: {err}"
            ))
        })?;
        if let Some(parent) = self.timetoke_snapshot_key_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(&self.timetoke_snapshot_key_path, encoded)?;
        Ok(signing)
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
        if self.storage.commit_io_budget_bytes == 0 {
            return Err(ChainError::Config(
                "node configuration storage.commit_io_budget_bytes must be greater than 0".into(),
            ));
        }
        if self.storage.compaction_io_budget_bytes == 0 {
            return Err(ChainError::Config(
                "node configuration storage.compaction_io_budget_bytes must be greater than 0"
                    .into(),
            ));
        }
        if self.storage.ring_size < MIN_STORAGE_RING_SIZE
            || self.storage.ring_size > MAX_STORAGE_RING_SIZE
        {
            return Err(ChainError::Config(format!(
                "node configuration storage.ring_size must be between {MIN_STORAGE_RING_SIZE} and {MAX_STORAGE_RING_SIZE}"
            )));
        }
        self.network.validate()?;
        self.rollout.telemetry.validate()?;
        self.queue_weights.validate()?;
        self.secrets.validate_with_path(&self.vrf_key_path)?;
        self.pruning.validate()?;
        self.admission_reconciler.validate()?;
        self.snapshot_validator.validate()?;
        self.governance.validate()?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredSigningKey {
    secret_key: String,
    #[allow(dead_code)]
    public_key: Option<String>,
}

fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let raw = fs::read_to_string(path)
        .map_err(|err| format!("unable to read signing key from {}: {err}", path.display()))?;
    let stored: StoredSigningKey = toml::from_str(&raw)
        .map_err(|err| format!("failed to decode signing key {}: {err}", path.display()))?;
    let secret_bytes = hex::decode(&stored.secret_key)
        .map_err(|err| format!("invalid signing key encoding: {err}"))?;
    let secret: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| "signing key must be 32 bytes".to_string())?;
    let signing = SigningKey::from_bytes(&secret)
        .map_err(|err| format!("invalid signing key bytes: {err}"))?;
    if let Some(public_hex) = stored.public_key.as_deref() {
        let public_bytes = hex::decode(public_hex)
            .map_err(|err| format!("invalid signing public key encoding: {err}"))?;
        let public: [u8; 32] = public_bytes
            .try_into()
            .map_err(|_| "public key must be 32 bytes".to_string())?;
        let expected = VerifyingKey::from_bytes(&public)
            .map_err(|err| format!("invalid signing public key bytes: {err}"))?;
        if expected != signing.verifying_key() {
            return Err("signing keypair mismatch between secret and public key".into());
        }
    }
    Ok(signing)
}

impl Default for NodeConfig {
    fn default() -> Self {
        let mut network = NetworkConfig::default();
        network.p2p.peerstore_path = default_peerstore_path();
        network.p2p.gossip_path = default_gossip_state_path();
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
            block_time_ms: 5_000,
            max_block_transactions: 512,
            max_block_identity_registrations: default_max_block_identity_registrations(),
            mempool_limit: 8_192,
            epoch_length: default_epoch_length(),
            target_validator_count: default_target_validator_count(),
            max_proof_size_bytes: default_max_proof_size_bytes(),
            rollout: RolloutConfig::default(),
            network,
            genesis: GenesisConfig::default(),
            reputation: ReputationConfig::default(),
            queue_weights: QueueWeightsConfig::default(),
            malachite: MalachiteConfig::default(),
            storage: FirewoodStorageConfig::default(),
            pruning: PruningConfig::default(),
            admission_reconciler: AdmissionReconcilerConfig::default(),
            snapshot_validator: SnapshotValidatorConfig::default(),
            governance: GovernanceConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PruningConfig {
    pub cadence_secs: u64,
    pub retention_depth: u64,
    pub emergency_pause: bool,
}

impl PruningConfig {
    pub fn validate(&self) -> ChainResult<()> {
        if self.cadence_secs == 0 {
            return Err(ChainError::Config(
                "pruning.cadence_secs must be greater than 0".into(),
            ));
        }
        if self.retention_depth == 0 {
            return Err(ChainError::Config(
                "pruning.retention_depth must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            cadence_secs: DEFAULT_PRUNING_CADENCE_SECS,
            retention_depth: DEFAULT_PRUNING_RETENTION_DEPTH,
            emergency_pause: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AdmissionReconcilerConfig {
    pub cadence_secs: u64,
    pub drift_alert_threshold: u64,
    pub max_audit_lag_secs: u64,
}

impl AdmissionReconcilerConfig {
    pub fn validate(&self) -> ChainResult<()> {
        if self.cadence_secs == 0 {
            return Err(ChainError::Config(
                "admission_reconciler.cadence_secs must be greater than 0".into(),
            ));
        }
        if self.drift_alert_threshold == 0 {
            return Err(ChainError::Config(
                "admission_reconciler.drift_alert_threshold must be greater than 0".into(),
            ));
        }
        if self.max_audit_lag_secs == 0 {
            return Err(ChainError::Config(
                "admission_reconciler.max_audit_lag_secs must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for AdmissionReconcilerConfig {
    fn default() -> Self {
        Self {
            cadence_secs: DEFAULT_ADMISSION_RECONCILER_CADENCE_SECS,
            drift_alert_threshold: DEFAULT_ADMISSION_RECONCILER_ALERT_THRESHOLD,
            max_audit_lag_secs: DEFAULT_ADMISSION_RECONCILER_AUDIT_LAG_SECS,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct SnapshotValidatorConfig {
    pub cadence_secs: u64,
}

impl SnapshotValidatorConfig {
    pub fn validate(&self) -> ChainResult<()> {
        if self.cadence_secs == 0 {
            return Err(ChainError::Config(
                "snapshot_validator.cadence_secs must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for SnapshotValidatorConfig {
    fn default() -> Self {
        Self {
            cadence_secs: DEFAULT_SNAPSHOT_VALIDATOR_CADENCE_SECS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruning_config_defaults_are_valid() {
        let config = NodeConfig::default();
        assert_eq!(config.pruning.cadence_secs, DEFAULT_PRUNING_CADENCE_SECS);
        assert_eq!(
            config.pruning.retention_depth,
            DEFAULT_PRUNING_RETENTION_DEPTH
        );
        assert!(!config.pruning.emergency_pause);
        config.pruning.validate().expect("defaults should validate");
    }

    #[test]
    fn admission_reconciler_defaults_are_valid() {
        let config = NodeConfig::default();
        assert_eq!(
            config.admission_reconciler.cadence_secs,
            DEFAULT_ADMISSION_RECONCILER_CADENCE_SECS
        );
        assert_eq!(
            config.admission_reconciler.drift_alert_threshold,
            DEFAULT_ADMISSION_RECONCILER_ALERT_THRESHOLD
        );
        assert_eq!(
            config.admission_reconciler.max_audit_lag_secs,
            DEFAULT_ADMISSION_RECONCILER_AUDIT_LAG_SECS
        );
        config
            .admission_reconciler
            .validate()
            .expect("defaults should validate");
    }

    #[test]
    fn snapshot_validator_defaults_are_valid() {
        let config = NodeConfig::default();
        assert_eq!(
            config.snapshot_validator.cadence_secs,
            DEFAULT_SNAPSHOT_VALIDATOR_CADENCE_SECS
        );
        config
            .snapshot_validator
            .validate()
            .expect("defaults should validate");
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
pub struct GovernanceConfig {
    pub timetoke_rewards: TimetokeRewardsGovernanceConfig,
}

impl GovernanceConfig {
    pub fn validate(&self) -> ChainResult<()> {
        self.timetoke_rewards.validate()
    }

    pub fn timetoke_rewards_governance(&self) -> TimetokeRewardGovernance {
        self.timetoke_rewards.to_governance()
    }
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            timetoke_rewards: TimetokeRewardsGovernanceConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TimetokeRewardsGovernanceConfig {
    pub enabled: bool,
    pub leader_pool_weight: f64,
    pub witness_pool_weight: f64,
    pub minimum_balance_hours: u64,
}

impl TimetokeRewardsGovernanceConfig {
    fn validate(&self) -> ChainResult<()> {
        let policy = self.to_governance();
        policy
            .validate()
            .map_err(|err| ChainError::Config(format!("governance.timetoke_rewards {err}")))
    }

    pub fn to_governance(&self) -> TimetokeRewardGovernance {
        TimetokeRewardGovernance::new(
            self.enabled,
            self.leader_pool_weight,
            self.witness_pool_weight,
            self.minimum_balance_hours,
        )
    }
}

impl Default for TimetokeRewardsGovernanceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            leader_pool_weight: 0.6,
            witness_pool_weight: 0.3,
            minimum_balance_hours: 1,
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
    use std::path::PathBuf;
    use tempfile::tempdir;

    use crate::node_runtime::node::NodeRuntimeConfig;

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
    fn telemetry_config_validation_accepts_defaults() {
        let config = TelemetryConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn telemetry_config_validation_rejects_zero_queue() {
        let mut config = TelemetryConfig::default();
        config.trace_max_queue_size = 0;
        let error = config
            .validate()
            .expect_err("telemetry validation should fail for zero queue size");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("trace_max_queue_size"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn telemetry_config_validation_rejects_invalid_ratio() {
        let mut config = TelemetryConfig::default();
        config.trace_sample_ratio = 1.5;
        let error = config
            .validate()
            .expect_err("telemetry validation should fail for invalid ratio");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("trace_sample_ratio"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn telemetry_config_validation_rejects_invalid_endpoint() {
        let mut config = TelemetryConfig::default();
        config.http_endpoint = Some("not a uri".to_string());
        let error = config
            .validate()
            .expect_err("telemetry validation should fail for invalid endpoint");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("telemetry.http_endpoint"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn telemetry_config_validation_rejects_partial_tls_identity() {
        let mut config = TelemetryConfig::default();
        config.grpc_tls = Some(TelemetryTlsConfig {
            client_certificate: Some(PathBuf::from("/tmp/cert.pem")),
            ..TelemetryTlsConfig::default()
        });
        let error = config
            .validate()
            .expect_err("telemetry validation should fail for partial TLS identity");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("client_certificate"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn telemetry_config_validation_rejects_invalid_vrf_thresholds() {
        let mut config = TelemetryConfig::default();
        config.vrf_thresholds.max_fallback_ratio = 1.2;
        let error = config
            .validate()
            .expect_err("telemetry validation should fail for invalid VRF thresholds");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("telemetry.vrf_thresholds.max_fallback_ratio"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
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
    fn node_config_validation_rejects_empty_network_auth_token() {
        let mut config = NodeConfig::default();
        config.network.rpc.auth_token = Some("   ".into());
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("network.rpc.auth_token"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn node_config_validation_rejects_empty_network_allowed_origin() {
        let mut config = NodeConfig::default();
        config.network.rpc.allowed_origin = Some("".into());
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("network.rpc.allowed_origin"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn node_config_validation_rejects_zero_network_timeouts() {
        let mut config = NodeConfig::default();
        config.network.limits.header_read_timeout_ms = 0;
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("network.limits.header_read_timeout_ms"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }

        let mut config = NodeConfig::default();
        config.network.limits.read_timeout_ms = 0;
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("network.limits.read_timeout_ms"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }

        let mut config = NodeConfig::default();
        config.network.limits.write_timeout_ms = 0;
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("network.limits.write_timeout_ms"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn node_config_validation_rejects_zero_network_body_limits() {
        let mut config = NodeConfig::default();
        config.network.limits.max_header_bytes = 0;
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("network.limits.max_header_bytes"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }

        let mut config = NodeConfig::default();
        config.network.limits.max_body_bytes = 0;
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("network.limits.max_body_bytes"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn node_config_validation_rejects_invalid_token_bucket() {
        let mut config = NodeConfig::default();
        config.network.limits.per_ip_token_bucket.burst = 0;
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("per_ip_token_bucket.burst"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }

        let mut config = NodeConfig::default();
        config
            .network
            .limits
            .per_ip_token_bucket
            .replenish_per_minute = 0;
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("per_ip_token_bucket.replenish_per_minute"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn node_config_validation_rejects_missing_tls_files() {
        let mut config = NodeConfig::default();
        let temp = tempdir().expect("tempdir");
        let cert_path = temp.path().join("server.pem");
        let key_path = temp.path().join("server-key.pem");
        fs::write(&key_path, "key").expect("write key");
        config.network.tls.enabled = true;
        config.network.tls.certificate = Some(cert_path.clone());
        config.network.tls.private_key = Some(key_path.clone());
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("network.tls.certificate"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }

        let mut config = NodeConfig::default();
        fs::write(&cert_path, "certificate").expect("write cert");
        config.network.tls.enabled = true;
        config.network.tls.certificate = Some(cert_path);
        config.network.tls.private_key = Some(temp.path().join("missing-key.pem"));
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("network.tls.private_key"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }

        let mut config = NodeConfig::default();
        config.network.tls.enabled = true;
        config.network.tls.require_client_auth = true;
        config.network.tls.certificate = Some(temp.path().join("server.pem"));
        config.network.tls.private_key = Some(key_path);
        config.network.tls.client_ca = Some(temp.path().join("missing-ca.pem"));
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("network.tls.client_ca"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn node_config_validation_rejects_tls_directories() {
        let mut config = NodeConfig::default();
        let temp = tempdir().expect("tempdir");
        let dir = temp.path().join("certs");
        fs::create_dir(&dir).expect("create dir");
        let key_path = temp.path().join("server-key.pem");
        fs::write(&key_path, "key").expect("write key");
        config.network.tls.enabled = true;
        config.network.tls.certificate = Some(dir);
        config.network.tls.private_key = Some(key_path);
        let error = config.validate().expect_err("validation should fail");
        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("must be a file"),
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
            config.validator.vrf.threshold.target_validator_count,
            ValidatorSelectionConfig::default()
                .vrf
                .threshold
                .target_validator_count
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
witness_count = 16
epoch_duration_secs = 3600
round_timeout_ms = 1000
max_round_extensions = 1

[validator.vrf.threshold]
curve = "curve"
target_validator_count = 100
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
witness_count = 16
epoch_duration_secs = 7200
round_timeout_ms = 2000
max_round_extensions = 2

[validator.vrf.threshold]
curve = "curve"
target_validator_count = 77
"#,
        )
        .expect("write malachite config");

        let loaded = NodeConfig::load(&node_path).expect("load node config");
        assert_eq!(loaded.validator_set_size(), 77);
    }

    #[test]
    fn node_config_for_mode_hybrid_applies_mode_defaults() {
        let config = NodeConfig::for_mode(RuntimeMode::Hybrid);

        assert!(config.rollout.telemetry.enabled);
        assert_eq!(config.network.p2p.heartbeat_interval_ms, 4_000);
        assert_eq!(config.network.p2p.gossip_rate_limit_per_sec, 192);
        assert_eq!(config.malachite.proof.proof_batch_size, 96);
        assert_eq!(config.malachite.proof.proof_cache_ttl_secs, 720);
    }

    #[test]
    fn node_config_for_mode_validator_applies_mode_defaults() {
        let config = NodeConfig::for_mode(RuntimeMode::Validator);

        assert!(config.rollout.telemetry.enabled);
        assert_eq!(config.rollout.telemetry.sample_interval_secs, 15);
        assert_eq!(config.rollout.release_channel, ReleaseChannel::Testnet);
        assert_eq!(config.network.p2p.heartbeat_interval_ms, 3_000);
        assert_eq!(config.network.p2p.gossip_rate_limit_per_sec, 256);
        assert_eq!(config.malachite.proof.proof_batch_size, 128);
        assert_eq!(config.malachite.proof.proof_cache_ttl_secs, 600);
        assert_eq!(config.malachite.proof.max_recursive_depth, 6);
    }

    #[test]
    fn wallet_config_for_mode_validator_inherits_hybrid_defaults() {
        let config = WalletConfig::for_mode(RuntimeMode::Validator);

        assert!(!config.node.embedded);
        assert!(
            !config.node.gossip_endpoints.is_empty(),
            "validator mode should ensure gossip endpoints are populated"
        );
        assert!(
            config
                .node
                .gossip_endpoints
                .iter()
                .all(|endpoint| !endpoint.trim().is_empty()),
            "gossip endpoints must not contain empty entries"
        );
    }

    #[test]
    fn wallet_config_defaults_cover_engine_policy_and_fees() {
        let config = WalletConfig::default();

        assert_eq!(
            config.wallet.engine,
            WalletEngineSettings::default(),
            "engine defaults should match the wallet module"
        );
        assert_eq!(
            config.wallet.policy,
            WalletPolicySettings::default(),
            "policy defaults should match the wallet module"
        );
        assert_eq!(
            config.wallet.fees,
            WalletFeeSettings::default(),
            "fee defaults should match the wallet module"
        );
        assert_eq!(
            config.wallet.prover,
            WalletProverSettings::default(),
            "prover defaults should match the wallet module"
        );
    }

    #[test]
    fn wallet_config_validation_rejects_invalid_policy_and_fees() {
        let mut config = WalletConfig::default();
        config.wallet.policy.external_gap_limit = 0;
        let error = config.validate().expect_err("gap limit must be validated");
        match error {
            ChainError::Config(message) => {
                assert!(message.contains("wallet.policy.external_gap_limit"));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        config.wallet.policy.external_gap_limit = 20;
        config.wallet.fees.min_sats_per_vbyte = 5;
        config.wallet.fees.max_sats_per_vbyte = 4;
        let error = config.validate().expect_err("fee bounds must be validated");
        match error {
            ChainError::Config(message) => {
                assert!(message.contains("wallet.fees.min_sats_per_vbyte"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn hsm_secrets_backend_reports_unavailable_error() {
        let backend = SecretsBackendConfig::Hsm(HsmKeystoreConfig::default());
        let error = backend
            .build_keystore()
            .expect_err("HSM backend should not be available by default");

        match error {
            ChainError::Config(message) => {
                assert!(
                    message.contains("HSM secrets backend is not available"),
                    "unexpected message: {}",
                    message
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn admission_defaults_round_trip_from_templates() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|path| path.parent())
            .expect("workspace root");
        let templates = [
            "config/node.toml",
            "config/hybrid.toml",
            "config/validator.toml",
        ];

        for template in templates {
            let path = workspace_root.join(template);
            let config = NodeConfig::load(&path).expect("load template");
            let runtime = NodeRuntimeConfig::from(&config);
            assert_eq!(
                runtime.admission.policy_path,
                config.network.admission.policy_path
            );
            assert_eq!(
                runtime.admission.audit_retention_days,
                config.network.admission.audit_retention_days
            );
            assert_eq!(
                runtime.admission.defaults,
                config.network.admission.defaults
            );
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletServiceConfig {
    pub rpc: WalletRpcConfig,
    pub security: WalletSecurityConfig,
    pub audit: WalletAuditConfig,
    pub auth: WalletAuthConfig,
    pub keys: WalletKeysConfig,
    pub budgets: WalletBudgetsConfig,
    pub rescan: WalletRescanConfig,
    pub engine: WalletEngineSettings,
    pub policy: WalletPolicySettings,
    pub fees: WalletFeeSettings,
    pub prover: WalletProverSettings,
}

impl Default for WalletServiceConfig {
    fn default() -> Self {
        Self {
            rpc: WalletRpcConfig::default(),
            security: WalletSecurityConfig::default(),
            audit: WalletAuditConfig::default(),
            auth: WalletAuthConfig::default(),
            keys: WalletKeysConfig::default(),
            budgets: WalletBudgetsConfig::default(),
            rescan: WalletRescanConfig::default(),
            engine: WalletEngineSettings::default(),
            policy: WalletPolicySettings::default(),
            fees: WalletFeeSettings::default(),
            prover: WalletProverSettings::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletConfig {
    pub data_dir: PathBuf,
    #[serde(default)]
    pub wallet: WalletServiceConfig,
    #[serde(default)]
    pub node: WalletNodeRuntimeConfig,
    #[serde(default)]
    pub gui: WalletGuiConfig,
    #[cfg(feature = "vendor_electrs")]
    #[serde(default = "default_wallet_electrs_config")]
    pub electrs: Option<ElectrsConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletRpcConfig {
    #[serde(default = "default_wallet_rpc_listen")]
    pub listen: SocketAddr,
    #[serde(default)]
    pub allowed_origin: Option<String>,
    #[serde(default)]
    pub requests_per_minute: Option<u64>,
    #[serde(default)]
    pub security: WalletRpcSecurityConfig,
}

impl WalletRpcConfig {
    fn validate(&self, mtls_enabled: bool) -> ChainResult<()> {
        if let Some(origin) = &self.allowed_origin {
            if origin.trim().is_empty() {
                return Err(ChainError::Config(
                    "wallet configuration wallet.rpc.allowed_origin must not be empty".into(),
                ));
            }
        }
        if let Some(limit) = self.requests_per_minute {
            if limit == 0 {
                return Err(ChainError::Config(
                    "wallet configuration wallet.rpc.requests_per_minute must be greater than 0"
                        .into(),
                ));
            }
        }
        self.security.validate(mtls_enabled)?;
        Ok(())
    }
}

impl Default for WalletRpcConfig {
    fn default() -> Self {
        Self {
            listen: default_wallet_rpc_listen(),
            allowed_origin: None,
            requests_per_minute: None,
            security: WalletRpcSecurityConfig::default(),
        }
    }
}

fn default_wallet_rpc_listen() -> SocketAddr {
    "127.0.0.1:9090".parse().expect("valid socket addr")
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletRpcSecurityConfig {
    pub certificate: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
    pub ca_certificate: Option<PathBuf>,
}

impl WalletRpcSecurityConfig {
    fn validate(&self, mtls_enabled: bool) -> ChainResult<()> {
        if cfg!(not(feature = "wallet_rpc_mtls")) {
            if self.certificate.is_some()
                || self.private_key.is_some()
                || self.ca_certificate.is_some()
            {
                return Err(wallet_rpc_mtls_disabled_error("wallet.rpc.security"));
            }
            return Ok(());
        }

        if mtls_enabled {
            for (path, field) in [
                (&self.certificate, "wallet.rpc.security.certificate"),
                (&self.private_key, "wallet.rpc.security.private_key"),
                (&self.ca_certificate, "wallet.rpc.security.ca_certificate"),
            ] {
                let path = path.as_ref().ok_or_else(|| {
                    ChainError::Config(format!(
                        "{field} must be provided when TLS security is enabled"
                    ))
                })?;
                if path.as_os_str().is_empty() {
                    return Err(ChainError::Config(format!("{field} must not be empty")));
                }
                if !path.exists() {
                    return Err(ChainError::Config(format!(
                        "{field} references {} which does not exist",
                        path.display()
                    )));
                }
            }
        } else if self.certificate.is_some()
            || self.private_key.is_some()
            || self.ca_certificate.is_some()
        {
            return Err(ChainError::Config(
                "wallet.rpc.security certificate, private_key, and ca_certificate require wallet.security.mtls_enabled"
                    .into(),
            ));
        }
        Ok(())
    }

    pub fn runtime_settings(
        &self,
        security: &WalletSecurityConfig,
    ) -> WalletRpcSecurityRuntimeConfig {
        WalletRpcSecurityRuntimeConfig::new(
            security.mtls_enabled,
            self.certificate.clone(),
            self.private_key.clone(),
            self.ca_certificate.clone(),
            security.ca_fingerprints.clone(),
        )
    }
}

impl Default for WalletRpcSecurityConfig {
    fn default() -> Self {
        Self {
            certificate: None,
            private_key: None,
            ca_certificate: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletAuditConfig {
    pub enabled: bool,
    pub retention_days: u64,
}

impl WalletAuditConfig {
    pub fn runtime_settings(&self, data_dir: &Path) -> WalletAuditRuntimeConfig {
        let mut settings = WalletAuditRuntimeConfig::default();
        settings.set_enabled(self.enabled);
        settings.set_retention_days(self.retention_days);
        settings.set_directory(data_dir.join("wallet").join("audit"));
        settings
    }
}

impl Default for WalletAuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_days: 30,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletSecurityConfig {
    #[serde(default)]
    pub mtls_enabled: bool,
    #[serde(default)]
    pub ca_fingerprints: Vec<WalletRpcSecurityCaFingerprint>,
    #[serde(default)]
    pub bindings: Vec<WalletRpcSecurityBinding>,
}

impl WalletSecurityConfig {
    fn validate(&self) -> ChainResult<()> {
        if cfg!(not(feature = "wallet_rpc_mtls")) {
            if self.is_configured() {
                return Err(wallet_rpc_mtls_disabled_error("wallet.security"));
            }
            return Ok(());
        }

        for fingerprint in &self.ca_fingerprints {
            fingerprint.validate("wallet.security.ca_fingerprints")?;
        }
        for binding in &self.bindings {
            binding.validate("wallet.security.bindings")?;
        }
        Ok(())
    }

    pub fn runtime_bindings(&self) -> Vec<WalletSecurityBinding> {
        self.bindings
            .iter()
            .map(WalletRpcSecurityBinding::to_runtime_binding)
            .collect()
    }

    fn is_configured(&self) -> bool {
        self.mtls_enabled || !self.ca_fingerprints.is_empty() || !self.bindings.is_empty()
    }
}

impl Default for WalletSecurityConfig {
    fn default() -> Self {
        Self {
            mtls_enabled: false,
            ca_fingerprints: Vec::new(),
            bindings: Vec::new(),
        }
    }
}

fn wallet_rpc_mtls_disabled_error(scope: &str) -> ChainError {
    ChainError::Config(format!(
        "{scope} requires compiling with the `wallet_rpc_mtls` feature; rebuild this binary to configure wallet RPC security"
    ))
}

#[cfg(test)]
mod wallet_security_tests {
    use super::*;

    #[test]
    fn ca_fingerprint_metadata_is_preserved_in_runtime_settings() {
        let mut service = WalletServiceConfig::default();
        service.security.ca_fingerprints = vec![
            WalletRpcSecurityCaFingerprint {
                fingerprint: "aa55".into(),
                description: Some("Primary CA".into()),
            },
            WalletRpcSecurityCaFingerprint {
                fingerprint: "bb66".into(),
                description: None,
            },
        ];

        let runtime = service.runtime_settings(&service.security);
        let entries = runtime.ca_fingerprints();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].fingerprint, "aa55");
        assert_eq!(entries[0].description.as_deref(), Some("Primary CA"));
        assert_eq!(entries[1].fingerprint, "bb66");
        assert!(entries[1].description.is_none());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletRpcSecurityCaFingerprint {
    pub fingerprint: String,
    #[serde(default)]
    pub description: Option<String>,
}

impl WalletRpcSecurityCaFingerprint {
    fn validate(&self, label: &str) -> ChainResult<()> {
        let trimmed = self.fingerprint.trim();
        if trimmed.is_empty() {
            return Err(ChainError::Config(format!(
                "{label} entries must not contain empty fingerprints"
            )));
        }
        if !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(ChainError::Config(format!(
                "{label} fingerprints must be hexadecimal"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletRpcSecurityBinding {
    pub identity: WalletIdentity,
    #[serde(default)]
    pub roles: Vec<WalletRole>,
}

impl WalletRpcSecurityBinding {
    fn validate(&self, label: &str) -> ChainResult<()> {
        if self.roles.is_empty() {
            return Err(ChainError::Config(format!(
                "{label} entry for identity {:?} must define at least one role",
                self.identity
            )));
        }
        Ok(())
    }

    fn to_runtime_binding(&self) -> WalletSecurityBinding {
        let roles: WalletRoleSet = self.roles.iter().copied().collect();
        WalletSecurityBinding::new(self.identity.clone(), roles)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletAuthConfig {
    pub enabled: bool,
    pub token: Option<String>,
    pub tls: Option<WalletAuthTlsConfig>,
}

impl WalletAuthConfig {
    fn validate(&self, require_tls: bool) -> ChainResult<()> {
        if !self.enabled {
            if let Some(tls) = &self.tls {
                if tls.is_configured() {
                    tls.validate("wallet.auth.tls")?;
                }
            }
            return Ok(());
        }

        match self
            .token
            .as_ref()
            .map(|value| value.trim())
            .filter(|v| !v.is_empty())
        {
            Some(_) => {}
            None => {
                return Err(ChainError::Config(
                    "wallet configuration wallet.auth.token must be provided when authentication is enabled"
                        .into(),
                ));
            }
        }

        if require_tls {
            let tls = self
                .tls
                .as_ref()
                .ok_or_else(|| {
                    ChainError::Config(
                        "wallet configuration wallet.auth.tls must be configured when authentication is enabled"
                            .into(),
                    )
                })?;
            tls.validate("wallet.auth.tls")?;
        } else if let Some(tls) = &self.tls {
            tls.validate("wallet.auth.tls")?;
        }

        Ok(())
    }
}

impl Default for WalletAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            token: None,
            tls: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletAuthTlsConfig {
    pub certificate: Option<PathBuf>,
    pub private_key: Option<PathBuf>,
    pub ca_certificate: Option<PathBuf>,
}

impl WalletAuthTlsConfig {
    fn is_configured(&self) -> bool {
        self.certificate.is_some() || self.private_key.is_some() || self.ca_certificate.is_some()
    }

    fn validate(&self, label: &str) -> ChainResult<()> {
        let certificate = self.certificate.as_ref().ok_or_else(|| {
            ChainError::Config(format!(
                "wallet configuration {label}.certificate must be provided when TLS is enabled"
            ))
        })?;
        let private_key = self.private_key.as_ref().ok_or_else(|| {
            ChainError::Config(format!(
                "wallet configuration {label}.private_key must be provided when TLS is enabled"
            ))
        })?;

        for (path, field) in [(certificate, "certificate"), (private_key, "private_key")] {
            if path.as_os_str().is_empty() {
                return Err(ChainError::Config(format!(
                    "wallet configuration {label}.{field} must not be empty"
                )));
            }
            if !path.exists() {
                return Err(ChainError::Config(format!(
                    "wallet configuration {label}.{field} references {} which does not exist",
                    path.display()
                )));
            }
        }

        if let Some(ca) = &self.ca_certificate {
            if ca.as_os_str().is_empty() {
                return Err(ChainError::Config(format!(
                    "wallet configuration {label}.ca_certificate must not be empty"
                )));
            }
            if !ca.exists() {
                return Err(ChainError::Config(format!(
                    "wallet configuration {label}.ca_certificate references {} which does not exist",
                    ca.display()
                )));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletKeysConfig {
    pub key_path: PathBuf,
}

impl WalletKeysConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.key_path.as_os_str().is_empty() {
            return Err(ChainError::Config(
                "wallet configuration wallet.keys.key_path must not be empty".into(),
            ));
        }
        Ok(())
    }
}

impl Default for WalletKeysConfig {
    fn default() -> Self {
        Self {
            key_path: PathBuf::from("./keys/wallet.toml"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletBudgetsConfig {
    pub submit_transaction_per_minute: u64,
    pub proof_generation_per_minute: u64,
    pub pipeline_depth: usize,
}

impl WalletBudgetsConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.submit_transaction_per_minute == 0 {
            return Err(ChainError::Config(
                "wallet configuration wallet.budgets.submit_transaction_per_minute must be greater than 0"
                    .into(),
            ));
        }
        if self.proof_generation_per_minute == 0 {
            return Err(ChainError::Config(
                "wallet configuration wallet.budgets.proof_generation_per_minute must be greater than 0"
                    .into(),
            ));
        }
        if self.pipeline_depth == 0 {
            return Err(ChainError::Config(
                "wallet configuration wallet.budgets.pipeline_depth must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for WalletBudgetsConfig {
    fn default() -> Self {
        Self {
            submit_transaction_per_minute: 120,
            proof_generation_per_minute: 60,
            pipeline_depth: 64,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletRescanConfig {
    pub auto_trigger: bool,
    pub lookback_blocks: u64,
    pub chunk_size: u64,
}

impl WalletRescanConfig {
    fn validate(&self) -> ChainResult<()> {
        if self.lookback_blocks == 0 {
            return Err(ChainError::Config(
                "wallet configuration wallet.rescan.lookback_blocks must be greater than 0".into(),
            ));
        }
        if self.chunk_size == 0 {
            return Err(ChainError::Config(
                "wallet configuration wallet.rescan.chunk_size must be greater than 0".into(),
            ));
        }
        Ok(())
    }
}

impl Default for WalletRescanConfig {
    fn default() -> Self {
        Self {
            auto_trigger: false,
            lookback_blocks: 2_880,
            chunk_size: 64,
        }
    }
}

fn validate_wallet_engine(config: &WalletEngineSettings) -> ChainResult<()> {
    if config.data_dir.as_os_str().is_empty() {
        return Err(ChainError::Config(
            "wallet configuration wallet.engine.data_dir must not be empty".into(),
        ));
    }
    if config.keystore_path.as_os_str().is_empty() {
        return Err(ChainError::Config(
            "wallet configuration wallet.engine.keystore_path must not be empty".into(),
        ));
    }
    if config.backup_path.as_os_str().is_empty() {
        return Err(ChainError::Config(
            "wallet configuration wallet.engine.backup_path must not be empty".into(),
        ));
    }
    Ok(())
}

fn validate_wallet_policy(config: &WalletPolicySettings) -> ChainResult<()> {
    if config.external_gap_limit == 0 {
        return Err(ChainError::Config(
            "wallet configuration wallet.policy.external_gap_limit must be greater than 0".into(),
        ));
    }
    if config.internal_gap_limit == 0 {
        return Err(ChainError::Config(
            "wallet configuration wallet.policy.internal_gap_limit must be greater than 0".into(),
        ));
    }
    if config.min_confirmations == 0 {
        return Err(ChainError::Config(
            "wallet configuration wallet.policy.min_confirmations must be greater than 0".into(),
        ));
    }
    Ok(())
}

fn validate_wallet_fees(config: &WalletFeeSettings) -> ChainResult<()> {
    if config.min_sats_per_vbyte == 0 {
        return Err(ChainError::Config(
            "wallet configuration wallet.fees.min_sats_per_vbyte must be greater than 0".into(),
        ));
    }
    if config.max_sats_per_vbyte == 0 {
        return Err(ChainError::Config(
            "wallet configuration wallet.fees.max_sats_per_vbyte must be greater than 0".into(),
        ));
    }
    if config.min_sats_per_vbyte > config.max_sats_per_vbyte {
        return Err(ChainError::Config(
            "wallet configuration wallet.fees.min_sats_per_vbyte must not exceed max_sats_per_vbyte"
                .into(),
        ));
    }
    if config.default_sats_per_vbyte < config.min_sats_per_vbyte
        || config.default_sats_per_vbyte > config.max_sats_per_vbyte
    {
        return Err(ChainError::Config(
            "wallet configuration wallet.fees.default_sats_per_vbyte must fall within the configured min/max bounds"
                .into(),
        ));
    }
    Ok(())
}

fn validate_wallet_prover(config: &WalletProverSettings) -> ChainResult<()> {
    if config.job_timeout_secs == 0 {
        return Err(ChainError::Config(
            "wallet configuration wallet.prover.job_timeout_secs must be greater than 0".into(),
        ));
    }
    if config.max_witness_bytes == 0 {
        return Err(ChainError::Config(
            "wallet configuration wallet.prover.max_witness_bytes must be greater than 0".into(),
        ));
    }
    if config.max_witness_bytes > usize::MAX as u64 {
        return Err(ChainError::Config(
            "wallet configuration wallet.prover.max_witness_bytes must fit into platform usize"
                .into(),
        ));
    }
    if config.max_concurrency == 0 {
        return Err(ChainError::Config(
            "wallet configuration wallet.prover.max_concurrency must be greater than 0".into(),
        ));
    }
    Ok(())
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
        if self.wallet.rpc.requests_per_minute.is_none() {
            self.wallet.rpc.requests_per_minute = Some(600);
        }
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
        if let Some(parent) = self.wallet.keys.key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&self.wallet.engine.data_dir)?;
        if let Some(parent) = self.wallet.engine.keystore_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&self.wallet.engine.backup_path)?;
        let security_paths = WalletSecurityPaths::from_data_dir(&self.data_dir);
        security_paths.ensure()?;
        if self.wallet.audit.enabled {
            fs::create_dir_all(self.data_dir.join("wallet").join("audit"))?;
        }
        #[cfg(feature = "vendor_electrs")]
        self.ensure_electrs_directories()?;
        Ok(())
    }

    fn validate(&self) -> ChainResult<()> {
        if cfg!(not(feature = "wallet_rpc_mtls")) && self.wallet.security.is_configured() {
            return Err(wallet_rpc_mtls_disabled_error("wallet.security"));
        }
        self.wallet.security.validate()?;
        self.wallet
            .rpc
            .validate(self.wallet.security.mtls_enabled)?;
        self.wallet.keys.validate()?;
        self.wallet.budgets.validate()?;
        self.wallet.rescan.validate()?;
        validate_wallet_engine(&self.wallet.engine)?;
        validate_wallet_policy(&self.wallet.policy)?;
        validate_wallet_fees(&self.wallet.fees)?;
        validate_wallet_prover(&self.wallet.prover)?;
        self.wallet.auth.validate(false)?;
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

    pub fn validate_for_mode(
        &self,
        mode: RuntimeMode,
        node: Option<&NodeConfig>,
    ) -> ChainResult<()> {
        if mode.includes_node() {
            self.wallet.auth.validate(true)?;
            if let Some(node) = node {
                let wallet_listen = self.wallet.rpc.listen;
                let node_listen = node.network.rpc.listen;
                if wallet_listen.port() != 0
                    && node_listen.port() != 0
                    && wallet_listen.port() == node_listen.port()
                    && (wallet_listen.ip() == node_listen.ip()
                        || wallet_listen.ip().is_unspecified()
                        || node_listen.ip().is_unspecified())
                {
                    return Err(ChainError::Config(
                        "wallet configuration wallet.rpc.listen must use a distinct address from the node RPC listener in hybrid/validator modes"
                            .into(),
                    ));
                }
                if let Some(port) = extract_tcp_port(&node.p2p.listen_addr) {
                    if port != 0 && wallet_listen.port() == port {
                        return Err(ChainError::Config(
                            "wallet configuration wallet.rpc.listen must not reuse the node P2P TCP port"
                                .into(),
                        ));
                    }
                }
            }
        } else {
            self.wallet.auth.validate(false)?;
        }

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
            wallet: WalletServiceConfig::default(),
            node: WalletNodeRuntimeConfig {
                embedded: false,
                gossip_endpoints: vec!["/ip4/127.0.0.1/tcp/7600".to_string()],
            },
            gui: WalletGuiConfig::default(),
            #[cfg(feature = "vendor_electrs")]
            electrs: default_wallet_electrs_config(),
        }
    }
}

fn extract_tcp_port(multiaddr: &str) -> Option<u16> {
    let mut parts = multiaddr.split('/').filter(|segment| !segment.is_empty());
    while let Some(protocol) = parts.next() {
        if protocol.eq_ignore_ascii_case("tcp") {
            if let Some(value) = parts.next() {
                if let Ok(port) = value.parse::<u16>() {
                    return Some(port);
                }
            }
        }
    }
    None
}

#[cfg(feature = "vendor_electrs")]
fn default_wallet_electrs_config() -> Option<ElectrsConfig> {
    Some(ElectrsConfig::default())
}

const WALLET_GUI_DEFAULT_POLL_INTERVAL_MS: u64 = 5_000;
const WALLET_GUI_MIN_POLL_INTERVAL_MS: u64 = 1_000;
const WALLET_GUI_DEFAULT_MAX_HISTORY_ROWS: u32 = 20;
const WALLET_GUI_MIN_HISTORY_ROWS: u32 = 5;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct WalletGuiConfig {
    pub poll_interval_ms: u64,
    pub max_history_rows: u32,
    pub theme: WalletGuiTheme,
    pub confirm_clipboard: bool,
    pub telemetry_opt_in: bool,
    pub security_controls_enabled: bool,
}

impl WalletGuiConfig {
    pub fn sanitized(mut self) -> Self {
        if self.poll_interval_ms < WALLET_GUI_MIN_POLL_INTERVAL_MS {
            self.poll_interval_ms = WALLET_GUI_MIN_POLL_INTERVAL_MS;
        }
        if self.max_history_rows < WALLET_GUI_MIN_HISTORY_ROWS {
            self.max_history_rows = WALLET_GUI_DEFAULT_MAX_HISTORY_ROWS;
        }
        self
    }
}

impl Default for WalletGuiConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: WALLET_GUI_DEFAULT_POLL_INTERVAL_MS,
            max_history_rows: WALLET_GUI_DEFAULT_MAX_HISTORY_ROWS,
            theme: WalletGuiTheme::System,
            confirm_clipboard: true,
            telemetry_opt_in: false,
            security_controls_enabled: cfg!(feature = "wallet_rpc_mtls"),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletGuiTheme {
    System,
    Light,
    Dark,
}

impl Default for WalletGuiTheme {
    fn default() -> Self {
        WalletGuiTheme::System
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

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryTlsConfig {
    pub ca_certificate: Option<PathBuf>,
    pub client_certificate: Option<PathBuf>,
    pub client_private_key: Option<PathBuf>,
    pub domain_name: Option<String>,
    pub insecure_skip_verify: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub http_endpoint: Option<String>,
    pub auth_token: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_retry_max")]
    pub retry_max: u64,
    #[serde(default = "default_sample_interval_secs")]
    pub sample_interval_secs: u64,
    #[serde(default = "default_redact_logs")]
    pub redact_logs: bool,
    #[serde(default = "default_trace_max_queue_size")]
    pub trace_max_queue_size: usize,
    #[serde(default = "default_trace_max_export_batch_size")]
    pub trace_max_export_batch_size: usize,
    #[serde(default = "default_trace_sample_ratio")]
    pub trace_sample_ratio: f64,
    #[serde(default = "default_warn_on_drop")]
    pub warn_on_drop: bool,
    #[serde(default)]
    pub grpc_tls: Option<TelemetryTlsConfig>,
    #[serde(default)]
    pub http_tls: Option<TelemetryTlsConfig>,
    #[serde(default)]
    pub vrf_thresholds: VrfTelemetryThresholds,
    #[serde(default)]
    pub metrics: PrometheusMetricsConfig,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            http_endpoint: None,
            auth_token: None,
            timeout_ms: default_timeout_ms(),
            retry_max: default_retry_max(),
            sample_interval_secs: default_sample_interval_secs(),
            redact_logs: default_redact_logs(),
            trace_max_queue_size: default_trace_max_queue_size(),
            trace_max_export_batch_size: default_trace_max_export_batch_size(),
            trace_sample_ratio: default_trace_sample_ratio(),
            warn_on_drop: default_warn_on_drop(),
            grpc_tls: None,
            http_tls: None,
            vrf_thresholds: VrfTelemetryThresholds::default(),
            metrics: PrometheusMetricsConfig::default(),
        }
    }
}

impl TelemetryConfig {
    pub fn validate(&self) -> ChainResult<()> {
        if self.trace_max_queue_size == 0 {
            return Err(ChainError::Config(
                "telemetry.trace_max_queue_size must be greater than 0".into(),
            ));
        }
        if self.trace_max_export_batch_size == 0 {
            return Err(ChainError::Config(
                "telemetry.trace_max_export_batch_size must be greater than 0".into(),
            ));
        }
        if self.trace_max_export_batch_size > self.trace_max_queue_size {
            return Err(ChainError::Config(
                "telemetry.trace_max_export_batch_size must be less than or equal to trace_max_queue_size"
                    .into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.trace_sample_ratio) {
            return Err(ChainError::Config(
                "telemetry.trace_sample_ratio must be between 0.0 and 1.0".into(),
            ));
        }

        if let Some(endpoint) = self.endpoint.as_ref() {
            validate_endpoint("telemetry.endpoint", endpoint)?;
        }
        if let Some(endpoint) = self.http_endpoint.as_ref() {
            validate_endpoint("telemetry.http_endpoint", endpoint)?;
        }

        validate_tls_config("telemetry.grpc_tls", self.grpc_tls.as_ref())?;
        validate_tls_config("telemetry.http_tls", self.http_tls.as_ref())?;
        self.vrf_thresholds.validate()?;
        self.metrics.validate()?;

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PrometheusMetricsConfig {
    pub listen: Option<SocketAddr>,
    pub auth_token: Option<String>,
}

impl Default for PrometheusMetricsConfig {
    fn default() -> Self {
        Self {
            listen: None,
            auth_token: None,
        }
    }
}

impl PrometheusMetricsConfig {
    pub fn validate(&self) -> ChainResult<()> {
        if let Some(token) = self.auth_token.as_ref() {
            if token.trim().is_empty() {
                return Err(ChainError::Config(
                    "telemetry.metrics.auth_token must not be empty".into(),
                ));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct VrfTelemetryThresholds {
    pub min_participation_rate: f64,
    pub max_rejection_rate: f64,
    pub max_fallback_ratio: f64,
}

impl Default for VrfTelemetryThresholds {
    fn default() -> Self {
        Self {
            min_participation_rate: 0.66,
            max_rejection_rate: 0.25,
            max_fallback_ratio: 0.10,
        }
    }
}

impl VrfTelemetryThresholds {
    pub fn validate(&self) -> ChainResult<()> {
        for (label, value) in [
            (
                "telemetry.vrf_thresholds.min_participation_rate",
                self.min_participation_rate,
            ),
            (
                "telemetry.vrf_thresholds.max_rejection_rate",
                self.max_rejection_rate,
            ),
            (
                "telemetry.vrf_thresholds.max_fallback_ratio",
                self.max_fallback_ratio,
            ),
        ] {
            if !(0.0..=1.0).contains(&value) {
                return Err(ChainError::Config(format!(
                    "{label} must be between 0.0 and 1.0"
                )));
            }
        }
        Ok(())
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

fn default_trace_max_queue_size() -> usize {
    2_048
}

fn default_trace_max_export_batch_size() -> usize {
    512
}

fn default_trace_sample_ratio() -> f64 {
    1.0
}

fn default_warn_on_drop() -> bool {
    true
}

fn validate_endpoint(label: &str, value: &str) -> ChainResult<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ChainError::Config(format!(
            "{label} must not be empty when configured",
        )));
    }

    let uri: Uri = trimmed
        .parse()
        .map_err(|_| ChainError::Config(format!("{label} must be a valid URI")))?;

    match uri.scheme_str() {
        Some("http") | Some("https") => {}
        Some(other) => {
            return Err(ChainError::Config(format!(
                "{label} must use http or https scheme, found {other}"
            )));
        }
        None => {
            return Err(ChainError::Config(format!(
                "{label} must include a URI scheme"
            )));
        }
    }

    if uri.host().is_none() {
        return Err(ChainError::Config(format!(
            "{label} must include a hostname"
        )));
    }

    Ok(())
}

fn validate_tls_config(label: &str, config: Option<&TelemetryTlsConfig>) -> ChainResult<()> {
    let Some(config) = config else {
        return Ok(());
    };

    if let Some(domain) = config.domain_name.as_ref() {
        if domain.trim().is_empty() {
            return Err(ChainError::Config(format!(
                "{label}.domain_name must not be empty"
            )));
        }
    }

    if config.client_certificate.is_some() ^ config.client_private_key.is_some() {
        return Err(ChainError::Config(format!(
            "{label} requires both client_certificate and client_private_key when mutual TLS is configured",
        )));
    }

    for (field, path) in [
        ("ca_certificate", config.ca_certificate.as_ref()),
        ("client_certificate", config.client_certificate.as_ref()),
        ("client_private_key", config.client_private_key.as_ref()),
    ] {
        if let Some(path) = path {
            if path.as_path().to_string_lossy().trim().is_empty() {
                return Err(ChainError::Config(format!(
                    "{label}.{field} must not be empty when provided",
                )));
            }
            if !path.exists() {
                return Err(ChainError::Config(format!(
                    "{label}.{field} path {} does not exist",
                    path.display()
                )));
            }
        }
    }

    Ok(())
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
