use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const DEFAULT_GAP_LIMIT: u32 = 20;
const DEFAULT_MIN_CONFIRMATIONS: u32 = 1;
const DEFAULT_MIN_FEE_RATE: u64 = 1;
const DEFAULT_MAX_FEE_RATE: u64 = 200;
const DEFAULT_FEE_RATE: u64 = 5;
const DEFAULT_DUST_LIMIT: u128 = 546;
const DEFAULT_MAX_CHANGE_OUTPUTS: u32 = 1;
const DEFAULT_PENDING_LOCK_TIMEOUT_SECS: u64 = 600;
const DEFAULT_FEE_TARGET_CONFIRMATIONS: u16 = 3;
const DEFAULT_HEURISTIC_MIN_FEE_RATE: u64 = 2;
const DEFAULT_HEURISTIC_MAX_FEE_RATE: u64 = 100;
const DEFAULT_FEE_CACHE_TTL_SECS: u64 = 30;
const DEFAULT_PROVER_JOB_TIMEOUT_SECS: u64 = 300;
const DEFAULT_PROVER_MAX_WITNESS_BYTES: u64 = 16 * 1024 * 1024;
const DEFAULT_PROVER_MAX_CONCURRENCY: u32 = 1;
const DEFAULT_GUI_POLL_INTERVAL_MS: u64 = 5_000;
const MIN_GUI_POLL_INTERVAL_MS: u64 = 1_000;
const DEFAULT_GUI_MAX_HISTORY_ROWS: u32 = 20;
const MIN_GUI_MAX_HISTORY_ROWS: u32 = 5;

/// High-level wallet configuration exposed to runtime services.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletConfig {
    pub engine: WalletEngineConfig,
    pub policy: WalletPolicyConfig,
    pub fees: WalletFeeConfig,
    pub prover: WalletProverConfig,
    pub zsi: WalletZsiConfig,
    pub gui: WalletGuiConfig,
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            engine: WalletEngineConfig::default(),
            policy: WalletPolicyConfig::default(),
            fees: WalletFeeConfig::default(),
            prover: WalletProverConfig::default(),
            zsi: WalletZsiConfig::default(),
            gui: WalletGuiConfig::default(),
        }
    }
}

/// Configure storage paths and lifecycle metadata for the wallet engine.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletEngineConfig {
    /// Directory where the wallet stores state and cache data.
    pub data_dir: PathBuf,
    /// Path to the persisted keystore bundle used by the wallet engine.
    pub keystore_path: PathBuf,
    /// Directory storing encrypted wallet backup archives.
    pub backup_path: PathBuf,
    /// Optional birthday height used when bootstrapping from checkpoints.
    pub birthday_height: Option<u64>,
}

impl Default for WalletEngineConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data/wallet"),
            keystore_path: PathBuf::from("./data/wallet/keystore.toml"),
            backup_path: PathBuf::from("./data/wallet/backups"),
            birthday_height: None,
        }
    }
}

/// Spending policy constraints enforced by the wallet engine.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletPolicyConfig {
    /// Maximum number of unused external addresses tracked by the wallet.
    pub external_gap_limit: u32,
    /// Maximum number of unused change addresses tracked by the wallet.
    pub internal_gap_limit: u32,
    /// Minimum confirmations required before funds become spendable.
    pub min_confirmations: u32,
    /// Threshold below which outputs are considered dust and rejected.
    pub dust_limit: u128,
    /// Cap the number of change outputs emitted by a transaction.
    pub max_change_outputs: u32,
    /// Optional daily spend limit enforced before draft creation succeeds.
    pub spend_limit_daily: Option<u128>,
    /// Timeout (in seconds) after which pending input locks may be released.
    pub pending_lock_timeout: u64,
    /// Hooks coordinating tier-aware policy integrations.
    pub tier: PolicyTierHooks,
}

impl Default for WalletPolicyConfig {
    fn default() -> Self {
        Self {
            external_gap_limit: DEFAULT_GAP_LIMIT,
            internal_gap_limit: DEFAULT_GAP_LIMIT,
            min_confirmations: DEFAULT_MIN_CONFIRMATIONS,
            dust_limit: DEFAULT_DUST_LIMIT,
            max_change_outputs: DEFAULT_MAX_CHANGE_OUTPUTS,
            spend_limit_daily: None,
            pending_lock_timeout: DEFAULT_PENDING_LOCK_TIMEOUT_SECS,
            tier: PolicyTierHooks::default(),
        }
    }
}

/// Control tier-aware runtime integrations for wallet policies.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PolicyTierHooks {
    /// Enable tier integration checks for spending policies.
    pub enabled: bool,
    /// Optional named hook surfaced to clients for bespoke integrations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
}

impl Default for PolicyTierHooks {
    fn default() -> Self {
        Self {
            enabled: false,
            hook: None,
        }
    }
}

/// Fee rate guidance exposed to RPC consumers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletFeeConfig {
    /// Default fee rate applied when callers omit an explicit value.
    pub default_sats_per_vbyte: u64,
    /// Lowest allowed fee rate for submitted transactions.
    pub min_sats_per_vbyte: u64,
    /// Highest allowed fee rate for submitted transactions.
    pub max_sats_per_vbyte: u64,
    /// Preferred confirmation target used when sampling node statistics.
    pub target_confirmations: u16,
    /// Lower bound applied to node-derived heuristic estimates.
    pub heuristic_min_sats_per_vbyte: u64,
    /// Upper bound applied to node-derived heuristic estimates.
    pub heuristic_max_sats_per_vbyte: u64,
    /// Duration (in seconds) to cache node-derived estimates before refreshing.
    pub cache_ttl_secs: u64,
}

impl Default for WalletFeeConfig {
    fn default() -> Self {
        Self {
            default_sats_per_vbyte: DEFAULT_FEE_RATE,
            min_sats_per_vbyte: DEFAULT_MIN_FEE_RATE,
            max_sats_per_vbyte: DEFAULT_MAX_FEE_RATE,
            target_confirmations: DEFAULT_FEE_TARGET_CONFIRMATIONS,
            heuristic_min_sats_per_vbyte: DEFAULT_HEURISTIC_MIN_FEE_RATE,
            heuristic_max_sats_per_vbyte: DEFAULT_HEURISTIC_MAX_FEE_RATE,
            cache_ttl_secs: DEFAULT_FEE_CACHE_TTL_SECS,
        }
    }
}

/// Controls prover integration toggles for the wallet runtime.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletProverConfig {
    /// Enable prover-backed flows for transaction authoring.
    pub enabled: bool,
    /// Allow falling back to the mock prover backend when available.
    pub mock_fallback: bool,
    /// Timeout (in seconds) applied to prover jobs before they are aborted.
    pub job_timeout_secs: u64,
    /// Maximum witness size (in bytes) accepted from prover backends.
    pub max_witness_bytes: u64,
    /// Upper bound on concurrent prover jobs executed by the runtime.
    pub max_concurrency: u32,
}

impl Default for WalletProverConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mock_fallback: true,
            job_timeout_secs: DEFAULT_PROVER_JOB_TIMEOUT_SECS,
            max_witness_bytes: DEFAULT_PROVER_MAX_WITNESS_BYTES,
            max_concurrency: DEFAULT_PROVER_MAX_CONCURRENCY,
        }
    }
}

/// Toggle Zero Sync identity workflows exposed by the wallet.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletZsiConfig {
    /// Enable the wallet ZSI helpers and JSON-RPC surface.
    pub enabled: bool,
    /// Optional backend identifier recorded for telemetry purposes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
}

impl Default for WalletZsiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: None,
        }
    }
}

/// Configure GUI-specific behaviour for the wallet desktop application.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WalletGuiConfig {
    /// Interval (in milliseconds) between sync status polls.
    pub poll_interval_ms: u64,
    /// Maximum number of history entries fetched per page.
    pub max_history_rows: u32,
    /// Preferred visual theme surfaced to the GUI.
    pub theme: WalletGuiTheme,
    /// Require clipboard confirmation before copying sensitive data.
    pub confirm_clipboard: bool,
    /// Opt-in flag for telemetry collection from the GUI.
    pub telemetry_opt_in: bool,
}

impl WalletGuiConfig {
    /// Returns a sanitized copy that clamps out-of-range values.
    pub fn sanitized(mut self) -> Self {
        if self.poll_interval_ms < MIN_GUI_POLL_INTERVAL_MS {
            self.poll_interval_ms = MIN_GUI_POLL_INTERVAL_MS;
        }
        if self.max_history_rows < MIN_GUI_MAX_HISTORY_ROWS {
            self.max_history_rows = DEFAULT_GUI_MAX_HISTORY_ROWS;
        }
        self
    }
}

impl Default for WalletGuiConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: DEFAULT_GUI_POLL_INTERVAL_MS,
            max_history_rows: DEFAULT_GUI_MAX_HISTORY_ROWS,
            theme: WalletGuiTheme::System,
            confirm_clipboard: true,
            telemetry_opt_in: false,
        }
    }
}

/// Appearance theme options exposed to the GUI.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_defaults_match_expected_ranges() {
        let config = WalletConfig::default();
        assert_eq!(config.engine.data_dir, PathBuf::from("./data/wallet"));
        assert_eq!(
            config.engine.keystore_path,
            PathBuf::from("./data/wallet/keystore.toml")
        );
        assert!(config.engine.birthday_height.is_none());
        assert_eq!(config.policy.external_gap_limit, DEFAULT_GAP_LIMIT);
        assert_eq!(config.policy.internal_gap_limit, DEFAULT_GAP_LIMIT);
        assert_eq!(config.policy.min_confirmations, DEFAULT_MIN_CONFIRMATIONS);
        assert_eq!(config.policy.dust_limit, DEFAULT_DUST_LIMIT);
        assert_eq!(config.policy.max_change_outputs, DEFAULT_MAX_CHANGE_OUTPUTS);
        assert!(config.policy.spend_limit_daily.is_none());
        assert_eq!(
            config.policy.pending_lock_timeout,
            DEFAULT_PENDING_LOCK_TIMEOUT_SECS
        );
        assert!(!config.policy.tier.enabled);
        assert!(config.policy.tier.hook.is_none());
        assert_eq!(config.fees.default_sats_per_vbyte, DEFAULT_FEE_RATE);
        assert_eq!(config.fees.min_sats_per_vbyte, DEFAULT_MIN_FEE_RATE);
        assert_eq!(config.fees.max_sats_per_vbyte, DEFAULT_MAX_FEE_RATE);
        assert_eq!(
            config.fees.target_confirmations,
            DEFAULT_FEE_TARGET_CONFIRMATIONS
        );
        assert_eq!(
            config.fees.heuristic_min_sats_per_vbyte,
            DEFAULT_HEURISTIC_MIN_FEE_RATE
        );
        assert_eq!(
            config.fees.heuristic_max_sats_per_vbyte,
            DEFAULT_HEURISTIC_MAX_FEE_RATE
        );
        assert_eq!(config.fees.cache_ttl_secs, DEFAULT_FEE_CACHE_TTL_SECS);
        assert!(!config.prover.enabled);
        assert!(config.prover.mock_fallback);
        assert_eq!(
            config.prover.job_timeout_secs,
            DEFAULT_PROVER_JOB_TIMEOUT_SECS
        );
        assert_eq!(
            config.prover.max_witness_bytes,
            DEFAULT_PROVER_MAX_WITNESS_BYTES
        );
        assert_eq!(
            config.prover.max_concurrency,
            DEFAULT_PROVER_MAX_CONCURRENCY
        );
        assert!(!config.zsi.enabled);
        assert!(config.zsi.backend.is_none());
        assert_eq!(config.gui.poll_interval_ms, DEFAULT_GUI_POLL_INTERVAL_MS);
        assert_eq!(config.gui.max_history_rows, DEFAULT_GUI_MAX_HISTORY_ROWS);
        assert_eq!(config.gui.theme, WalletGuiTheme::System);
        assert!(config.gui.confirm_clipboard);
        assert!(!config.gui.telemetry_opt_in);
    }

    #[test]
    fn serde_roundtrip_preserves_nested_configuration() {
        let config = WalletConfig {
            engine: WalletEngineConfig {
                data_dir: PathBuf::from("./custom"),
                keystore_path: PathBuf::from("./custom/keys.toml"),
                birthday_height: Some(42),
            },
            policy: WalletPolicyConfig {
                external_gap_limit: 32,
                internal_gap_limit: 16,
                min_confirmations: 12,
                dust_limit: 2_000,
                max_change_outputs: 4,
                spend_limit_daily: Some(50_000),
                pending_lock_timeout: 900,
                tier: PolicyTierHooks {
                    enabled: true,
                    hook: Some("tier:tl2".to_string()),
                },
            },
            fees: WalletFeeConfig {
                default_sats_per_vbyte: 11,
                min_sats_per_vbyte: 5,
                max_sats_per_vbyte: 250,
                target_confirmations: 4,
                heuristic_min_sats_per_vbyte: 3,
                heuristic_max_sats_per_vbyte: 300,
                cache_ttl_secs: 90,
            },
            prover: WalletProverConfig {
                enabled: true,
                mock_fallback: false,
                job_timeout_secs: 420,
                max_witness_bytes: 8 * 1024 * 1024,
                max_concurrency: 4,
            },
            zsi: WalletZsiConfig {
                enabled: true,
                backend: Some("stwo".into()),
            },
            gui: WalletGuiConfig {
                poll_interval_ms: 2_000,
                max_history_rows: 48,
                theme: WalletGuiTheme::Dark,
                confirm_clipboard: false,
                telemetry_opt_in: true,
            },
        };

        let serialized = toml::to_string(&config).expect("serialize");
        let restored: WalletConfig = toml::from_str(&serialized).expect("deserialize");

        assert_eq!(restored.engine.data_dir, PathBuf::from("./custom"));
        assert_eq!(
            restored.engine.keystore_path,
            PathBuf::from("./custom/keys.toml")
        );
        assert_eq!(restored.engine.birthday_height, Some(42));
        assert_eq!(restored.policy.external_gap_limit, 32);
        assert_eq!(restored.policy.internal_gap_limit, 16);
        assert_eq!(restored.policy.min_confirmations, 12);
        assert_eq!(restored.policy.dust_limit, 2_000);
        assert_eq!(restored.policy.max_change_outputs, 4);
        assert_eq!(restored.policy.spend_limit_daily, Some(50_000));
        assert_eq!(restored.policy.pending_lock_timeout, 900);
        assert!(restored.policy.tier.enabled);
        assert_eq!(restored.policy.tier.hook.as_deref(), Some("tier:tl2"));
        assert_eq!(restored.fees.default_sats_per_vbyte, 11);
        assert_eq!(restored.fees.min_sats_per_vbyte, 5);
        assert_eq!(restored.fees.max_sats_per_vbyte, 250);
        assert_eq!(restored.fees.target_confirmations, 4);
        assert_eq!(restored.fees.heuristic_min_sats_per_vbyte, 3);
        assert_eq!(restored.fees.heuristic_max_sats_per_vbyte, 300);
        assert_eq!(restored.fees.cache_ttl_secs, 90);
        assert!(restored.prover.enabled);
        assert!(!restored.prover.mock_fallback);
        assert_eq!(restored.prover.job_timeout_secs, 420);
        assert_eq!(restored.prover.max_witness_bytes, 8 * 1024 * 1024);
        assert_eq!(restored.prover.max_concurrency, 4);
        assert!(restored.zsi.enabled);
        assert_eq!(restored.zsi.backend.as_deref(), Some("stwo"));
        assert_eq!(restored.gui.poll_interval_ms, 2_000);
        assert_eq!(restored.gui.max_history_rows, 48);
        assert_eq!(restored.gui.theme, WalletGuiTheme::Dark);
        assert!(!restored.gui.confirm_clipboard);
        assert!(restored.gui.telemetry_opt_in);
    }

    #[test]
    fn gui_section_defaults_when_absent() {
        let contents = r#"
            [wallet.policy]
            external_gap_limit = 32

            [wallet.prover]
            enabled = true
        "#;

        let mut config: WalletConfig = toml::from_str(contents).expect("deserialize");
        config.gui = config.gui.sanitized();

        assert_eq!(config.gui.poll_interval_ms, DEFAULT_GUI_POLL_INTERVAL_MS);
        assert_eq!(config.gui.max_history_rows, DEFAULT_GUI_MAX_HISTORY_ROWS);
        assert_eq!(config.gui.theme, WalletGuiTheme::System);
        assert!(config.gui.confirm_clipboard);
        assert!(!config.gui.telemetry_opt_in);
    }

    #[test]
    fn gui_sanitization_clamps_out_of_range_values() {
        let config = WalletGuiConfig {
            poll_interval_ms: 250,
            max_history_rows: 0,
            theme: WalletGuiTheme::Light,
            confirm_clipboard: false,
            telemetry_opt_in: false,
        }
        .sanitized();

        assert_eq!(config.poll_interval_ms, MIN_GUI_POLL_INTERVAL_MS);
        assert_eq!(config.max_history_rows, DEFAULT_GUI_MAX_HISTORY_ROWS);
        assert_eq!(config.theme, WalletGuiTheme::Light);
        assert!(!config.confirm_clipboard);
        assert!(!config.telemetry_opt_in);
    }
}
