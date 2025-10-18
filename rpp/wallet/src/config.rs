#![cfg(feature = "vendor_electrs")]

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::vendor::electrs::rpp_ledger::bitcoin::Network as LedgerNetwork;

/// Configuration options for the Electrs vendor integration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ElectrsConfig {
    /// Ledger network the wallet should track.
    pub network: NetworkSelection,
    /// Optional feature toggles that enable runtime-backed components.
    pub features: FeatureGates,
    /// Cache configuration for vendor integrations.
    pub cache: CacheConfig,
    /// Tracker-specific configuration options.
    pub tracker: TrackerConfig,
}

impl Default for ElectrsConfig {
    fn default() -> Self {
        Self {
            network: NetworkSelection::Regtest,
            features: FeatureGates::default(),
            cache: CacheConfig::default(),
            tracker: TrackerConfig::default(),
        }
    }
}

/// Supported runtime networks for the Electrs integration.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkSelection {
    Regtest,
    Testnet,
    Signet,
    Mainnet,
}

impl Default for NetworkSelection {
    fn default() -> Self {
        NetworkSelection::Regtest
    }
}

impl From<NetworkSelection> for LedgerNetwork {
    fn from(value: NetworkSelection) -> Self {
        match value {
            NetworkSelection::Regtest => LedgerNetwork::Regtest,
            NetworkSelection::Testnet => LedgerNetwork::Testnet,
            NetworkSelection::Signet => LedgerNetwork::Signet,
            NetworkSelection::Mainnet => LedgerNetwork::Bitcoin,
        }
    }
}

/// Optional feature toggles for vendor-backed components.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct FeatureGates {
    /// Attach runtime adapters to the Firewood integration.
    pub runtime: bool,
    /// Bring up the Electrs tracker backed by the runtime daemon.
    pub tracker: bool,
}

impl Default for FeatureGates {
    fn default() -> Self {
        Self {
            runtime: false,
            tracker: false,
        }
    }
}

/// Cache configuration influencing warmup and telemetry behaviour.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    /// Telemetry settings for cache statistics.
    pub telemetry: CacheTelemetryConfig,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            telemetry: CacheTelemetryConfig::default(),
        }
    }
}

/// Controls tracker-specific behaviour, including telemetry endpoints.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TrackerConfig {
    /// Socket address used when registering tracker telemetry metrics.
    pub telemetry_endpoint: SocketAddr,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            telemetry_endpoint: SocketAddr::from(([127, 0, 0, 1], 0)),
        }
    }
}

/// Controls how the cache reports telemetry and where it stores warmup data.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct CacheTelemetryConfig {
    /// Enable or disable telemetry collection for cache interactions.
    pub enabled: bool,
    /// Optional hex-encoded prefix used when persisting warmup entries.
    pub warmup_prefix: Option<String>,
}

impl Default for CacheTelemetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            warmup_prefix: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_target_regtest_without_features() {
        let config = ElectrsConfig::default();
        assert_eq!(config.network, NetworkSelection::Regtest);
        assert!(!config.features.runtime);
        assert!(!config.features.tracker);
        assert!(!config.cache.telemetry.enabled);
        assert!(config.cache.telemetry.warmup_prefix.is_none());
        assert_eq!(
            config.tracker.telemetry_endpoint,
            SocketAddr::from(([127, 0, 0, 1], 0))
        );
    }

    #[test]
    fn serde_roundtrip_preserves_network_and_features() {
        let config = ElectrsConfig {
            network: NetworkSelection::Signet,
            features: FeatureGates {
                runtime: true,
                tracker: false,
            },
            cache: CacheConfig {
                telemetry: CacheTelemetryConfig {
                    enabled: true,
                    warmup_prefix: Some("cafebabe".into()),
                },
            },
            tracker: TrackerConfig {
                telemetry_endpoint: SocketAddr::from(([10, 0, 0, 42], 9000)),
            },
        };

        let json = serde_json::to_string(&config).expect("serialize");
        let restored: ElectrsConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(restored.network, NetworkSelection::Signet);
        assert!(restored.features.runtime);
        assert!(!restored.features.tracker);
        assert!(restored.cache.telemetry.enabled);
        assert_eq!(
            restored.cache.telemetry.warmup_prefix,
            Some("cafebabe".into())
        );
        assert_eq!(
            restored.tracker.telemetry_endpoint,
            SocketAddr::from(([10, 0, 0, 42], 9000))
        );
    }
}
