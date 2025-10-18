#![cfg(feature = "vendor_electrs")]

use serde::{Deserialize, Serialize};

use crate::vendor::electrs::rpp_ledger::bitcoin::Network as LedgerNetwork;

/// Configuration options for the Electrs vendor integration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ElectrsConfig {
    /// Ledger network the wallet should track.
    pub network: NetworkSelection,
    /// Optional feature toggles that enable runtime-backed components.
    pub features: FeatureGates,
}

impl Default for ElectrsConfig {
    fn default() -> Self {
        Self {
            network: NetworkSelection::Regtest,
            features: FeatureGates::default(),
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
