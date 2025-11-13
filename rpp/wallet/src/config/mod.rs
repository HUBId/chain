pub mod wallet;

#[cfg(feature = "vendor_electrs")]
pub mod electrs;

pub use wallet::{
    PolicyTierHooks, WalletConfig, WalletEngineConfig, WalletFeeConfig, WalletPolicyConfig,
    WalletProverConfig,
};

#[cfg(feature = "vendor_electrs")]
pub use electrs::ElectrsConfig;
