pub mod wallet;

#[cfg(feature = "vendor_electrs")]
pub mod electrs;

pub use wallet::{
    PolicyTierHooks, WalletConfig, WalletEngineConfig, WalletFeeConfig, WalletGuiConfig,
    WalletGuiTheme, WalletHwConfig, WalletHwTransport, WalletMultisigConfig, WalletPolicyConfig,
    WalletProverConfig, WalletTelemetryConfig,
};

#[cfg(feature = "vendor_electrs")]
pub use electrs::ElectrsConfig;
