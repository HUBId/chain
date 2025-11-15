//! Command-line helpers for wallet subsystems.

pub mod telemetry;
pub mod wallet;

#[cfg(feature = "wallet_zsi")]
pub mod zsi;

#[cfg(not(feature = "wallet_zsi"))]
#[path = "zsi_stub.rs"]
pub mod zsi;
