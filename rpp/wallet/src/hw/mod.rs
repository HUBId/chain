//! Hardware signer abstractions exposed by the wallet.
//!
//! The module is gated behind the `wallet_hw` Cargo feature so downstream
//! integrations can opt-in without pulling the extra trait surface into
//! builds that do not target hardware devices.

pub mod traits;

pub use traits::*;

#[cfg(any(test, feature = "wallet_hw"))]
pub mod mock;

#[cfg(any(test, feature = "wallet_hw"))]
pub use mock::MockHardwareSigner;
