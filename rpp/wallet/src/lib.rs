//! Wallet facade that interacts with the prover backend for signing flows.
//!
//! # STWO feature toggles
//! * `prover-stwo` activates the STWO backend with the scalar execution path.
//! * `prover-stwo-simd` builds on top of `prover-stwo` and enables the optional
//!   SIMD acceleration in the STWO fork. Use it on hosts with supported
//!   instruction sets and keep it disabled otherwise for maximum portability.
//! * `prover-mock` routes wallet operations through the mock backend for pure
//!   testing environments.
//!
//! Switching among these features happens via Cargo's feature flags; no code
//! samples or configuration edits are necessary.
//!
//! # Runtime-backed tracker integration
//! * `vendor_electrs` pulls in the vendored Electrs modules together with the
//!   runtime adapters (`storage-firewood`, `rpp::runtime::node`,
//!   `rpp::runtime::orchestration`) that the tracker uses to mirror the node
//!   state. Enable this flag when testing the wallet against a live runtime or
//!   the Firewood-backed daemon harness.
pub use prover_backend_interface as proof_backend;

#[cfg(feature = "prover-stwo")]
pub use prover_stwo_backend as stwo;

#[cfg(not(feature = "prover-stwo"))]
#[path = "stwo_stub.rs"]
pub mod stwo;

pub mod config;

/// Zugriff auf optionale Drittanbieter-Integrationen.
pub mod vendor;

/// Wallet backup and restore helpers.
pub mod backup;

/// Persistent wallet state stored in Firewood.
pub mod db;

/// Wallet telemetry helpers.
pub mod telemetry;

/// Crash reporting hooks and spool helpers.
pub mod crash_reporting;

/// User-facing message catalog loader.
pub mod messages;

/// Wallet runtime operating modes (e.g. watch-only).
pub mod modes;

/// Command-line helpers for wallet subsystems.
pub mod cli;

/// JSON-RPC facades exposed by the wallet runtime.
pub mod rpc;

/// Multisig configuration and registry helpers.
#[cfg(feature = "wallet_multisig_hooks")]
pub mod multisig;
#[cfg(not(feature = "wallet_multisig_hooks"))]
#[path = "multisig_stub.rs"]
pub mod multisig;

/// Runtime integration shims and stubs.
pub mod runtime;

/// Hardware wallet integration traits.
#[cfg(any(test, feature = "wallet_hw"))]
pub mod hw;

#[cfg(feature = "wallet_gui")]
pub mod ui;

/// Indexer client abstractions and helpers.
pub mod indexer;

/// Zero Sync identity lifecycle helpers.
#[cfg(feature = "wallet_zsi")]
pub mod zsi;
#[cfg(not(feature = "wallet_zsi"))]
#[path = "zsi_stub.rs"]
pub mod zsi;

/// Wallet-facing proof helpers.
pub mod proofs;

/// Core wallet engine primitives.
pub mod engine;

/// Abstractions over execution node connectivity.
pub mod node_client;

/// High-level wallet facade consumed by the runtime.
pub mod wallet;

pub use engine::{
    DerivationPath, DraftBundle, DraftInput, DraftOutput, DraftTransaction, SpendModel,
    WalletBalance, WalletEngine,
};
pub use node_client::*;

pub use rpp_wallet_interface::{
    node_client::*, rpc::*, telemetry::*, workflows::*, Address, AssetType,
    Result as WalletInterfaceResult, SendPreview, Tier, TransactionProofBundle, UtxoOutpoint,
    UtxoRecord, WalletInterfaceError,
};

pub(crate) use rpp_wallet_interface::node_client as interface_node_client;
pub(crate) use rpp_wallet_interface::rpc as interface_rpc;
pub(crate) use rpp_wallet_interface::telemetry as interface_telemetry;
pub(crate) use rpp_wallet_interface::workflows as interface_workflows;

#[cfg(any(test, feature = "test-fixtures"))]
pub mod tests;
