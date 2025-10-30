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
#[cfg(all(feature = "prover-stwo", feature = "prover-mock"))]
compile_error!("features `prover-stwo` and `prover-mock` are mutually exclusive");

pub use prover_backend_interface as proof_backend;

#[cfg(feature = "prover-stwo")]
pub use prover_stwo_backend as stwo;

#[cfg(not(feature = "prover-stwo"))]
#[path = "../../rpp/chain/src/stwo_stub.rs"]
pub mod stwo;

#[cfg(feature = "vendor_electrs")]
pub mod config;

/// Zugriff auf optionale Drittanbieter-Integrationen.
pub mod vendor;

/// Command-line helpers for wallet subsystems.
pub mod cli;

/// JSON-RPC facades exposed by the wallet runtime.
pub mod rpc;

/// Zero Sync identity lifecycle helpers.
pub mod zsi;

/// Wallet-facing proof helpers.
pub mod proofs;
