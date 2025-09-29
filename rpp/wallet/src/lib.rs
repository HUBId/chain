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
#[cfg(all(feature = "prover-stwo", feature = "prover-mock"))]
compile_error!("features `prover-stwo` and `prover-mock` are mutually exclusive");

pub use prover_backend_interface as proof_backend;
