//! Node entry point that wires the prover backends into the networking stack.
//!
//! # STWO feature toggles
//! * `prover-stwo` enables the STWO backend (default).
//! * `prover-stwo-simd` extends `prover-stwo` and turns on the optional SIMD
//!   acceleration exposed by the STWO fork. Activate it when the target
//!   architecture supports the vector instructions; leave it disabled to stay on
//!   the portable scalar implementation.
//! * `prover-mock` swaps in the mock backend for tests and environments without
//!   a prover.
//!
//! Switching between these options is handled entirely through Cargo features;
//! no code changes or configuration files are required.
#[cfg(all(feature = "prover-stwo", feature = "prover-mock"))]
compile_error!("features `prover-stwo` and `prover-mock` are mutually exclusive");

pub use rpp_chain;
pub use rpp_chain::proof_backend;

#[cfg(feature = "prover-stwo")]
pub use rpp_chain::stwo;
