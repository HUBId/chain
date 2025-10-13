//! Node entry point that wires the prover backends into the networking stack.
//!
//! # STWO feature toggles
//! * `prover-stwo` enables the STWO backend (nightly-only).
//! * `prover-stwo-simd` extends `prover-stwo` and turns on the optional SIMD
//!   acceleration exposed by the STWO fork. Activate it when the target
//!   architecture supports the vector instructions; leave it disabled to stay on
//!   the portable scalar implementation.
//! * `prover-mock` swaps in the mock backend for tests and environments without
//!   a prover.
//!
//! Switching between these options is handled entirely through Cargo features;
//! no code changes or configuration files are required.
rustversion::not_nightly! {
    #[cfg(feature = "prover-stwo")]
    compile_error!(
        "STWO Prover requires Rust nightly (portable_simd / array_chunks etc.). Build without these features or use Nightly."
    );
}

#[cfg(all(feature = "prover-stwo", feature = "prover-mock"))]
compile_error!("features `prover-stwo` and `prover-mock` are mutually exclusive");

pub use prover_backend_interface as proof_backend;
pub mod validation;
