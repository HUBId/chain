//! Wallet facade that interacts with the prover backend for signing flows.
//!
//! # STWO feature toggles
//! * `prover-stwo` activates the STWO backend with the scalar execution path (requires Rust nightly).
//! * `prover-stwo-simd` builds on top of `prover-stwo` and enables the optional
//!   SIMD acceleration in the STWO fork. Use it on hosts with supported
//!   instruction sets and keep it disabled otherwise for maximum portability.
//! * `prover-mock` routes wallet operations through the mock backend for pure
//!   testing environments.
//!
//! Switching among these features happens via Cargo's feature flags; no code
//! samples or configuration edits are necessary.
rustversion::not_nightly! {
    #[cfg(feature = "prover-stwo")]
    compile_error!(
        "STWO Prover requires Rust nightly (portable_simd / array_chunks etc.). Build without these features or use Nightly."
    );
}

#[cfg(all(feature = "prover-stwo", feature = "prover-mock"))]
compile_error!("features `prover-stwo` and `prover-mock` are mutually exclusive");

pub use prover_backend_interface as proof_backend;
