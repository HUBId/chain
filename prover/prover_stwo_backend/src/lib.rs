//! Local STWO proving system fork used by the RPP repository.
//!
//! This crate provides a lightweight, self-contained implementation of the
//! interfaces required by the chain node.  The implementation focuses on
//! determinism and debuggability rather than cryptographic performance.  It
//! offers simple, pure-Rust stand-ins for the original StarkWare components so
//! that tests and local development can run without external dependencies.
//!
//! # Toolchain and feature flags
//! * The crate is tested against the nightly toolchain pinned via the workspace
//!   `rust-toolchain.toml`. Consumers inherit this configuration automatically
//!   and do not need to manage toolchain overrides manually.
//! * `prover-stwo` pulls in the official STWO implementation bundled with this
//!   repository and unlocks all production circuits (identity, transaction,
//!   state, pruning, recursive, uptime, and consensus).
//! * `prover-stwo-simd` extends `prover-stwo` and enables the upstream
//!   `parallel` feature, activating the SIMD-accelerated execution path when the
//!   target CPU supports the required intrinsics.
//! * `prover-mock` remains available for parity with the rest of the workspace
//!   but does not affect this crate directly.
//!
//! Downstream crates select the desired proving surface area by enabling either
//! `prover-stwo` (scalar) or `prover-stwo-simd` (SIMD) on their dependency
//! declarations. No additional glue code or environment tweaks are necessary.

#[cfg(all(
    not(nightly),
    any(feature = "prover-stwo", feature = "prover-stwo-simd")
))]
compile_error!(
    "STWO Prover requires Rust nightly (portable_simd / array_chunks etc.). \
Build without these features or use Nightly."
);

pub mod backend;
#[cfg(any(test, feature = "scaffold"))]
pub mod circuits;
pub mod core;
pub mod errors;
pub mod identity_tree;
#[cfg(feature = "official")]
pub mod official;
pub mod params;
pub mod proof_system;
pub mod reputation;
pub mod state;
pub mod types;
pub mod utils;
pub mod vrf;

pub use core::vcs::blake2_hash::{Blake2sHash, Blake2sHasher};
pub use params::{FieldElement, StwoConfig};
pub use prover_backend_interface as proof_backend;
pub use utils::fri::{compress_proof, FriProof, FriProver, FriQuery};
pub use utils::merkle::merkle_root;
pub use utils::poseidon::hash_elements as poseidon_hash;

#[cfg(any(test, feature = "scaffold"))]
pub mod prover;
#[cfg(any(test, feature = "scaffold"))]
pub mod recursion;
#[cfg(any(test, feature = "scaffold"))]
pub mod verifier;

#[cfg(any(test, feature = "scaffold"))]
pub use prover::{prove_block, prove_identity, prove_reputation, prove_tx, Proof, ProofFormat};
#[cfg(any(test, feature = "scaffold"))]
pub use recursion::{link_proofs, RecursiveProof};
#[cfg(any(test, feature = "scaffold"))]
pub use verifier::{
    verify_block, verify_identity, verify_reputation, verify_tx, VerificationError,
    VerificationResult,
};

#[cfg(feature = "official")]
pub use stwo_official;
