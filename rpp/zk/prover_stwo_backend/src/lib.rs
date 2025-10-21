//! Local STWO proving system fork used by the RPP repository.
//!
//! This crate provides a lightweight, self-contained implementation of the
//! interfaces required by the chain node.  The implementation focuses on
//! determinism and debuggability rather than cryptographic performance.  It
//! offers simple, pure-Rust stand-ins for the original StarkWare components so
//! that tests and local development can run without external dependencies.
//!
//! # Feature flags
//! * `prover-stwo` pulls in the official STWO implementation bundled with this
//!   repository.
//! * `simd` builds on top of `prover-stwo` and enables the upstream
//!   `parallel` feature, allowing the SIMD-accelerated execution path when the
//!   host CPU supports it.
//! * `prover-mock` remains available for parity with the rest of the workspace
//!   but does not affect this crate directly.
//!
//! Switching between the scalar and SIMD implementations only involves toggling
//! these Cargo features; no code snippets or environment configuration are
//! necessary.

#[cfg(all(feature = "prover-stwo", feature = "prover-mock"))]
compile_error!("features `prover-stwo` and `prover-mock` are mutually exclusive");

pub mod backend;
pub mod errors;
#[cfg(any(test, feature = "scaffold"))]
pub mod circuits;
pub mod core;
pub mod proof_system;
#[cfg(feature = "official")]
pub mod official;
pub mod params;
pub mod reputation;
pub mod state;
pub mod types;
pub mod utils;

pub use prover_backend_interface as proof_backend;
pub use core::vcs::blake2_hash::{Blake2sHash, Blake2sHasher};
pub use params::{FieldElement, StwoConfig};
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
