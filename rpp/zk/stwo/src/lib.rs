//! Local STWO proving system fork used by the RPP repository.
//!
//! This crate provides a lightweight, self-contained implementation of the
//! interfaces required by the chain node.  The implementation focuses on
//! determinism and debuggability rather than cryptographic performance.  It
//! offers simple, pure-Rust stand-ins for the original StarkWare components so
//! that tests and local development can run without external dependencies.

pub mod circuits;
pub mod core;
pub mod params;
pub mod prover;
pub mod recursion;
pub mod utils;
pub mod verifier;

pub use prover::{prove_block, prove_identity, prove_reputation, prove_tx, Proof, ProofFormat};
pub use recursion::{link_proofs, RecursiveProof};
pub use verifier::{
    verify_block, verify_identity, verify_reputation, verify_tx, VerificationError,
    VerificationResult,
};

#[cfg(feature = "official")]
pub use stwo_official;
