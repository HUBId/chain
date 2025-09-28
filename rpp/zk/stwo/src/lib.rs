//! Local STWO proving system fork used by the RPP repository.
//!
//! This crate provides a lightweight, self-contained implementation of the
//! interfaces required by the chain node.  The implementation focuses on
//! determinism and debuggability rather than cryptographic performance.  It
//! offers simple, pure-Rust stand-ins for the original StarkWare components so
//! that tests and local development can run without external dependencies.

#[cfg(any(test, feature = "scaffold"))]
pub mod circuits;
pub mod core;
pub mod params;
pub mod utils;

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
