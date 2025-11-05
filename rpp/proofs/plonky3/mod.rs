//! Plonky3 backend integration scaffolding.
//!
//! This module mirrors the STWO hierarchy so the rest of the codebase can
//! compile against a unified prover/verifier abstraction while the concrete
//! Plonky3 logic is implemented incrementally.

pub mod aggregation;
pub mod circuit;
pub mod crypto;
pub mod params;
pub mod proof;
pub mod prover;
pub mod public_inputs;
pub mod verifier;

#[cfg(test)]
mod tests;
