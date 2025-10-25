//! STWO/STARK integration module hierarchy.

pub mod aggregation;
pub mod ffi;
pub mod prover;

#[cfg(feature = "prover-stwo")]
pub use stwo::official::{
    air, circuit, conversions, fri, official_adapter, params, proof, verifier,
};

#[cfg(not(feature = "prover-stwo"))]
pub use crate::stwo::{
    air, circuit, conversions, fri, official_adapter, params, proof, verifier,
};

#[cfg(test)]
mod tests;
