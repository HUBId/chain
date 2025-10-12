//! Example AIR definitions used in documentation and tutorials.

pub mod lfsr;

pub use self::lfsr::{
    Air as LfsrAir, PublicInputs as LfsrPublicInputs, TraceBuilder as LfsrTraceBuilder,
};
