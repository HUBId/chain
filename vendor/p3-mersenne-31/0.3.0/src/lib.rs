#![cfg_attr(not(feature = "std"), no_std)]

/// Minimal placeholder for the vendored Plonky3 crate.
pub fn placeholder() -> &'static str {
    env!("CARGO_PKG_NAME")
}
