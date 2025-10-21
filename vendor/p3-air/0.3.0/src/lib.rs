#![cfg_attr(not(feature = "std"), no_std)]

/// Minimal placeholder implementation of the upstream `p3-air` crate.
///
/// The real Plonky3 backend is not yet integrated in this workspace, so the
/// consumer crates only require the dependency to exist for compilation. The
/// helper function exported here allows build scripts or integration tests to
/// assert that the vendored shim was linked correctly.
pub fn placeholder() -> &'static str {
    "p3-air"
}
