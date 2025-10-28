use std::env;

use rustc_version::{version_meta, Channel};

/// Enables the `nightly` cfg when the opt-in STWO prover features are built.
/// These builds require either a nightly toolchain or `RUSTC_BOOTSTRAP`.
fn main() {
    if env::var_os("CARGO_FEATURE_STWO")
        .or_else(|| env::var_os("CARGO_FEATURE_PROVER_STWO"))
        .is_none()
    {
        return;
    }

    println!("cargo:rerun-if-env-changed=RUSTC_BOOTSTRAP");

    let is_nightly = version_meta()
        .map(|meta| matches!(meta.channel, Channel::Nightly | Channel::Dev))
        .unwrap_or(false);
    let has_bootstrap = env::var_os("RUSTC_BOOTSTRAP").is_some();

    if is_nightly || has_bootstrap {
        println!("cargo:rustc-cfg=nightly");
    }
}
