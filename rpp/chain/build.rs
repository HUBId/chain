use std::env;

use rustc_version::{version_meta, Channel};

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC_BOOTSTRAP");

    let is_nightly = version_meta()
        .map(|meta| matches!(meta.channel, Channel::Nightly | Channel::Dev))
        .unwrap_or(false);
    let has_bootstrap = env::var_os("RUSTC_BOOTSTRAP").is_some();

    if is_nightly || has_bootstrap {
        println!("cargo:rustc-cfg=nightly");
    }
}
