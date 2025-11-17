use rustc_version::{version_meta, Channel};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(nightly)");
    let bootstrap_enabled = std::env::var("RUSTC_BOOTSTRAP")
        .map(|value| value != "0" && !value.is_empty())
        .unwrap_or(false);

    let nightly_toolchain = version_meta()
        .map(|meta| matches!(meta.channel, Channel::Nightly | Channel::Dev))
        .unwrap_or(false);

    if bootstrap_enabled || nightly_toolchain {
        println!("cargo:rustc-cfg=nightly");
    }
}
