use std::env;
use std::process::Command;

fn main() {
    let prover_stwo_enabled = env::var("CARGO_FEATURE_PROVER_STWO").is_ok();
    if !prover_stwo_enabled {
        return;
    }

    if is_nightly_toolchain() {
        return;
    }

    panic!(
        "STWO Prover requires Rust nightly (portable_simd / array_chunks etc.). Build without these features or use Nightly."
    );
}

fn is_nightly_toolchain() -> bool {
    if env::var("RUSTC_BOOTSTRAP")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return true;
    }

    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    match Command::new(rustc).arg("--version").output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains("nightly")
        }
        _ => false,
    }
}
