# Storage Stable Report

_Last updated: 2025-10-12_

## Scan Summary

- Checked `storage-firewood/Cargo.toml` to ensure the crate targets Rust edition 2021 with `rust-version = "1.83"` and no `cargo-features` stanza.
- Searched the storage crate for unstable compiler usage.
  - `rg --fixed-strings '#![feature' storage-firewood` → no matches.
  - `rg '\-Z' storage-firewood` → no matches.

## Findings

No nightly-only compiler features or unstable Cargo flags remain in `storage-firewood/`. The crate is compatible with the stable Rust 1.83 toolchain.

## CI Status

No storage-specific CI workflows were found in `.github/workflows/`. The shared `Cargo fmt`, `Cargo clippy`, and `Cargo tests` jobs (default features plus the `prover-stwo` lane) already pin to the repository toolchain from `rust-toolchain.toml`, so storage components are covered transitively. If a dedicated storage pipeline is added in the future, pin it to `1.83.0` as well.

## Follow-up To-dos

- Re-run the scans above whenever new storage modules are added or dependencies are bumped.
- If future changes introduce storage-only CI jobs, ensure they run on `toolchain: 1.83.0` to keep parity with the workspace requirements.
- Monitor upstream Firewood releases for additional MSRV constraints.
