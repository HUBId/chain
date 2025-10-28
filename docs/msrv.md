# MSRV and feature compatibility CI

The repository guarantees a minimum supported Rust version (MSRV) of **1.79.0**. The
CI pipeline enforces this guarantee and validates feature combinations through the
`MSRV` workflow.

## Workflow overview

The workflow runs on pushes and pull requests targeting `main` or release
branches. It is composed of three ordered jobs:

1. **MSRV minimal feature matrix**
   - Installs the Rust 1.79.0 toolchain.
   - Installs `cargo-msrv` and `cargo-hack`.
   - Verifies the workspace builds with the declared MSRV via
     `cargo msrv verify --toolchain 1.79.0 --path .`.
   - Detects lockfile drift by running `cargo update --locked` and asserting that
     `Cargo.lock` has no uncommitted changes.
   - Exercises the minimal feature surface with `cargo hack check` in two
     configurations: without default features and with each stable feature
     individually (nightly prover features are excluded from the matrix).

2. **MSRV full workspace (stable features)**
   - Reuses the 1.79.0 toolchain.
   - Performs the same lockfile drift validation as the minimal job.
   - Builds the default workspace and the `integration`/`vendor_electrs`
     feature combination with `cargo hack check`, still excluding prover
     features that require nightly.

3. **Nightly prover feature matrix**
   - Installs the nightly toolchain to cover prover-only code paths.
   - Runs `cargo hack check` with the `prover-stwo-simd` feature set, which pulls
     in all prover-related functionality.

Each job scopes its cache via `Swatinem/rust-cache` with a shared key that embeds
its toolchain (`msrv-1.79.0-*` for stable and `nightly-prover` for nightly) to
avoid cross-contamination between stable and nightly builds.

## Local verification

To reproduce the CI coverage locally:

```bash
# Minimal matrix on the MSRV toolchain
rustup toolchain install 1.79.0
cargo +1.79.0 install --locked cargo-hack cargo-msrv
cargo +1.79.0 msrv verify --toolchain 1.79.0 --path .
cargo +1.79.0 hack check --workspace --all-targets --no-dev-deps --locked --no-default-features
cargo +1.79.0 hack check --workspace --all-targets --no-dev-deps --locked --each-feature \
  --exclude-features nightly-prover --exclude-features prover-stwo --exclude-features prover-stwo-simd

# Stable feature build
cargo +1.79.0 hack check --workspace --all-targets --no-dev-deps --locked
cargo +1.79.0 hack check --workspace --all-targets --no-dev-deps --locked --features "integration,vendor_electrs" \
  --exclude-features nightly-prover --exclude-features prover-stwo --exclude-features prover-stwo-simd

# Nightly prover coverage
rustup toolchain install nightly
cargo +nightly hack check --workspace --all-targets --no-dev-deps --locked --features "prover-stwo-simd"
```

Running the lockfile check locally ensures dependency updates do not modify
`Cargo.lock` unexpectedly:

```bash
cargo +1.79.0 update --locked
git diff --exit-code Cargo.lock
```

These steps keep the MSRV promise verifiable and highlight dependency drift
before changes are merged.
