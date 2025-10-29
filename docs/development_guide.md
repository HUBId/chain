# Development Guide

## Build and test workflows

The repository provides Make targets that wrap the appropriate toolchains for
stable and nightly builds:

- `make build:stable` compiles all stable workspace members with `cargo +1.79.0`
  and skips prover crates that require nightly-only features.
- `make test:stable` runs the stable test suite under the same pinned toolchain
  and excludes the prover workspace crates.
- `make build:nightly` enters the prover sub-workspace and builds it with
  `cargo +nightly-2025-07-14`.
- `make test:nightly` executes the prover tests with the pinned nightly toolchain.

Install or update the nightly compiler with `rustup toolchain install nightly-2025-07-14 --profile minimal` and remove obsolete
artifacts after switching to the new pin so that stale builds from older toolchains do not interfere with CI caches. Run
`cargo clean -p prover_stwo_backend`, delete the prover workspace target directory with `rm -rf prover/target`, and uninstall any
nightly toolchains older than `nightly-2025-07-14` (for example `rustup toolchain uninstall nightly-2025-06-30`).

Set `STABLE_TOOLCHAIN`, `NIGHTLY_TOOLCHAIN`, or `PROVER_MANIFEST` when invoking
`make` to override the defaults, for example

```sh
make build:stable STABLE_TOOLCHAIN=+stable
```

The nightly targets only operate on `prover/Cargo.toml`, so stable developers do
not need to install nightly unless they work on prover components.

## Feature flags

The workspace enables only the minimal feature set by default. When introducing a
new optional capability:

- Prefer additive `--features` flags over `default-features` changes so that
  stable builds remain deterministic.
- Gate prover-only functionality behind the `prover` feature and ensure it is
  disabled in `Cargo.toml` by default. Nightly CI will exercise the flag.
- Document any new feature in the crate README and add coverage for both the
  enabled and disabled configurations in the relevant tests.

To validate feature interactions locally, use:

```sh
cargo +1.79.0 test --no-default-features
cargo +1.79.0 test --all-features
```

## Nightly isolation

Nightly-only crates live under `prover/` and use a dedicated `Cargo.toml`. These
projects must not depend on stable-only workspace crates. The top-level
`Makefile` enforces this split via the `build:nightly` and `test:nightly`
targets, which change into the prover directory before invoking cargo. When a
stable crate needs to share code with nightly components, extract the common
logic into a `no_std` helper crate that compiles on the MSRV and add it as a
workspace dependency to both sides.

## Dependency update procedure

1. Run `cargo update -p <crate>` to propose a new version.
2. Verify the candidate still declares `rust-version = "1.79"` (or lower) and
   review the changelog for MSRV bumps.
3. If the dependency is listed in [`docs/msrv_pins.md`](./msrv_pins.md), open a
   discussion with the release engineering team before submitting a pull request.
4. Execute `make build:stable` and `make test:stable` locally, then run the
   nightly targets if the change touches prover code.
5. Include a note in the pull request summary about the dependency review and
   link to any upstream MSRV statements or issues.
