# Development Guide

## Build and test workflows

The repository provides Make targets that wrap the appropriate toolchains for
stable and nightly builds:

- `make build:stable` compiles all stable workspace members with `cargo +1.79.0`
  and skips prover crates that require nightly-only features.
- `make test:stable` runs the stable test suite under the same pinned toolchain
  and excludes the prover workspace crates.
- `make build:nightly` enters the prover sub-workspace and builds it with
  `cargo +nightly`.
- `make test:nightly` executes the prover tests with the nightly toolchain.

Set `STABLE_TOOLCHAIN`, `NIGHTLY_TOOLCHAIN`, or `PROVER_MANIFEST` when invoking
`make` to override the defaults, for example

```sh
make build:stable STABLE_TOOLCHAIN=+stable
```

The nightly targets only operate on `prover/Cargo.toml`, so stable developers do
not need to install nightly unless they work on prover components.
