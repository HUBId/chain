# Minimum Supported Rust Version (MSRV)

This project targets Rust **1.79.0** across the stable workspace. Prover
components continue to require nightly, but the rest of the repository must
compile, test, and lint successfully on the pinned stable toolchain.

## Policy rationale

- **Predictable upgrades.** Locking the MSRV to a specific minor release keeps the
  build surface deterministic for CI, vendor chains, and downstream integrators.
- **Security posture.** Requiring a recent stable compiler ensures access to the
  latest security patches for the standard library without depending on
  unstable language features.
- **Ecosystem compatibility.** The MSRV follows the oldest compiler supported by
  the majority of our audited third-party dependencies, helping avoid
  compatibility regressions when integrating upstream patches.

## Upgrade cadence

We re-evaluate the MSRV at the start of every even-numbered month. The release
engineering team leads the review and proposes an upgrade when:

1. The Rust release has been stable for at least four weeks.
2. CI runs for all supported targets (Linux, macOS, and Windows) pass with the
   candidate compiler.
3. All pinned dependencies in [`docs/msrv_pins.md`](./msrv_pins.md) have either
   verified compatibility or have approved migration plans.

Approved upgrades land in the first weekly release train following the review,
and the new version is added to `rust-toolchain.toml` and CI within the same
pull request.

## Local build instructions

Developers should install the pinned stable toolchain and use the provided Make
wrappers:

```sh
rustup toolchain install 1.79.0
make build:stable
make test:stable
```

`make build:nightly` and `make test:nightly` remain available for prover changes
and run in an isolated workspace. When experimenting with a newer compiler,
invoke cargo directly (e.g., `cargo +1.80.0 test`) but ensure CI still passes on
Rust 1.79.0 before opening a pull request.
