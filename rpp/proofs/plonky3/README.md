# Plonky3 backend scaffolding

The Plonky3 integration that ships with this repository focuses on the
plumbing required by the chain services (typed public inputs, witness encoders
and deterministic proof blobs).  The actual constraint systems are still under
active development, but the workspace can already be built and tested without
network access thanks to the vendored Plonky3 shims under `vendor/`.

## Prerequisites

* **Rust toolchain** – the workspace targets Rust `1.83.0` (as pinned in
  `rust-toolchain.toml`).  Install it with `rustup toolchain install 1.83.0` if
  it is not already available.
* **Memory budget** – the current stub backend comfortably fits within 2 GiB of
  RAM during `cargo test` runs.  Future full Plonky3 circuits are expected to be
  more demanding; allocate at least 8 GiB of RAM when running heavy prover
  workloads.
* **Vendored dependencies** – ensure the repository is cloned with the
  `vendor/` directory intact.  `cargo` is configured to use those offline copies
  via `cargo/config.toml`, so no additional setup is required.

## Running the integration tests

The deterministic integration tests can be executed with:

```bash
cargo test -p rpp-chain plonky3
```

The tests construct witnesses for the transaction, state, pruning and recursive
circuits, generate Plonky3 proof blobs and verify them using the node-side
verifier.  The proofs are deterministic to keep the artefacts reproducible
across CI runs.
