# prover_stwo_backend

The `prover_stwo_backend` crate packages the STWO proving stack that powers the
RPP node, wallet, and consensus subsystems. It mirrors the upstream StarkWare
blueprints while preserving deterministic behaviour for local development and
CI.

## Toolchain

The STWO fork relies on nightly-only dependencies. The prover-specific
subworkspace ships its own pinned toolchain under `prover/rust-toolchain.toml`,
ensuring callers only opt into nightly when they build the prover crates.

## Feature flags

| Feature             | Description |
| ------------------- | ----------- |
| `prover-stwo`       | Enables the official STWO prover and exposes all supported circuits (identity, transaction, state transition, pruning, recursive aggregation, uptime, and consensus). |
| `prover-stwo-simd`  | Extends `prover-stwo` and forwards to the upstream `parallel` feature, activating the optional SIMD execution path on hardware that supports it. |
| `prover-mock`       | Keeps the lightweight mock backend available for tests that do not require STARK proofs. |

> The historical `simd` flag remains as an alias for `prover-stwo-simd` to ease
> migration, but new code should prefer the explicit name.

## Enabling circuits downstream

Enable the required features in your `Cargo.toml` depending on the execution
path you need:

```toml
[dependencies]
prover-backend-interface = { path = "../rpp/zk/backend-interface", features = ["prover-stwo"] }
prover_stwo_backend = { path = "../prover/prover_stwo_backend", features = ["prover-stwo"] }
```

Switch to the SIMD accelerated prover by toggling the feature list:

```toml
[dependencies]
prover-backend-interface = { path = "../rpp/zk/backend-interface", features = ["prover-stwo-simd"] }
prover_stwo_backend = { path = "../prover/prover_stwo_backend", features = ["prover-stwo-simd"] }
```

The backend interface crate tracks the same feature names, allowing downstream
packages to opt into the new circuits without wiring changes beyond the feature
lists.
