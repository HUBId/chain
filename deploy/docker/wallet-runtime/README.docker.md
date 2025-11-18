# Wallet Runtime Dockerfile

This directory packages the `rpp-wallet` CLI and the optional `rpp-wallet-gui`
frontend into a Debian-based container image. The Dockerfile mirrors the release
bundle defaults by compiling the runtime with the STWO prover backend and the
GUI with the `wallet_gui` feature enabled. Operators can override the feature
set at build time to experiment with the mock prover or enable advanced modules
such as hardware wallet hooks, mTLS, or multisig extensions.

## Build arguments

| Argument | Default | Description |
| --- | --- | --- |
| `RUST_IMAGE` | `rust:1.79-bullseye` | Builder stage image. Override to match the Rust toolchain pinned in `rust-toolchain.toml`. |
| `WALLET_TARGET` | `x86_64-unknown-linux-gnu` | Cargo target triple to compile for. Set to `aarch64-unknown-linux-gnu` and enable `cross` for ARM. |
| `WALLET_PROFILE` | `release` | Cargo profile used for both binaries. |
| `WALLET_FEATURE_FLAGS` | `--no-default-features --features runtime,prover-stwo` | Feature string applied to the CLI (`rpp-wallet`). Append `wallet_rpc_mtls` or `wallet_zsi` to bake in advanced modules, or switch to `prover-mock` for local smoke tests. |
| `WALLET_GUI_FEATURE_FLAGS` | `--no-default-features --features wallet_gui,prover-stwo` | Feature string used for the GUI (`rpp-wallet-gui`). Pass `wallet_hw` or other UI-specific features here as needed. |
| `EXTRA_CARGO_FLAGS` | _empty_ | Additional flags forwarded to both cargo invocations (for example `--locked --timings`). |

All feature flags are validated by cargo, so attempting to mix the experimental
`backend-plonky3` with `prover-stwo` will fail the build just like the release
scripts.

## Example builds

Build a default image:

```sh
docker build -t rpp-wallet:local -f deploy/docker/wallet-runtime/Dockerfile .
```

Enable the mock prover for both CLI and GUI:

```sh
docker build -t rpp-wallet:mock \
  --build-arg WALLET_FEATURE_FLAGS="--no-default-features --features runtime,prover-mock" \
  --build-arg WALLET_GUI_FEATURE_FLAGS="--no-default-features --features wallet_gui,prover-mock" \
  -f deploy/docker/wallet-runtime/Dockerfile .
```

Compile with mTLS and hardware wallet support:

```sh
docker build -t rpp-wallet:secure \
  --build-arg WALLET_FEATURE_FLAGS="--no-default-features --features runtime,prover-stwo,wallet_rpc_mtls,wallet_hw" \
  --build-arg WALLET_GUI_FEATURE_FLAGS="--no-default-features --features wallet_gui,prover-stwo,wallet_rpc_mtls,wallet_hw" \
  -f deploy/docker/wallet-runtime/Dockerfile .
```

The runtime layer drops privileges to the `app` user, copies the sample
`config/wallet.toml`, and keeps both binaries under `/opt/rpp-wallet/bin`. Use
Docker bind mounts or Kubernetes projected volumes to replace the configuration
file in production.
