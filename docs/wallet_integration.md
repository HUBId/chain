# Wallet integration feature

## Purpose and scope

The `wallet-integration` feature flag on `rpp-chain` turns on every dependency the
runtime needs to embed the wallet orchestrator, wallet RPC surface, and Electrs
plumbing directly inside the node binaries. When the feature is enabled the crate
pulls in `rpp-wallet`, the wallet prover mocks, and the optional Electrs vendor
helpers, which is why the default feature set (`prover-mock` + `wallet-ui`)
already builds wallet support out of the box.【F:rpp/chain/Cargo.toml†L13-L41】 The
`rpp-node` binary always compiles with both `wallet-ui` and `wallet-integration`
so the `node`, `wallet`, `hybrid`, and `validator` entrypoints all share the same
codepaths, telemetry, and CLI plumbing.【F:rpp/node/Cargo.toml†L10-L49】 Disabling
the feature produces a lightweight chain binary with no wallet runtime, RPC
handlers, or Electrs integration.

## `rpp-wallet-interface` helper crate

`rpp-wallet-interface` lives alongside `rpp-wallet` and exposes the RPC DTOs,
telemetry counters, workflow payloads, and `WalletService` trait that both the
node runtime and the wallet binaries rely on. The wallet crate re-exports those
types, but the shared interface crate is what downstream consumers (e.g.,
testing shims or hosted services) import when they cannot depend on the full
wallet runtime. Always update the interface crate and the wallet modules in lock
step when changing payloads, then run `cargo check -p rpp-wallet-interface &&
cargo check -p rpp-wallet` before sending the patch.【F:rpp/wallet/README.md†L1-L37】

## Build and test commands

Use the following commands to control whether wallet support is compiled. The
examples below assume Rust 1.79, but they also work with `cargo +nightly` when
needed for prover crates.

| Goal | Command | Notes |
| --- | --- | --- |
| Build the default wallet-enabled node stack | `cargo build -p rpp-chain` | `prover-mock` and `wallet-ui` are part of the default feature set, so running `cargo build` with no extra flags already enables `wallet-integration`. |
| Run wallet-enabled tests | `cargo test -p rpp-chain` | Exercises the wallet RPC tests (e.g., `runtime_wallet_cfg`) because `wallet-integration` is part of the default features.【F:rpp/chain/Cargo.toml†L13-L50】 |
| Build a wallet-enabled profile after clearing defaults | `cargo build -p rpp-chain --no-default-features --features "wallet-integration,prover-stwo,prod"` | Start with a clean slate, then opt back into `wallet-integration` plus whatever prover or production flags you need. Use this pattern when auditing which optional crates the feature graph pulls in. |
| Run wallet-enabled tests with explicit flags | `cargo test -p rpp-chain --no-default-features --features "wallet-integration,prover-mock"` | Re-enables the wallet plus the mock prover after clearing defaults so feature guard tests continue to run. |
| Build a wallet-disabled validator profile | `cargo build -p rpp-chain --no-default-features --features prod` | Produces a minimal binary that excludes the wallet runtime, Electrs glue, and wallet RPC handlers. Pair with `--features prover-stwo` if you still need the STWO backend without wallet orchestration. |
| Run wallet-disabled tests | `cargo test -p rpp-chain --no-default-features --features prod` | Ensures validators can run without linking `rpp-wallet`. Wallet-specific tests are automatically skipped because their `required-features` include `wallet-integration`. |

## Feature dependency considerations

- `prover-mock` now lists `wallet-integration` as a dependency, so any build that
  turns on the mock backend (including the `rpp-node` `dev` profile) implicitly
  compiles the wallet. Use `--no-default-features --features prod` (and avoid
  `prover-mock`, `wallet-ui`, `wallet_rpc_mtls`, `backend-rpp-stark`, and
  `vendor_electrs`) when you want a wallet-free binary.【F:rpp/chain/Cargo.toml†L13-L74】
- Because the wallet is pulled in through the chain crate, running
  `cargo build --workspace --no-default-features` is rarely useful: crates such
  as `rpp-node` unconditionally request `wallet-integration`, so you must either
  exclude them (`-p rpp-chain` / `-p rpp-node`) or re-enable the feature set you
  need. Prefer the targeted commands above to make your intent explicit.
- Wallet-adjacent features like `wallet_rpc_mtls`, `backend-rpp-stark`, and
  `vendor_electrs` are layered on top of `wallet-integration`, so you cannot
  toggle them without also compiling the wallet runtime.【F:rpp/chain/Cargo.toml†L16-L74】

Refer back to this guide whenever you add new wallet-facing crates or change the
feature graph so contributors know how to reproduce both wallet-enabled and
wallet-disabled builds.
