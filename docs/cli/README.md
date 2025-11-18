# Chain CLI smoke coverage

The `rpp/chain-cli` crate provides the clap surface that powers the runtime entry points and exposes validator tooling across the `node`, `wallet`, `hybrid`, and `validator` subcommands.【F:rpp/chain-cli/src/lib.rs†L61-L152】 The `cargo xtask test-cli` command exercises the top-level help text and the version banners for the unified `chain-cli` entry point as well as those subcommands. The job runs in CI for both the default feature set and with `backend-rpp-stark` enabled to ensure the clap surface remains stable across feature permutations.

When iterating locally you can inspect the same help output via `cargo run -p rpp-chain -- --help` (the lightweight stub binary under `rpp/chain/src/bin/chain_cli.rs`) or `cargo run -p rpp-node -- --help` (which wires the CLI crate into the runtime executor).【F:rpp/chain/src/bin/chain_cli.rs†L1-L12】【F:rpp/node/src/main.rs†L1-L6】 This mirrors what CI enforces so the documentation snapshots below stay in sync with the shipping binaries.

## Feature profiles and local commands

Two different feature sets keep the CLI usable across workflows:

* **Production/runtime builds.** Release artifacts disable the default `rpp-node` feature set and explicitly turn on `prod` plus one of the prover backends (`prover-stwo` or `prover-stwo-simd`). The crate now depends on `rpp-chain` with the `runtime-cli` feature so the `chain-cli` binary is still compiled alongside `node`, `wallet`, `hybrid`, and `validator` even in stripped-down builds.【F:rpp/node/Cargo.toml†L9-L85】 Run the shipping CLI locally with the same profile via `cargo run -p rpp-node --no-default-features --features prod,prover-stwo -- --help` (or swap in `prover-stwo-simd` on compatible hosts) and append `--dry-run` plus a mode to validate a configuration without launching the runtime.
* **Lightweight config-validation builds.** When you only need the clap surface—for example to check help text, flag wiring, or record new snapshots—you can compile the stub `rpp-chain` binary with just the `runtime-cli` feature enabled. This excludes the wallet/runtime integrations while still exposing every subcommand because the `runtime-cli` flag pulls in the clap dependency tree.【F:rpp/chain/Cargo.toml†L13-L48】 Use `cargo run -p rpp-chain --no-default-features --features runtime-cli -- --help` to exercise this minimal mode.

Snapshots of the expected output live under [`docs/cli/snapshots`](snapshots). The files contain the exact stdout emitted by the CLI invocations and are compared byte-for-byte during the smoke test. If the clap metadata changes (for example when adding a new flag or tweaking the exit-code documentation), refresh the fixtures with:

```sh
cargo xtask test-cli --record
```

The command rewrites the contents of `docs/cli/snapshots/*.stdout`. Re-run the smoke test afterwards—optionally setting `XTASK_FEATURES=backend-rpp-stark`—to confirm the recorded output matches the new CLI behaviour:

```sh
cargo xtask test-cli
XTASK_FEATURES=backend-rpp-stark cargo xtask test-cli
```
