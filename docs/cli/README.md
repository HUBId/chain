# Chain CLI smoke coverage

The `rpp/chain-cli` crate provides the clap surface that powers the runtime entry points and exposes validator tooling across the `node`, `wallet`, `hybrid`, and `validator` subcommands.【F:rpp/chain-cli/src/lib.rs†L61-L152】 The `cargo xtask test-cli` command exercises the top-level help text and the version banners for the unified `chain-cli` entry point as well as those subcommands. Each invocation now performs two smoke passes: one that clears any `XTASK_NO_DEFAULT_FEATURES`/`XTASK_FEATURES` overrides so the default feature set is exercised, and another that pins `XTASK_NO_DEFAULT_FEATURES=1` with `XTASK_FEATURES=runtime-cli` so the clap metadata stays compatible with stripped-down runtime builds.

When iterating locally run `cargo run -p rpp-chain -- --help` (the lightweight stub binary under `rpp/chain/src/bin/chain_cli.rs`) to inspect the same help output without bootstrapping the runtime.【F:rpp/chain/src/bin/chain_cli.rs†L1-L12】 This mirrors what CI enforces so the documentation snapshots below stay in sync with the shipping binaries. Use the built `rpp-node` binary only when validating the production artefact itself (for example, `target/release/rpp-node -- --help`).

## Feature profiles and local commands

Two different feature sets keep the CLI usable across workflows:

* **Production/runtime builds.** Release artifacts disable the default `rpp-node` feature set and explicitly turn on `prod` plus one of the prover backends (`prover-stwo` or `prover-stwo-simd`). The crate depends on `rpp-chain` with the `runtime-cli` feature so the `chain-cli` binary is still compiled alongside `node`, `wallet`, `hybrid`, and `validator` even in stripped-down builds.【F:rpp/node/Cargo.toml†L9-L85】 To reproduce the shipping profile locally run the release binary directly:

  ```sh
  target/release/rpp-node -- --help
  ```

  Swap in `prover-stwo-simd` during the build on compatible hosts. Attach `--dry-run node --node-config <path>` (or the `wallet`, `hybrid`, and `validator` modes) to validate a configuration without launching the runtime when using `cargo run -p rpp-chain`.
* **Lightweight config-validation builds.** When you only need the clap surface—for example to check help text, flag wiring, or record new snapshots—you can compile the stub `rpp-chain` binary with just the `runtime-cli` feature enabled. This excludes the wallet/runtime integrations while still exposing every subcommand because the `runtime-cli` flag pulls in the clap dependency tree.【F:rpp/chain/Cargo.toml†L13-L48】 Use the minimal profile to exercise help output quickly:

  ```sh
  cargo run -p rpp-chain --bin chain-cli --no-default-features --features runtime-cli -- --help
  ```

  This build is ideal for config-file validation because `cargo` skips the prover, wallet, and runtime integrations.

Snapshots of the expected output live under [`docs/cli/snapshots`](snapshots). Each profile keeps its own directory (for example `docs/cli/snapshots/default` and `docs/cli/snapshots/runtime-cli`) so the default and minimal builds can evolve independently. The files contain the exact stdout emitted by the CLI invocations and are compared byte-for-byte during the smoke test. `cargo xtask test-cli` automatically sets and restores the required `XTASK_*` environment variables before each pass, so local runs always capture both profiles without leaking overrides back into the shell. If the clap metadata changes (for example when adding a new flag or tweaking the exit-code documentation), refresh the fixtures with:

```sh
cargo xtask test-cli --record
```

The command rewrites the contents of `docs/cli/snapshots/*/*.stdout`. Re-run the smoke test afterwards to confirm the recorded output matches the new CLI behaviour. There is no need to call the command twice—the default feature set and the stripped-down `runtime-cli` build both run automatically:

```sh
cargo xtask test-cli
```
