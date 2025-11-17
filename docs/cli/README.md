# Chain CLI smoke coverage

The `rpp/chain-cli` crate provides the clap surface that powers the runtime entry points and exposes validator tooling across the `node`, `wallet`, `hybrid`, and `validator` subcommands.【F:rpp/chain-cli/src/lib.rs†L61-L152】 The `cargo xtask test-cli` command exercises the top-level help text and the version banners for the unified `chain-cli` entry point as well as those subcommands. The job runs in CI for both the default feature set and with `backend-rpp-stark` enabled to ensure the clap surface remains stable across feature permutations.

When iterating locally you can inspect the same help output via `cargo run -p rpp-chain -- --help` (the lightweight stub binary under `rpp/chain/src/bin/chain_cli.rs`) or `cargo run -p rpp-node -- --help` (which wires the CLI crate into the runtime executor).【F:rpp/chain/src/bin/chain_cli.rs†L1-L12】【F:rpp/node/src/main.rs†L1-L6】 This mirrors what CI enforces so the documentation snapshots below stay in sync with the shipping binaries.

Snapshots of the expected output live under [`docs/cli/snapshots`](snapshots). The files contain the exact stdout emitted by the CLI invocations and are compared byte-for-byte during the smoke test. If the clap metadata changes (for example when adding a new flag or tweaking the exit-code documentation), refresh the fixtures with:

```sh
cargo xtask test-cli --record
```

The command rewrites the contents of `docs/cli/snapshots/*.stdout`. Re-run the smoke test afterwards—optionally setting `XTASK_FEATURES=backend-rpp-stark`—to confirm the recorded output matches the new CLI behaviour:

```sh
cargo xtask test-cli
XTASK_FEATURES=backend-rpp-stark cargo xtask test-cli
```
