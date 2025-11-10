# Chain CLI smoke coverage

The `cargo xtask test-cli` command exercises the top-level help text and the version banners for the unified `chain-cli` entry point as well as the `node`, `wallet`, `hybrid`, and `validator` subcommands. The job runs in CI for both the default feature set and with `backend-rpp-stark` enabled to ensure the clap surface remains stable across feature permutations.

Snapshots of the expected output live under [`docs/cli/snapshots`](snapshots). The files contain the exact stdout emitted by the CLI invocations and are compared byte-for-byte during the smoke test. If the clap metadata changes (for example when adding a new flag or tweaking the exit-code documentation), refresh the fixtures with:

```sh
cargo xtask test-cli --record
```

The command rewrites the contents of `docs/cli/snapshots/*.stdout`. Re-run the smoke test afterwards—optionally setting `XTASK_FEATURES=backend-rpp-stark`—to confirm the recorded output matches the new CLI behaviour:

```sh
cargo xtask test-cli
XTASK_FEATURES=backend-rpp-stark cargo xtask test-cli
```
