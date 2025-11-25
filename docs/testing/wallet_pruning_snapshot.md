# Wallet pruning snapshot smoke test

This smoke test exercises the end-to-end wallet backup flow while pruning the
local data directory, restoring from the exported snapshot, and verifying that
balances and submission receipts survive the round-trip.

## What the test covers

* Seeds a wallet with deterministic keys and UTXOs from the test indexer.
* Creates and broadcasts a transaction to ensure receipts are recorded.
* Exports an encrypted backup archive, wipes the data directory, and imports the
  archive into a fresh directory.
* Resumes synchronization against the same indexer and asserts that balances
  match the pre-backup state.
* Broadcasts a second transaction after restore and writes a summary artifact to
  `logs/wallet-pruning-snapshot/summary.json` for CI collection.

## Running locally

```bash
cargo test -p wallet-integration-tests --locked --test wallet_pruning_snapshot
```

The test writes its summary under `logs/wallet-pruning-snapshot/summary.json` in
workspace-relative paths. Inspect the JSON to confirm the initial/restored
balances, the restored birthday checkpoint, and the number of captured
submissions.

## CI execution

The integration workflow now runs the smoke test in both the default and
`backend-rpp-stark` matrices via `cargo xtask test-integration`. Artifacts under
`logs/wallet-pruning-snapshot` are uploaded alongside the other integration
logs, making it easy to inspect restore evidence after failures.
