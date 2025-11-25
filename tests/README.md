# Tests

## Feature guard coverage

`tests/feature_guard.rs` now drives the wallet and chain binaries to exercise the
runtime configuration guards alongside the existing compile-time checks. Each
stanza-specific test writes an isolated configuration under a temporary
directory, runs the binary via `cargo run`, and asserts that the expected
`WalletError` or `ChainError::Config` is surfaced when the related Cargo feature
is missing. Positive-control counterparts re-run the same command with the
feature enabled to prove that the guard clears once the binary supports the
stanza. Execute the suite with:

```
cargo test -p rpp-chain --test feature_guard
```

The helper uses `tempfile::tempdir`, distinct filenames, and `--dry-run` so the
checks remain parallel-safe and avoid long-running runtime loops.

## Wallet reorg coverage

Reorg handling is exercised under the wallet E2E suite to prove balances and
draft lock sequencing reconcile after forks for both REST- and CLI-driven
wallet flows. The tests force mocked indexer reorgs while transactions are in
flight, then assert that pending locks clear, balances match the new tip, and
nonce/lock identifiers advance on rebuilt drafts. Run the wallet coverage with:

```
cargo test -p rpp-chain --test wallet_e2e
```
