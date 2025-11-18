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
