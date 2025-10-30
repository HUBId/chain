# State Sync Validation Pipeline

The state sync pipeline distributes pruning snapshots to peers that are still
catching up.  Prior to Phase 3 networking work the snapshots are staged on
coordinator infrastructure, which makes it critical that regressions are caught
before artifacts leave the build farm.  This repository ships a lightweight
validation pipeline that compares the receipts captured from pruning jobs with
the manifests that describe the snapshots to be published.

## Snapshot metadata

Canonical snapshot metadata lives in `storage::snapshots`.  Each entry records
schema and parameter digests alongside the block heights that were captured.  A
snapshot set therefore represents the exact view of state that will be offered
to new peers.  The data is derived from long-running devnet jobs and should be
updated whenever new snapshots are slated for distribution.

```rust
use storage::snapshots::known_snapshot_sets;

for set in known_snapshot_sets() {
    println!(
        "{} covers {} snapshots",
        set.label,
        set.snapshots.len()
    );
}
```

## Conformance test

`tests/state_sync/pruning_validation.rs` loads pruning receipts exported by
Firewood and asserts that every manifest advertised in `storage::snapshots`
matches the receipts written to disk.  The fixture encodes the raw
`PersistedPrunerState` structure so the test exercises the same conversion paths
that snapshot distribution will rely on when metadata is ingested at runtime.

The suite is wired into a dedicated `cargo xtask` command and exposed through
the `Makefile` so continuous integration environments can run it without
recreating the entire workspace test matrix:

```bash
cargo xtask pruning-validation
# or
make pruning-validation
```

CI jobs should execute this target before snapshots are pushed to artifact
storage.  Doing so ensures that schema upgrades, digest mismatches or stale
pruning data are caught early, long before a distribution pipeline would serve
invalid state to the network.
