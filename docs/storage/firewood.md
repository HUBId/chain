# Firewood lifecycle API

The Firewood storage backend exposes a dedicated lifecycle helper that moves
snapshot artifacts between nodes while preserving the Merkle commitment
contracts that Firewood publishes. The [`FirewoodLifecycle` helper](../../storage-firewood/src/lifecycle.rs)
wraps a [`FirewoodState`](../../storage-firewood/src/state.rs) handle and
orchestrates how pruning manifests and proofs land in the on-disk column
families. Its API surfaces the following guarantees:

- `ingest_snapshot` verifies the exported manifest and proof bundle before
  persisting it. The integration test exercises a sequence of three snapshots
  produced by Firewood itself and checks that every manifest ends up in the
  target storage directory. 【F:tests/firewood_lifecycle/mod.rs†L91-L120】
- `rollback_to_snapshot` truncates state to a previously verified height by
  deleting newer manifests and proofs before reloading the target block. The
  regression test confirms that only the intended snapshots remain after a
  rollback. 【F:tests/firewood_lifecycle/mod.rs†L122-L152】
- Layout upgrades are gated through the storage layout marker enforced by
  `STORAGE_LAYOUT_VERSION`. Any snapshot manifest with a different layout is
  rejected, preserving compatibility guarantees. 【F:storage-firewood/src/lifecycle.rs†L63-L95】【F:tests/firewood_lifecycle/mod.rs†L154-L178】

Firewood snapshots also carry schema and parameter digests whose prefixes map
back to the canonical key spaces defined in the storage schema module. The
[`schema` constants](../../storage-firewood/src/schema.rs) document those
prefixes and serve as the source of truth for how account, reputation, and block
metadata keys are encoded on disk. Snapshot ingestion therefore validates both
Merkle proofs and schema versioning before the runtime exposes the updated
state.

## Pruning automation and operational hooks

The runtime now ships a pruning worker alongside the lifecycle helper so nodes
continuously produce and hydrate Firewood snapshots without manual triggers. At
startup the pruning service publishes its cadence, retention depth, and pause
state, then streams `PruningJobStatus` updates through a watch channel that both
internal components and RPC handlers can subscribe to.【F:rpp/node/src/services/pruning.rs†L120-L200】
Each cycle persists pruning proofs, records missing heights, and broadcasts the
status over the snapshots gossip topic so downstream recovery tools observe the
latest plan immediately.【F:rpp/runtime/node.rs†L3580-L3639】

Operators interact with the automation via the `/snapshots/rebuild` and
`/snapshots/snapshot` RPCs, which return structured receipts describing whether
the request was accepted and why.【F:rpp/rpc/src/routes/state.rs†L1-L26】【F:rpp/storage/pruner/receipt.rs†L1-L58】
The pruning runbooks document how to adjust cadence, inspect receipts, and
monitor the status stream, rounding out the operational story for the automated
worker.【F:docs/runbooks/pruning.md†L1-L120】【F:docs/runbooks/pruning_operations.md†L1-L120】
