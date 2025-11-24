# Pruning checkpoints and recovery drills

The pruning flows exercised in CI mirror the operator steps for validating
state-sync checkpoints and mempool replay after a crash. The integration test
harness builds a short chain, prunes payloads down to proofs, and records a
state-sync checkpoint before simulating a WAL crash. The recovered node reloads
both the pruning plan and any transactions staged in the mempool WAL to ensure
state hashes and proof verification remain consistent across backends.

## Running the cross-backend drill locally

```shell
# Default backend
cargo test -p rpp-chain --locked --test pruning_cross_backend -- pruning_checkpoint_round_trip_default_backend

# RPP-STARK backend
cargo test -p rpp-chain --locked --features backend-rpp-stark --test pruning_cross_backend \
  -- pruning_checkpoint_round_trip_rpp_stark_backend
```

The scenarios:

1. Create deterministic dummy blocks and prune them down to proofs.
2. Capture the pruning checkpoint plan to `checkpoint-<height>.json`.
3. Reconstruct pruned payloads from an in-memory provider and verify their
   pruning proofs and hashes match the originals.
4. Append a handful of synthetic transactions to a dedicated mempool WAL,
   inject a partial record to mimic a crash, and replay the intact entries.
5. Restart the node, rehydrate the mempool from the recovered WAL contents, and
   confirm the checkpoint still lines up with the reconstructed tip height.

## Signals to watch

* The pruning plan tip height should match the persisted checkpoint even after
  recovery.
* Reconstructed blocks must hash to the same value they held before pruning and
  pass `verify_pruning` against their predecessor.
* WAL replay should resurrect the queued transactions so the mempool count after
  restart equals the recovered WAL length.

These steps now run in the integration matrix (default and `backend-rpp-stark`)
so regressions in pruning, proof verification, or WAL handling are surfaced
before release.
