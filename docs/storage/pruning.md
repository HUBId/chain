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
4. Advance consensus by appending a new block after the pruning cycle and
   assert the refreshed checkpoint tip height/hash/state-root equals the
   finalized head.
5. Reload the persisted pruning proof for the finalized head and validate it
   with `ValidatedPruningEnvelope` so zk commitments match the header digests.
6. Append a handful of synthetic transactions to a dedicated mempool WAL,
   inject a partial record to mimic a crash, and replay the intact entries.
7. Restart the node, rehydrate the mempool from the recovered WAL contents, and
   confirm the checkpoint still lines up with the reconstructed tip height.

## Signals to watch

* The pruning plan tip height/hash/state-root should match the finalized head
  even if consensus advanced mid-prune.
* Reconstructed blocks must hash to the same value they held before pruning and
  pass `verify_pruning` against their predecessor. The persisted pruning proof
  for the finalized head must validate via `ValidatedPruningEnvelope`.
* WAL replay should resurrect the queued transactions so the mempool count after
  restart equals the recovered WAL length.

These steps now run in the integration matrix (default and `backend-rpp-stark`)
so regressions in pruning, proof verification, or WAL handling are surfaced
before release.
