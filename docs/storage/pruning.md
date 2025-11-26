# Pruning checkpoints and recovery drills

The pruning flows exercised in CI mirror the operator steps for validating
state-sync checkpoints and mempool replay after a crash. The integration test
harness builds a short chain, prunes payloads down to proofs, and records a
state-sync checkpoint before simulating a WAL crash. The recovered node reloads
both the pruning plan and any transactions staged in the mempool WAL to ensure
state hashes and proof verification remain consistent across backends.

Each checkpoint JSON now embeds a `metadata` block that records the snapshot
height, the Unix timestamp when the plan was persisted, and the proof backend
used to generate it. The checkpoint and its metadata are written atomically to
`snapshot-<height>.json`, so recovery routines can ignore truncated files and
select the newest valid checkpoint by inspecting the metadata.

## Running the cross-backend drill locally

```shell
# Default backend (includes STWO proof replay)
cargo test -p rpp-chain --locked --features prover-stwo --test pruning_cross_backend -- \
  pruning_checkpoint_round_trip_default_backend wallet_snapshot_round_trip_default_backend

# RPP-STARK backend (replays golden vector verification)
cargo test -p rpp-chain --locked --features backend-rpp-stark --test pruning_cross_backend \
  -- pruning_checkpoint_round_trip_rpp_stark_backend wallet_snapshot_round_trip_rpp_stark_backend
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
8. After replay, verify zk proofs against deterministic inputs: the default
   backend synthesizes and verifies a STWO transaction proof, while the
   `backend-rpp-stark` lane replays the bundled golden vector to ensure
   verifier state stays aligned with snapshot contents.

## Signals to watch

* The pruning plan tip height/hash/state-root should match the finalized head
  even if consensus advanced mid-prune.
* Reconstructed blocks must hash to the same value they held before pruning and
  pass `verify_pruning` against their predecessor. The persisted pruning proof
  for the finalized head must validate via `ValidatedPruningEnvelope`.
* WAL replay should resurrect the queued transactions so the mempool count after
  restart equals the recovered WAL length.
* The STWO and RPP-STARK verifiers must accept their respective reference
  proofs after snapshot replay, proving that pruning did not desync witness
  inputs across backends.

These steps now run in the integration matrix (default and `backend-rpp-stark`)
so regressions in pruning, proof verification, or WAL handling are surfaced
before release.
