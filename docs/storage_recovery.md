# Firewood Storage Recovery Runbook

This runbook documents how operators rebuild Firewood-backed nodes after a
crash or snapshot restore. It covers write-ahead log (WAL) replay, snapshot
restoration, and pruning checkpoint validation so recovered nodes rejoin the
network with verified state commitments.

## 1. Validate the WAL

1. **Stop the node and mount the data directory read-only.** Prevent new writes
   until recovery completes.
2. **Inspect the WAL health flag.** Opening the WAL replays the index and raises
   `WalError::Corrupt` if the payload lengths do not match their prefixes. The
   integration test `corrupted_payload_triggers_recovery_error` demonstrates the
   expected error when a truncated payload is detected.【F:storage-firewood/src/wal.rs†L256-L303】
3. **Rebuild the log if corruption is detected.** Delete the `firewood.wal`
   file, copy in the most recent snapshot (see §2), and restart the node so it
   reconstructs a fresh WAL from the snapshot.
4. **Replay from the last consistent sequence.** Healthy logs can be replayed
   from any sequence using `FileWal::replay_from`. The `append_and_replay_after_restart`
   test shows that re-opening the WAL replays the complete history and supports
   partial recovery for sequence-specific replays.【F:storage-firewood/src/wal.rs†L232-L281】

## 2. Restore a Consistent Snapshot

1. **Stage the snapshot into `data_dir/db`.** Replace the RocksDB column
   families with the files captured during the maintenance window or hot backup.
2. **Reapply deterministic mutations.** Restart the node and allow it to
   rebuild Merkle state. Each block commit should call
   `FirewoodState::commit_block`, which flushes the staged mutations, returns the
   new Merkle root, and produces a pruning proof for downstream verification.【F:storage-firewood/src/state.rs†L37-L63】
3. **Audit the recovered root.** Compare the emitted state root with the
   checkpoint recorded during backup. Mismatches indicate missing WAL entries or
   an incomplete snapshot and must be resolved before continuing.

## 3. Verify Pruning Checkpoints

1. **Collect recent pruning proofs.** The node persists canonical pruning
   envelopes for each block ID; restoring from snapshot should preserve the
   latest envelopes generated during `commit_block`.
2. **Verify checkpoints before pruning historical state.** Feed the state root
   and pruning envelope into `FirewoodPruner::verify_pruned_state` to ensure the
   compacted snapshot matches the recorded Merkle frontier.【F:storage-firewood/src/pruning.rs†L302-L317】
3. **Resume automated pruning.** Once proofs verify, resume normal operations so
   the pruner can evict cold state while keeping the commitment trail intact for
   recursive proof systems.

## 4. Post-Recovery Checks

1. **Run health checks.** Confirm RPC endpoints respond, telemetry resumes, and
   consensus participation metrics match other validators.
2. **Document the incident.** Record the corruption root cause, snapshot age,
   and verification steps for future audits.

Following these steps guarantees storage repairs reconstitute the Merkle state
and pruning frontier expected by downstream proofs.

## 5. Automated Recovery Drill

To keep these procedures fresh, CI runs `scripts/ci/firewood_recovery.sh` every
night at 05:00 UTC. The drill corrupts a WAL, restores a snapshot, and
validates the resulting state root with `FirewoodPruner::verify_pruned_state`.
GitHub Actions uploads the generated JSON summary and console log as the
`firewood-recovery-artifacts` bundle so operators can review the latest dry
run results.
