# Timetoke failover runbook

Use this runbook when Timetoke replay stalls, replay errors spike, or snapshot
retries no longer advance the ledger commitment. It complements the
[Timetoke observability guide](../observability/timetoke.md) and the
[snapshot failover playbook](./network_snapshot_failover.md) by focusing on the
ledger replay and pruning validation steps that gate validator participation.

## Detection

Investigate a Timetoke failover when any of the following signals trigger:

- **Replay error alert.** Prometheus rules fire when
  `timetoke_replay_failure_total` increases faster than the paired success
  counter or the replay success rate drops below the 99 % SLO.【F:docs/observability/timetoke.md†L9-L52】
- **Latency regressions.** The `timetoke_replay_duration_ms` histogram widens
  (p95 or p99 crossing the 60 s / 120 s SLO) and the paired `cargo xtask
  report-timetoke-slo` summary flags the breach.【F:docs/observability/timetoke.md†L9-L52】【F:xtask/src/main.rs†L1197-L1423】
- **Snapshot lag correlation.** `snapshot_stream_lag_seconds` climbs together
  with Timetoke latency, signalling that the consumer no longer ingests chunks
  fast enough to feed replay.【F:docs/observability/pipeline.md†L48-L96】
- **Checksum warnings.** `snapshot chunk validation failed` log entries and
  increments of `snapshot_chunk_checksum_failures_total{kind="checksum_mismatch"}`
  indicate corrupted on-disk chunks that block replay until repaired.【F:rpp/node/src/services/snapshot_validator.rs†L85-L158】

Keep the pipeline dashboards and the Timetoke SLO report open while running the
rest of this playbook to confirm that each intervention moves the counters back
into their targets.【F:docs/observability/pipeline.md†L48-L96】【F:xtask/src/main.rs†L1197-L1423】

## Prerequisites

1. Export the validator RPC token (`export RPP_RPC_TOKEN=...`).
2. Identify the affected consumer RPC endpoint (host:port).
3. Collect the active snapshot session ID from the alert, the incident log, or
   via `GET /p2p/snapshots` / `rpp-node validator snapshot status`.
4. Confirm the Timetoke replay peer is still allowlisted with the expected tier
   (for example `Tl3`) using the admission policy tools before making changes.【F:docs/runbooks/admission.md†L21-L59】

## Step 1 – Capture the failing state

1. Record the replay counters and latency SLO snapshot:
   ```sh
   cargo xtask report-timetoke-slo \
     --prometheus-url "https://prom.example.net" \
     --bearer-token "${PROM_TOKEN}" \
     --output timetoke-slo-before.md
   ```
   Attach the report to the incident log for before/after evidence.【F:xtask/src/main.rs†L1197-L1423】
2. Fetch the latest Timetoke snapshot from a healthy producer and persist it:
   ```sh
   curl -sS \
     -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     http://<producer-host>:<port>/ledger/timetoke \
     -o timetoke-snapshot.json
   ```
   The integration test `snapshot_timetoke_metrics.rs` exercises the same RPC to
   validate that providers serve complete snapshots.【F:tests/observability/snapshot_timetoke_metrics.rs†L187-L210】
3. Inspect the consumer session for stalled chunk or update indices:
   ```sh
   rpp-node validator snapshot status --session <session-id> --config /etc/rpp/validator.toml
   ```
   Record the `last_chunk_index`, `last_update_index`, `verified`, and any `error`
   values for correlation with the metrics dashboards.【F:docs/runbooks/network_snapshot_failover.md†L82-L118】

## Step 2 – Reset the replay state

1. Cancel the stuck session to clear the local replay cursor:
   ```sh
   rpp-node validator snapshot cancel --session <session-id> --config /etc/rpp/validator.toml
   ```
   The RPC equivalent (`DELETE /p2p/snapshots/<session>`) removes the persisted
   state and ensures a fresh resume starts at chunk index 0.【F:docs/runbooks/network_snapshot_failover.md†L174-L211】
2. Re-run the checksum validator against the local snapshot directory to confirm
   no corrupted chunks remain before resuming:
   ```sh
   journalctl -u rpp-node -t snapshot_validator --since "-10 min"
   ```
   Look for repeated `snapshot chunk validation failed` entries and verify the
   metric increments, as exercised by the restart regression test.【F:rpp/node/src/services/snapshot_validator.rs†L85-L158】【F:tests/network/snapshot_checksum_restart.rs†L80-L170】
3. If the validator recently rotated tiers or admission policies, verify the
   provider peer remains allowlisted at the required tier level and reapply the
   last known-good snapshot if drift is detected.【F:docs/runbooks/admission.md†L21-L104】

## Step 3 – Re-request the snapshot and replay

1. Start a fresh snapshot session targeting the healthy provider:
   ```sh
   rpp-node validator snapshot start \
     --peer <provider-peer-id> \
     --config /etc/rpp/validator.toml
   ```
   Monitor the returned session ID and plan identifier for the incident log.【F:docs/runbooks/network_snapshot_failover.md†L73-L118】
2. After the new chunks land, push the recorded snapshot to the consumer to
   restart Timetoke replay:
   ```sh
   curl -sS -X POST \
     -H 'Content-Type: application/json' \
     -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     -d @timetoke-snapshot.json \
     http://<consumer-host>:<port>/ledger/timetoke/sync
   ```
   The RPC route accepts a `records` array and returns the identities that were
   updated; the observability test confirms the workflow end-to-end.【F:rpp/rpc/api.rs†L2523-L2540】【F:tests/observability/snapshot_timetoke_metrics.rs†L201-L248】
3. Poll the session status until `verified: true`, then confirm replay latency
   returns to baseline and the failure counter stops increasing. Attach the
   terminal output and Grafana screenshots to the incident log.【F:docs/observability/timetoke.md†L9-L52】【F:docs/observability/pipeline.md†L48-L96】

## Troubleshooting

- **Replay still fails validation.** Run `cargo test --test timetoke_snapshots --
  timetoke_replay_validation_guards_roots_and_tags` to reproduce the failure
  locally and inspect the pruning digest bindings enforced by the validator.【F:tests/consensus/timetoke_snapshots.rs†L101-L169】
- **Metrics never move.** Use `cargo xtask test-observability` (or invoke the
  `snapshot_timetoke_metrics` integration test directly) to ensure the metrics
  pipeline is healthy before escalating the incident.【F:tests/observability/snapshot_timetoke_metrics.rs†L70-L248】
- **Checksum mismatches persist.** Re-run the checksum restart test pattern
  locally (`cargo test --test snapshot_checksum_restart`) to validate the
  manifest and chunk directories, mirroring the production cadence.【F:tests/network/snapshot_checksum_restart.rs†L80-L177】
- **Peer rejected on resume.** Reconcile admission allowlists and tier
  assignments using the admission runbook before retrying the snapshot request;
  mismatched tiers prevent replay peers from connecting.【F:docs/runbooks/admission.md†L21-L104】

Document each action, attach before/after metrics, and update the incident log
so the Phase 3 evidence trail remains complete.
