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
- **Stalled replay gauges.** `timetoke_replay_stalled{threshold="warning"}` and
  `{threshold="critical"}` flip to `1` after 60 s / 120 s ohne Erfolgs-Replay.
  Paar sie mit den [finalen Kennzahlen](../observability/timetoke.md#final-replay-metrics)
  (`timetoke_replay_success_rate`, `timetoke_replay_stalled_final{threshold}`)
  und dem [CLI-Wrapper](../observability/timetoke.md#cli-quick-check)
  `rpp-node snapshot replay status`, der Erfolgsrate, Stalled-Detector und
  Exit-Codes dokumentiert – ✅ geprüft am 2026‑08‑26.【F:docs/observability/timetoke.md†L9-L158】【F:rpp/node/src/main.rs†L720-L1015】
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
   via `GET /p2p/snapshots` / `cargo run -p rpp-chain -- validator snapshot status`.
4. Confirm the Timetoke replay peer is still allowlisted with the expected tier
   (for example `Tl3`) using the admission policy tools before making changes.【F:docs/runbooks/admission.md†L21-L59】

## Step 1 – Capture and analyse the failing state

1. Inspect the replay dashboard or run the following PromQL queries to confirm which SLO breached. Focus on the new helper gauges that back the replay drill-down panels:
   - `timetoke_replay_seconds_since_success` and `timetoke_replay_last_success_timestamp`
     highlight how long the consumer has been idle.
   - `timetoke_replay_backlog_records` captures the number of ledger entries
     waiting for replay; pair it with `snapshot_stream_lag_seconds` to
     understand whether backlog growth is caused by slow ingest or slow
     replay.
   - `timetoke_replay_duration_ms_bucket` (p50/p95/p99) confirms whether the
     latency SLO or the success-rate SLO triggered the alert. Use the
     Timetoke observability snippets to chart the same percentiles locally
     when Grafana is unavailable.【F:docs/observability/timetoke.md†L9-L58】
   Capture a screenshot of the widened histogram buckets or rising backlog
   counter in the incident log so the evidence trail covers the pre-mitigation
   state.
2. Record the replay counters and latency SLO snapshot:
   ```sh
   cargo xtask report-timetoke-slo \
     --prometheus-url "https://prom.example.net" \
     --bearer-token "${PROM_TOKEN}" \
     --output timetoke-slo-before.md
   ```
   Attach the report to the incident log for before/after evidence.【F:xtask/src/main.rs†L1197-L1423】
   Supplement the Prometheus snapshot with the CLI view (finale Kennzahlen, Exit-Code-Matrix ✅ geprüft am 2026‑08‑26):
   ```sh
   rpp-node snapshot replay status \
     --config /etc/rpp/validator.toml \
     --rpc-url https://<consumer-host>:7070
   ```
   The command prints the final replay success rate (`Replay success rate: … %`
   inklusive Erfolgs-/Fehlerzähler) sowie den konsolidierten
   Stalled-Detector (`Replay stalled (warning|critical): …`). Anschließend folgen
   die Prozentillatenzen und der Exit-Code signalisiert, welche SLO verletzt
   wurde (`0` = grün, `10` = Erfolgsrate < 99 %, `20`/`21` = Stall-Warnung/-Kritisch,
   `30` = Latenzverletzung). Include the terminal output in the incident
   record.【F:docs/observability/timetoke.md†L90-L158】【F:rpp/node/src/main.rs†L720-L1015】
3. Fetch the latest Timetoke snapshot from a healthy producer and persist it:
   ```sh
   curl -sS \
     -H "Authorization: Bearer ${RPP_RPC_TOKEN}" \
     http://<producer-host>:<port>/ledger/timetoke \
     -o timetoke-snapshot.json
   ```
   The integration test `snapshot_timetoke_metrics.rs` exercises the same RPC to
   validate that providers serve complete snapshots.【F:tests/observability/snapshot_timetoke_metrics.rs†L187-L210】
4. Inspect the consumer session for stalled chunk or update indices:
   ```sh
   cargo run -p rpp-chain -- validator snapshot status --session <session-id> --config /etc/rpp/validator.toml
   ```
   Record the `last_chunk_index`, `last_update_index`, `verified`, and any `error`
   values for correlation with the metrics dashboards.【F:docs/runbooks/network_snapshot_failover.md†L82-L118】

5. If `timetoke_replay_backlog_records` continues to grow after the snapshot
   capture or the CLI reports `warning: replay success rate below 99 %`,
   escalate immediately:
   - **Ops On-Call** (`#ops-oncall`, +49 30 555 1234) – Coordinate failover and
     confirm whether multiple consumers are impacted.
   - **Timetoke Reliability Owner** (Nina Weber, nina.weber@example.com) –
     Reviews the backlog metrics, approves emergency replay throttling, and
     signs off on cross-region snapshot pulls.
   - **SRE Liaison** (`sre-standby@example.com`) – Tracks SLO impact and files
     the breach report referenced in the Phase‑B acceptance log.
   Continue with the reset steps below while the escalation is in flight and
   document the hand-off in the incident record.【F:docs/runbooks/incident_response.md†L1-L52】

## Step 2 – Reset the replay state

1. Cancel the stuck session to clear the local replay cursor:
   ```sh
   cargo run -p rpp-chain -- validator snapshot cancel --session <session-id> --config /etc/rpp/validator.toml
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
   cargo run -p rpp-chain -- validator snapshot start \
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
