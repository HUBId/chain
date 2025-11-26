# Pruning operations runbook

Use this runbook during routine monitoring of the pruning worker or when the
service degrades. It complements the [pruning change runbook](pruning.md) by
focusing on telemetry, dashboards, and failure-handling procedures.

For Firewood durability knobs—WAL sizing, sync policy trade-offs, and recovery
signals—consult the [Firewood storage operations notes](../storage/firewood.md#wal-sizing-and-sync-policy-guidance)
before applying overrides.

## 1. Monitor the pruning service

1. **Confirm the worker is active.** Right after startup the service logs the
   cadence, retention depth, and pause flag. Absence of the
   `"pruning service started"` log means the worker never spawned or crashed
   immediately.【F:rpp/node/src/services/pruning.rs†L151-L163】
2. **Watch the status stream.** The service publishes `PruningJobStatus` updates
   for every cycle. Operators can subscribe through `PruningService::subscribe_status`
   or poll the `/snapshots/jobs` RPC exposed to validators to capture the latest
   plan, missing heights, and persisted snapshot path.【F:rpp/node/src/services/pruning.rs†L177-L179】【F:rpp/node/src/services/pruning.rs†L407-L417】【F:rpp/runtime/node.rs†L428-L435】【F:rpp/runtime/node.rs†L3200-L3215】
3. **Track cadence overrides.** Retention and pause updates flow through the
   command channel. Each change emits a telemetry sample so dashboards should
   show the new retention depth or pause state before the next scheduled run.【F:rpp/node/src/services/pruning.rs†L356-L399】【F:rpp/node/src/telemetry/pruning.rs†L25-L116】

## 2. Metrics reference

| Metric | Type | Labels | Operational use |
|--------|------|--------|-----------------|
| `rpp.node.pruning.cycle_total` | Counter | `shard`, `partition`, `reason`, `result` | Alert when scheduled cycles fail repeatedly or when manual runs dominate within a shard.【F:rpp/node/src/telemetry/pruning.rs†L25-L116】【F:rpp/node/src/services/pruning.rs†L391-L399】 |
| `rpp.node.pruning.cycle_duration_ms` | Histogram | `shard`, `partition`, `reason`, `result` | Plot p50/p95 to ensure rebuilds complete before the next cadence tick in each shard.【F:rpp/node/src/telemetry/pruning.rs†L25-L116】【F:rpp/node/src/services/pruning.rs†L391-L399】 |
| `rpp.node.pruning.persisted_plan_total` | Counter | `shard`, `partition`, `reason`, `persisted` | Detect when cycles stop emitting snapshot plans (possible storage regression) on a shard.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】【F:rpp/runtime/node.rs†L3200-L3202】 |
| `rpp.node.pruning.missing_heights` | Histogram | `shard`, `partition` | Surface sudden growth in backlog requiring manual hydration for a shard.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】【F:rpp/runtime/node.rs†L3200-L3207】 |
| `rpp.node.pruning.stored_proofs` | Histogram | `shard`, `partition` | Validate that pruning proofs continue to sync to storage.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】【F:rpp/runtime/node.rs†L3200-L3207】 |
| `rpp.node.pruning.retention_depth` | Histogram | `shard`, `partition` | Confirm override depth applied during incidents.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】【F:rpp/node/src/services/pruning.rs†L356-L399】 |
| `rpp.node.pruning.pause_transitions` | Counter | `shard`, `partition`, `state` | Alert when the service is paused longer than the agreed maintenance window.【F:rpp/node/src/telemetry/pruning.rs†L63-L117】【F:rpp/node/src/services/pruning.rs†L356-L366】 |

Dashboards should plot the histograms as time-series (e.g. last sample) or
aggregated percentiles. Combine `cycle_total` with failure-specific alerts to
raise incidents when three consecutive scheduled runs fail.

## 3. Log interpretation

- `pruning service started` – emitted once after worker spawn. Confirms cadence,
  chunk size, pause state, and retention depth resolved from configuration.【F:rpp/node/src/services/pruning.rs†L151-L163】
- `pruning cycle failed` – emitted whenever a pruning cycle returns an error.
  Correlate with `cycle_total{result="failure"}` and `/snapshots/jobs` receipts
  to identify the failing height.【F:rpp/node/src/services/pruning.rs†L393-L400】【F:rpp/node/src/services/pruning.rs†L407-L417】
- `persisted pruning snapshot plan` – emitted by the runtime when a cycle
  stores the plan on disk. If the log is missing while `persisted_plan_total`
  remains zero, storage or filesystem permissions likely regressed.【F:rpp/runtime/node.rs†L3200-L3202】【F:rpp/node/src/telemetry/pruning.rs†L36-L40】

## 4. Startup compatibility matrix

Pruning command-line switches are valid across the storage feature matrix, but
`--pruning-pause` and `--pruning-resume` are mutually exclusive. The runtime
fails fast on startup when both are supplied so operators choose a single
startup state before the pruning worker launches.【F:rpp/node/src/lib.rs†L218-L239】【F:rpp/node/tests/runtime_modes.rs†L44-L75】

| Binary feature set | Storage path | Prover backend | Pruning CLI compatibility |
|--------------------|--------------|----------------|---------------------------|
| Default (no extra features) | Sync I/O | plonky3 | `--pruning-pause` **or** `--pruning-resume`; both flags together are rejected. |
| `io-uring` | io-uring | plonky3 | Same as default; conflicting pause/resume flags abort startup. |
| `branch_factor_256` | Sync I/O (branch-factor 256 hashing) | plonky3 | Same as default; mutually exclusive pause/resume options. |
| `io-uring` + `branch_factor_256` | io-uring with branch-factor 256 hashing | plonky3 | Same as default; pause/resume conflict rejected. |
| `backend-rpp-stark` (+ storage variants above) | Matches storage column | RPP-STARK | Same as default; pause/resume conflict rejected. |

## 5. Verify pruning checkpoints

1. **Capture roots before and after pruning.** Use `fwdctl compare` to hash the
   Firewood database captured prior to pruning or checkpoint rebuild and the
   post-pruning database:

   ```bash
   fwdctl compare --before-db /var/lib/firewood/pre-prune.db --after-db /var/lib/firewood/post-prune.db
   ```

   Matching roots print `State roots match: <hash>` and exit successfully. If
   the hashes differ, the command surfaces both digests so operators can halt
   rollout before distributing a corrupted checkpoint.
2. **Log the result alongside receipts.** Record the comparison output in the
   same incident or maintenance log entry that tracks pruning receipts. When the
   hashes differ, stop snapshot exports and rebuild the checkpoint before
   resuming pruning automation.
3. **Replay wallet indices across prover backends.** Run the wallet snapshot
   round-trip tests to confirm balances and nonces (the wallet-facing index) do
   not drift after pruning. Execute both backends to cover the plonky3 default
   and the `backend-rpp-stark` stack:

   ```bash
   RPP_PROVER_DETERMINISTIC=1 cargo test -p rpp-chain --locked --test pruning_cross_backend -- \
     wallet_snapshot_round_trip_default_backend

   RPP_PROVER_DETERMINISTIC=1 cargo test -p rpp-chain --locked --features backend-rpp-stark --test pruning_cross_backend -- \
     wallet_snapshot_round_trip_rpp_stark_backend
   ```

   Keep the outputs with the pruning receipts to document which prover stack
   validated the wallet index for the snapshot.

## 6. Benchmark pruning throughput

1. **Scheduled CI coverage.** The performance workflow now runs the pruning
   benchmark every day across both storage backends (standard and io-uring) and
   branch factors (16 and 256). Each matrix entry emits a metrics JSON and log
   artifact so regressions are visible in the nightly run.【F:.github/workflows/perf.yml†L64-L115】
2. **Local spot checks.** The pruning benchmark uses a fixed 3×32 workload with
   deterministic payloads and deferred sync to keep runs lightweight. Execute
   all four configurations when validating performance locally:

   ```bash
   cargo +nightly run -p firewood-benchmark -- pruning
   cargo +nightly run -p firewood-benchmark --features io-uring -- pruning
   cargo +nightly run -p firewood-benchmark --features branch_factor_256 -- pruning
   cargo +nightly run -p firewood-benchmark --features "io-uring branch_factor_256" -- pruning
   ```

   Metrics land at `FIREWOOD_PRUNING_OUTPUT` (defaults to
   `pruning-metrics.json`) and are validated against the baseline map in
   `benchmark/baselines/pruning.json`. Override
   `FIREWOOD_PRUNING_BASELINE` to compare against a freshly generated file when
   refreshing expectations.【F:benchmark/src/pruning.rs†L16-L124】【F:benchmark/src/pruning_baseline.rs†L9-L117】【F:benchmark/baselines/pruning.json†L1-L20】

## 7. Failure scenarios

### A. Repeated cycle failures

1. Check `cycle_total{result="failure"}` to confirm the failure streak.
2. Inspect recent warnings for `"pruning cycle failed"` to capture the error
   message and failing command.
3. Fetch the latest `PruningJobStatus` via `/snapshots/jobs` to review missing
   heights and the persisted plan location.
4. Start a snapshot stream via `POST /p2p/snapshots` and poll
   `GET /p2p/snapshots/<session>` to ensure downstream consumers can ingest
   the advertised plan. If the session errors or never verifies, the problem
   likely sits with the provider rather than the pruning worker.【F:rpp/rpc/src/routes/p2p.rs†L16-L102】【F:docs/network/snapshots.md†L1-L120】
5. If failures point to storage gaps, trigger the snapshot rebuild workflow
   from the change runbook and escalate to the storage team.

### B. Metrics gap or zeroed dashboards

1. Ensure telemetry is enabled and exporting (see telemetry section of the
   validator deployment playbook). A disabled exporter stops the pruning meter
   from emitting data.
2. Re-run a manual pruning cycle. A success should increment
   `cycle_total{reason="manual"}` and refresh histograms. If not, restart the
   node with telemetry overrides to rebuild the OTLP pipeline.
3. Capture the `/snapshots/jobs` payload to prove the worker still runs while
   telemetry is misconfigured.

### C. Service stuck in paused state

1. Review `pause_transitions{state="paused"}` to confirm when the pause was
   applied.
2. Issue a resume command (CLI override or configuration update) and watch for a
   `pause_transitions{state="resumed"}` increment within the next minute.
3. If the counter does not change, check the command queue depth and logs for
   rejected overrides, then restart the node with explicit `--pruning-resume` to
   unblock automation.

### D. Roll back a failed pruning attempt

1. Inspect the most recent `"pruning cycle failed"` warning to confirm the error
   class (for example `error=storage` when `persist_plan` cannot write the
   snapshot plan).【F:rpp/node/src/services/pruning.rs†L392-L400】
2. Clear the offending filesystem state. When the snapshot directory path points
   to a file or a volume mounted read-only, remove the blocking file or remount
   the volume with write permissions before retrying.
3. Retry a manual cycle and verify `cycle_total{result="failure"}` stops
   incrementing while `cycle_total{result="success"}` and `persisted_plan_total{persisted="true"}`
   increase again.【F:rpp/node/src/telemetry/pruning.rs†L25-L116】 Use `/snapshots/jobs`
   or the validator telemetry RPC to confirm a new pruning status is cached
   after recovery.【F:rpp/runtime/node.rs†L3200-L3215】
