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
4. **Cancel cleanly when needed.** Use the validator CLI (`rpp-node validator snapshot cancel-pruning --config <cfg>`) or
   POST `/snapshots/cancel` to stop the current cycle without corrupting stored
   proofs. The handler returns a receipt, increments `rpp.node.pruning.cancellations_total`,
   and marks the cycle as `result="cancelled"` so a later run can resume from the
   persisted plan.【F:rpp/chain-cli/src/lib.rs†L255-L265】【F:rpp/rpc/src/routes/state.rs†L1-L26】【F:rpp/node/src/services/pruning.rs†L321-L370】【F:rpp/node/src/telemetry/pruning.rs†L25-L124】

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
| `rpp.node.pruning.cancellations_total` | Counter | `shard`, `partition` | Track operator-issued cancellations to correlate with `cycle_total{result="cancelled"}` before scheduling a resume run.【F:rpp/node/src/telemetry/pruning.rs†L25-L116】【F:rpp/node/src/services/pruning.rs†L321-L370】 |
| `rpp.node.pruning.pacing_total` | Counter | `shard`, `partition`, `reason`, `action`, `observed`, `limit` | Confirms whether pruning is yielding to CPU/IO pressure, mempool backlog, or timetoke credit queues and when it resumes.【F:rpp/node/src/telemetry/pruning.rs†L69-L140】【F:rpp/node/src/services/pruning.rs†L390-L456】 |
| `rpp.node.pruning.pacing_delay_ms` | Histogram | `shard`, `partition`, `reason`, `action` | Shows the backoff duration applied when pruning defers due to load.【F:rpp/node/src/telemetry/pruning.rs†L25-L124】【F:rpp/node/src/services/pruning.rs†L390-L456】 |

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
- Cross-shard references captured in the pruning receipts must line up with the
  canonical snapshot metadata before state sync proceeds. Validation rejects
  dangling `shard` / `partition` links so pruning cannot strand dependencies on
  other partitions.【F:rpp/node/src/state_sync/light_client.rs†L243-L352】【F:storage/src/snapshots/mod.rs†L11-L78】

### Pacing and backoff

- The pruning worker now throttles when CPU or disk IO exceed the pacing
  thresholds, when the combined mempool backlog (transactions, identities, and
  votes) exceeds the configured limit, or when uptime/timetoke proof queues grow
  past `timetoke_backlog_limit`. Each yield/resume is recorded in
  `rpp.node.pruning.pacing_total` and the backoff duration lands in
  `pacing_delay_ms`.【F:rpp/node/src/services/pruning.rs†L80-L205】【F:rpp/node/src/telemetry/pruning.rs†L105-L180】
- Tune pacing in `pruning.pacing.*` (CPU percent, IO bytes/sec, mempool and
  timetoke backlog limits, and `backoff_secs`). Lower limits protect block
  production and uptime credits; raising them speeds up pruning during quiet
  periods. Changes take effect without restarting the node when applied via the
  config reload path.【F:rpp/runtime/config.rs†L2618-L2665】【F:rpp/node/src/services/pruning.rs†L330-L420】

## 4. Verify pruning checkpoints

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

## 5. Benchmark pruning throughput

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

## 6. Failure scenarios

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
