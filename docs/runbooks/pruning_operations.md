# Pruning operations runbook

Use this runbook during routine monitoring of the pruning worker or when the
service degrades. It complements the [pruning change runbook](pruning.md) by
focusing on telemetry, dashboards, and failure-handling procedures.

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
| `rpp.node.pruning.cycle_total` | Counter | `reason`, `result` | Alert when scheduled cycles fail repeatedly or when manual runs dominate.【F:rpp/node/src/telemetry/pruning.rs†L31-L35】【F:rpp/node/src/services/pruning.rs†L391-L399】 |
| `rpp.node.pruning.cycle_duration_ms` | Histogram | `reason`, `result` | Plot p50/p95 to ensure rebuilds complete before the next cadence tick.【F:rpp/node/src/telemetry/pruning.rs†L25-L30】【F:rpp/node/src/services/pruning.rs†L391-L399】 |
| `rpp.node.pruning.persisted_plan_total` | Counter | `reason`, `persisted` | Detect when cycles stop emitting snapshot plans (possible storage regression).【F:rpp/node/src/telemetry/pruning.rs†L36-L40】【F:rpp/runtime/node.rs†L3200-L3202】 |
| `rpp.node.pruning.missing_heights` | Histogram | — | Surface sudden growth in backlog requiring manual hydration.【F:rpp/node/src/telemetry/pruning.rs†L41-L44】【F:rpp/runtime/node.rs†L3200-L3207】 |
| `rpp.node.pruning.stored_proofs` | Histogram | — | Validate that pruning proofs continue to sync to storage.【F:rpp/node/src/telemetry/pruning.rs†L46-L49】【F:rpp/runtime/node.rs†L3200-L3207】 |
| `rpp.node.pruning.retention_depth` | Histogram | — | Confirm override depth applied during incidents.【F:rpp/node/src/telemetry/pruning.rs†L51-L55】【F:rpp/node/src/services/pruning.rs†L356-L399】 |
| `rpp.node.pruning.pause_transitions` | Counter | `state` | Alert when the service is paused longer than the agreed maintenance window.【F:rpp/node/src/telemetry/pruning.rs†L56-L59】【F:rpp/node/src/services/pruning.rs†L356-L366】 |

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

## 4. Failure scenarios

### A. Repeated cycle failures

1. Check `cycle_total{result="failure"}` to confirm the failure streak.
2. Inspect recent warnings for `"pruning cycle failed"` to capture the error
   message and failing command.
3. Fetch the latest `PruningJobStatus` via `/snapshots/jobs` to review missing
   heights and the persisted plan location.
4. If failures point to storage gaps, trigger the snapshot rebuild workflow
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
