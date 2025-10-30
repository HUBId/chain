# Pruning observability

This guide describes the Grafana panels and alert rules recommended for the
pruning worker. Metrics originate from the node telemetry instrumentation and
share the `rpp.node.pruning.*` prefix.【F:rpp/node/src/telemetry/pruning.rs†L25-L116】

## Key metrics

- **`rpp.node.pruning.cycle_total`** – counter labelled by `reason` and `result`
  that increments on every pruning attempt. Use stacked visualisations to spot
  growing failure counts versus scheduled runs.【F:rpp/node/src/telemetry/pruning.rs†L31-L35】【F:rpp/node/src/services/pruning.rs†L391-L399】
- **`rpp.node.pruning.cycle_duration_ms`** – histogram capturing cycle runtime in
  milliseconds. Plot p50/p95 to ensure runs finish before the cadence interval.【F:rpp/node/src/telemetry/pruning.rs†L25-L30】【F:rpp/node/src/services/pruning.rs†L391-L399】
- **`rpp.node.pruning.persisted_plan_total`** – counter labelled by `persisted`
  to confirm whether the reconstruction plan hit disk for each cycle.【F:rpp/node/src/telemetry/pruning.rs†L36-L40】【F:rpp/runtime/node.rs†L3200-L3202】
- **`rpp.node.pruning.missing_heights`** – histogram with the number of heights
  still missing after a cycle. Any sustained increase signals storage drift.【F:rpp/node/src/telemetry/pruning.rs†L41-L44】【F:rpp/runtime/node.rs†L3200-L3207】
- **`rpp.node.pruning.stored_proofs`** – histogram showing how many pruning
  proofs synchronised to storage per cycle.【F:rpp/node/src/telemetry/pruning.rs†L46-L49】【F:rpp/runtime/node.rs†L3200-L3207】
- **`rpp.node.pruning.retention_depth`** – histogram recording the effective
  retention depth applied to each run; build singe-stat panels to catch override
  mistakes.【F:rpp/node/src/telemetry/pruning.rs†L51-L55】【F:rpp/node/src/services/pruning.rs†L356-L399】
- **`rpp.node.pruning.pause_transitions`** – counter labelled by `state` that
  increments whenever operators pause or resume automation.【F:rpp/node/src/telemetry/pruning.rs†L56-L59】【F:rpp/node/src/services/pruning.rs†L356-L366】

## Suggested dashboard panels

1. **Cycle outcome overview** – stacked bar chart of
   `sum by (reason, result)(increase(rpp.node.pruning.cycle_total[5m]))` to
   contrast manual versus scheduled runs and highlight failures.
2. **Cycle duration percentiles** – percentile panels based on
   `histogram_quantile(0.95, rate(rpp.node.pruning.cycle_duration_ms_bucket[15m]))`
   to ensure jobs complete before the next cadence tick.
3. **Missing heights trend** – single-stat or line chart fed by
   `last_over_time(rpp.node.pruning.missing_heights_sum[5m])` to visualise backlog
   growth.
4. **Pause state timeline** – heatmap using
   `increase(rpp.node.pruning.pause_transitions{state="paused"}[1h])` and
   `increase(...{state="resumed"}[1h])` to document maintenance windows.

## Example alerts

- **Scheduled cycle failure streak:** trigger when
  `increase(rpp.node.pruning.cycle_total{reason="scheduled",result="failure"}[15m]) >= 3`.
  Pair the alert with the most recent `/snapshots/jobs` payload so on-call staff
  can review the missing heights immediately.
- **Plan persistence halted:** fire if
  `increase(rpp.node.pruning.persisted_plan_total{persisted="true"}[30m]) == 0`
  while `increase(rpp.node.pruning.cycle_total{result="success"}[30m]) > 0`.
- **Unexpected pause:** notify when
  `increase(rpp.node.pruning.pause_transitions{state="paused"}[10m]) > 0` without
  a matching resume within the same window.

Combine the alerts with log streaming for `"pruning cycle failed"` to accelerate
triage.【F:rpp/node/src/services/pruning.rs†L393-L400】
