# Timetoke Replay Observability

The Timetoke replay path exports counters and histograms that cover ledger delta ingestion, replay success, and end-to-end latency. This document captures the service level objectives (SLOs), the reporting workflow, and instructions for querying the metrics directly. The final replay metrics—success rate and stalled-detector status—tie these signals together for incident response and audit evidence.

## SLO thresholds

| Metric | Target | Notes |
| --- | --- | --- |
| Replay success rate (`timetoke_replay_success_total` vs. `timetoke_replay_failure_total`) | ≥ 99 % over a 7‑day rolling window | Aggregated from the counter increases over the past seven days. Failures include validation errors and mismatched commitments. |
| Replay latency p50 (`timetoke_replay_duration_ms`) | ≤ 5 000 ms | Ensures steady-state replay completes within one gossip interval.
| Replay latency p95 (`timetoke_replay_duration_ms`) | ≤ 60 000 ms | Guards recovery and slow peers.
| Replay latency p99 (`timetoke_replay_duration_ms`) | ≤ 120 000 ms | Caps pathological catches while still giving room for multi-epoch deltas.

The SLO windows align with the weekly acceptance cadence. Operators should verify the success-rate counter monotonicity and latency histogram buckets when diagnosing replay regressions. Replay exporters also expose stall detectors that back the alerting rules:

- `timetoke_replay_last_attempt_timestamp` / `timetoke_replay_last_success_timestamp` provide the raw Unix timestamps for cursors. Combine with `time() - metric` to calculate the current age in PromQL.
- `timetoke_replay_seconds_since_success` offers a direct helper gauge for dashboards.
- `timetoke_replay_stalled{threshold="warning"|"critical"}` flips to `1` once 60 s / 120 s pass without a successful replay.

### Final replay metrics

Operators consume the replay counters above through two derived, “final” gauges that appear in dashboards, reports, and CLI summaries. They consolidate the raw counters and stall detectors into auditing-friendly views and ship with metadata labels (`threshold`, `window`) so dashboards can render the raw timestamps and the derived final state side by side:

- **Replay success rate (`timetoke_replay_success_rate`).** A rolling ratio of `success_total` vs. `failure_total` normalised to `0.0 – 1.0`. The nightly report multiplies this value by 100 to express the 7‑Tage-Erfolgsquote. Alert thresholds mirror the ≥ 99 % SLO, and the CLI renders both the percentage and the raw counter deltas so auditors can reconcile local PromQL queries. The gauge is computed server side via:

  ```promql
  clamp_max(
    sum(increase(timetoke_replay_success_total[7d])) /
    clamp_min(sum(increase(timetoke_replay_success_total[7d])) + sum(increase(timetoke_replay_failure_total[7d])), 1),
    1
  )
  ```

- **Replay stalled detector (`timetoke_replay_stalled_final{threshold}`).** Aggregates the warning/critical states into a single flag per threshold. It remains `0` while replay succeeds within the respective 60 s / 120 s windows and flips to `1` once the underlying `timetoke_replay_stalled{threshold}` signals a breach. Dashboards label the metric “Replay stalled (final)” to distinguish it from the per-attempt timestamps. The helper derives from the exporter by taking the max over the window:

  ```promql
  max_over_time(timetoke_replay_stalled{threshold="warning"}[1m])
  ```

  (swap `threshold` to `critical` for the 120 s window). In alerts and runbooks reference the *final* gauge so responders immediately see whether the stall is still active.

## Scheduled report

The `nightly-simnet` workflow runs every Monday at 01:30 UTC and executes `cargo xtask report-timetoke-slo`, publishing the rendered markdown as the `timetoke-slo-report` artifact. The freshness gate allows reports up to seven days old so that weekly cadence remains compliant with the merge checks. The command prefers a Prometheus datasource, falling back to log archives for local dry-runs:

```bash
cargo xtask report-timetoke-slo \
  --prometheus-url https://prometheus.example.net \
  --bearer-token "$TIMETOKE_PROMETHEUS_TOKEN" \
  --output timetoke-slo-report.md
```

Environment variables provide non-interactive configuration when running in CI:

- `TIMETOKE_PROMETHEUS_URL` / `PROMETHEUS_URL`
- `TIMETOKE_PROMETHEUS_BEARER` / `PROMETHEUS_BEARER_TOKEN`
- `TIMETOKE_METRICS_LOG` (path to JSONL metrics exported with `timetoke_replay_*` fields)

For offline validation the repository ships a fixture (`docs/observability/examples/timetoke_metrics.jsonl`). Point the command at the file to generate a sample report:

```bash
cargo xtask report-timetoke-slo \
  --metrics-log docs/observability/examples/timetoke_metrics.jsonl
```

The generated markdown lists the observation window, success totals, percentile latency, and whether each SLO passed. The Nightly workflow uploads the rendered report (`timetoke-slo-report.md`) so auditors can trace the rolling seven-day window.

## Manual queries

The report wrapper issues the following PromQL queries:

- `sum(increase(timetoke_replay_success_total[7d]))`
- `sum(increase(timetoke_replay_failure_total[7d]))`
- `histogram_quantile(0.50, sum(rate(timetoke_replay_duration_ms_bucket[7d])) by (le))`
- `histogram_quantile(0.95, sum(rate(timetoke_replay_duration_ms_bucket[7d])) by (le))`
- `histogram_quantile(0.99, sum(rate(timetoke_replay_duration_ms_bucket[7d])) by (le))`

Reuse these snippets in Grafana dashboard panels or when cross-checking the CLI output with live Prometheus. When latency SLOs regress, correlate the histogram buckets with the `timetoke_replay_duration_ms_count` increase to ensure the exporter is healthy. The derived gauges above use the same counter windows, so you can recompute them manually for postmortem evidence:

```promql
timetoke_replay_success_rate
timetoke_replay_stalled_final{threshold}
```

## CLI quick check

Validators expose the aggregated replay telemetry via `GET /observability/timetoke/replay`. The `rpp-node snapshot replay status` helper wraps the call, prints counters and percentiles, and exits with a non-zero status whenever the 99 % success-rate, the 60 s / 120 s stall thresholds, or the documented latency targets are violated:

```bash
rpp-node snapshot replay status \
  --config /etc/rpp/validator.toml \
  --rpc-url https://validator.example.net:7070 \
  --format table
```

Key behaviour:

- **Final replay metrics first.** The command renders `Replay success rate: 99.7 % (success=12345, failure=32)` and `Replay stalled (warning|critical): 0` before listing percentile latencies so responders can stop once the final gauges are green.
- **Context for auditors.** The raw counter deltas, Prometheus window (`window=7d`), and stall thresholds are echoed inline to reconcile dashboards with the CLI output.
- **Fail-fast exit codes.** `0` for healthy runs, `10` when the success rate drops below 99 %, `20`/`21` for warning/critical stall detections, and `30` when latency percentiles violate their SLOs.

During incidents paste the command output into the log and escalate via the [Timetoke failover runbook](../runbooks/timetoke_failover.md) if any exit code other than `0` is returned. The helper is safe to run repeatedly; it issues a single RPC call and does not mutate validator state.
