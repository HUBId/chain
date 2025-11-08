# Timetoke Replay Observability

The Timetoke replay path exports counters and histograms that cover ledger delta ingestion, replay success, and end-to-end latency. This document captures the service level objectives (SLOs), the reporting workflow, and instructions for querying the metrics directly.

## SLO thresholds

| Metric | Target | Notes |
| --- | --- | --- |
| Replay success rate (`timetoke_replay_success_total` vs. `timetoke_replay_failure_total`) | ≥ 99 % over a 7‑day rolling window | Aggregated from the counter increases over the past seven days. Failures include validation errors and mismatched commitments. |
| Replay latency p50 (`timetoke_replay_duration_ms`) | ≤ 5 000 ms | Ensures steady-state replay completes within one gossip interval.
| Replay latency p95 (`timetoke_replay_duration_ms`) | ≤ 60 000 ms | Guards recovery and slow peers.
| Replay latency p99 (`timetoke_replay_duration_ms`) | ≤ 120 000 ms | Caps pathological catches while still giving room for multi-epoch deltas.

The SLO windows align with the weekly acceptance cadence. Operators should verify the success-rate counter monotonicity and latency histogram buckets when diagnosing replay regressions.

## Scheduled report

The `nightly-simnet` workflow runs every day at 01:30 UTC and executes `cargo xtask report-timetoke-slo`, publishing the rendered markdown as the `timetoke-slo-report` artifact. The command prefers a Prometheus datasource, falling back to log archives for local dry-runs:

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

Reuse these snippets in Grafana dashboard panels or when cross-checking the CLI output with live Prometheus. When latency SLOs regress, correlate the histogram buckets with the `timetoke_replay_duration_ms_count` increase to ensure the exporter is healthy.
