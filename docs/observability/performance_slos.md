# Firewood performance service level objectives

This document codifies the latency, throughput, and resource objectives for the
`firewood-benchmark` scenarios that underpin the storage pipeline SLO. The
budgets are calculated from the default CLI parameters shipped with the
benchmark harness (`--batch-size 10000`, `--number-of-batches 1000`,
`--duration-minutes 65`, and a 1.5M entry cache). These defaults match the
datasets used during scalability testing and provide enough samples to produce
stable percentile estimates.

## Scenario targets

| Scenario        | Target TPS | p99 latency budget | CPU budget | Memory budget |
|-----------------|-----------:|-------------------:|-----------:|--------------:|
| `create`        |   ≥150,000 |             ≤120 ms |      ≤85 % |         ≤8 GiB |
| `tenk-random`   |    ≥90,000 |             ≤180 ms |      ≤85 % |         ≤8 GiB |
| `zipf`          |   ≥110,000 |             ≤200 ms |      ≤85 % |         ≤8 GiB |
| `single`        |    ≥60,000 |             ≤150 ms |      ≤75 % |         ≤6 GiB |

- **Target TPS.** Calculated as `(batches × batch_size) / runtime_seconds` for
the default configuration. Targets allocate a 10 % cushion relative to the
best sustained throughput observed when running on c6i.4xlarge instances.
- **Latency budget.** Based on the p99 proposal commit latency for the same
runs. Budgets include a 15 % headroom to absorb background maintenance tasks.
- **Resource budgets.** CPU and memory figures represent sustained utilisation
limits on the benchmark nodes. Spikes above the target are acceptable provided
the 95th percentile stays below the budget over a one-hour sliding window.

## Acceptable variance

Shorter validation runs (such as the CI check) down-scale the batch count and
duration to reduce the wall-clock cost. These runs inherit the targets above,
but regressions are only flagged when:

- Throughput drops by more than 5 % relative to the rolling baseline average.
- p99 latency rises by more than 10 % relative to the rolling baseline average.

This tolerance mirrors the guard rails enforced by
`scripts/ci/run_benchmarks.sh`. When a nightly benchmark is promoted to the
baseline cache it uses an exponential moving average with `α = 0.2`, making the
system responsive to sustained regressions while filtering out noise.

## Reporting

Each scenario emits JSON summaries under `target/perf-results/<scenario>.json`:

```json
{
  "scenario": "create",
  "throughput_tps": 154321.3,
  "latency_ms": {
    "p50": 28.4,
    "p95": 74.9,
    "p99": 110.2
  },
  "total_batches": 1000,
  "total_operations": 10000000,
  "total_duration_seconds": 64.8,
  "latency_samples": 1000
}
```

The CI summariser consumes these artifacts, compares them against the baseline,
and surfaces the deltas in `logs/perf/<git_sha>/summary.json`. Dashboards and
release checklists reference the same location.
