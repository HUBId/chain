# Performance dashboards

Two Grafana dashboards complement the Firewood performance SLOs:

- [`performance_overview.json`](performance_overview.json) plots the throughput
  and latency trend lines for every benchmark scenario. Panels use the
  `firewood_benchmark_*` Prometheus metrics exported by the CI summariser after
  each run of `scripts/ci/run_benchmarks.sh`.
- [`performance_capacity.json`](performance_capacity.json) joins the JSON
  summary artifacts (served via the `perf-artifacts` data source) with CPU and
  memory utilisation measurements so operators can visualise how far the latest
  results are from the documented budgets.

To import the dashboards:

1. Navigate to the Grafana instance used for Firewood observability.
2. Open **Dashboards → Import** and upload the JSON exports above.
3. Update the data source selectors:
   - Point `prometheus` panels at the cluster collecting
     `firewood_benchmark_*` metrics (the default performance Prometheus
     deployment).
   - Configure the `perf-artifacts` JSON data source to read from the HTTP
     endpoint that serves `logs/perf/<git_sha>/summary.json` (the nightly job
     uploads the files to object storage under `/firewood/perf/summary`).
4. Save the dashboards in the `Performance` folder so they surface in the
   release checklist.

The [performance SLOs](../observability/performance_slos.md) describe how the
budgets were derived and the tolerances used by CI. Both dashboards link back to
those thresholds via panel descriptions.
