# Firewood smoke benchmark

The Firewood repository now includes a lightweight performance smoke test that
can be executed locally and on a nightly GitHub Actions schedule. The goal of
this benchmark is to provide a fast signal that detects dramatic performance
regressions without requiring the full benchmarking stack.

## Running the smoke benchmark locally

```bash
rustup toolchain install nightly --profile minimal
cargo +nightly run -p firewood-benchmark -- smoke
```

The command uses the `firewood-benchmark` binary and produces a
`smoke-metrics.json` file in the current working directory. Set the
`FIREWOOD_SMOKE_OUTPUT` environment variable to choose a different output path.
The JSON payload includes:

- `batches` – number of batches committed during the run
- `batch_size` – number of operations per batch
- `total_operations` – total key/value writes that were executed
- `total_duration_ms` – wall-clock time in milliseconds
- `per_batch_ms` – individual batch timings
- `throughput_ops_per_sec` – aggregate throughput across the run

During local development you can increase the workload size with
`--number-of-batches` and `--batch-size`, but keep the defaults for parity with
CI.

## Scheduled performance workflow

The [`Performance smoke benchmark`](../.github/workflows/perf.yml) workflow runs
nightly and on demand. It builds the repository with the nightly Rust toolchain,
executes the smoke benchmark, and publishes three artifacts:

- `smoke-benchmark.log` captures the terminal output.
- `smoke-metrics.json` contains the structured metrics.
- `smoke-summary.md` summarizes the run for quick review.

The workflow parses `smoke-metrics.json`, compares the recorded metrics against
the JSON baseline embedded in `benchmark/baselines/smoke.json`, and fails if any
value lands outside of the accepted range. The baseline tracks throughput,
total runtime, and the 95th percentile batch latency so that we catch both
throughput drops and stalls.

The benchmark binary accepts an optional `FIREWOOD_SMOKE_BASELINE` environment
variable that points to an alternate baseline file. This is useful when testing
changes locally before updating the repository default.

## Grafana dashboards

The scheduled workflow also verifies that our performance dashboards remain in
sync with the Grafana instance. The check uses
[`tools/perf_dashboard_check.sh`](../tools/perf_dashboard_check.sh) together with
the manifest in [`docs/performance_dashboards.json`](./performance_dashboards.json)
to download each dashboard and compare the exported `schemaVersion` and
`version` fields against the committed JSON. The manifest also stores a
human-readable `version_tag` and SHA-256 checksum per export; CI revalidates
those values so that dashboard changes cannot merge without explicit review.
If Grafana is unreachable or a dashboard drifts, the workflow fails to surface
the issue.

To refresh the exports after editing a dashboard in Grafana:

1. Create an API token with `dashboard:read` access and set the environment
   variables `PERF_GRAFANA_URL` and `PERF_GRAFANA_API_KEY` to the Grafana base
   URL and token, respectively.
2. Run `tools/perf_dashboard_check.sh --verify` to confirm that credentials work
   and to check for drift without writing to disk.
3. Run `tools/perf_dashboard_check.sh --write` to download and overwrite the
   exports listed in `docs/performance_dashboards.json`.
4. Inspect the resulting diffs, commit the updated JSON files, and note the
   Grafana change in the pull request description.

## Updating the baseline

We keep the baseline intentionally tight (roughly ±15% from recent nightly
runs) so that the job detects meaningful regressions while tolerating routine
variance. To adjust the baseline:

1. Run `cargo +nightly run -p firewood-benchmark -- smoke` and inspect the
   generated `smoke-metrics.json`.
2. Edit `benchmark/baselines/smoke.json`, updating the `lower`/`upper` bounds
   for throughput, total duration, and `per_batch_p95_ms`.
3. Re-run the benchmark to confirm the `baseline.within_range` flags stay
   `true`.
4. Commit the updated JSON and include a link to the validating benchmark run in
   the pull request description.

Baseline adjustments must be reviewed by the performance on-call engineer or a
Firewood maintainer to ensure we are not masking a regression.

## Responding to alerts

When the scheduled workflow fails:

1. Download the `smoke-benchmark` artifact bundle.
2. Inspect `smoke-summary.md` to confirm whether throughput dropped or the
   benchmark crashed.
3. Compare the current numbers with previous successful runs. Significant
   increases in `total_duration_ms` or decreases in
   `throughput_ops_per_sec` indicate regressions.
4. Reproduce locally with `cargo +nightly run -p firewood-benchmark -- smoke`
   (optionally setting `RUST_LOG=debug` for more detail).
5. If the regression is confirmed, bisect recent changes in Firewood or Firewood
   Storage and open an issue summarizing the findings and linking to the failed
   workflow run.

For transient infrastructure problems (for example, network or dependency
fetching issues) rerun the workflow from the GitHub UI before escalating.
