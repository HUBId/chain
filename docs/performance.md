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

The workflow fails if the reported throughput falls below the
`SMOKE_THROUGHPUT_THRESHOLD` environment variable (default `1.0` op/sec). Adjust
this threshold when we establish a stable baseline on the target hardware.

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
