# Firewood Benchmark Docker Image

This document describes how to build and run the container image that packages the
`firewood-benchmark` binary for repeatable benchmarking runs.

## Build

From the repository root, build the image with the benchmark Dockerfile:

```sh
docker build -f benchmark/Dockerfile -t firewood-benchmark:latest .
```

The Dockerfile uses a nightly Rust toolchain builder stage with cached
workspace dependencies and produces a slim Debian runtime image that only
contains the compiled benchmark binary and its entrypoint helper.

## Run

The runtime stage is intended for batch execution with `docker run --rm`.
Pass the desired subcommand and flags just like the CLI:

```sh
docker run --rm firewood-benchmark:latest create
```

To continue with a workload after creation you can re-use the same image:

```sh
docker run --rm firewood-benchmark:latest tenkrandom
```

### Environment overrides

The entrypoint inspects a few environment variables and translates them to the
corresponding CLI flags before invoking the binary. All other arguments are
forwarded as-is, so you can still supply any additional flags directly.

| Environment variable | CLI flag | Description | Default |
| -------------------- | -------- | ----------- | ------- |
| `FIREWOOD_BENCH_DB_PATH` | `-d, --dbname` | RocksDB path for benchmark state (directory created on demand). | `/firewood/data/benchmark_db` |
| `FIREWOOD_BENCH_TELEMETRY` | `-e, --telemetry-server` | Enable telemetry when set to a truthy value (`true`, `1`, `yes`, `on`). | empty (disabled) |
| `FIREWOOD_BENCH_DURATION_MINUTES` | `-t, --duration-minutes` | Stop the benchmark after the given number of minutes. | empty (binary default of 65 minutes) |

Example: run the Zipf workload for two hours with telemetry enabled and a
custom database path.

```sh
docker run --rm \
  -e FIREWOOD_BENCH_TELEMETRY=true \
  -e FIREWOOD_BENCH_DURATION_MINUTES=120 \
  -e FIREWOOD_BENCH_DB_PATH=/firewood/data/custom.db \
  firewood-benchmark:latest zipf
```

### Persisting database artifacts

By default the database lives inside the container at `/firewood/data`. Mount a
host directory to preserve the database across runs or to inspect it locally:

```sh
mkdir -p benchmark-data

docker run --rm \
  -v "$(pwd)/benchmark-data:/firewood/data" \
  firewood-benchmark:latest create
```

Subsequent runs can mount the same host directory to continue using the same
state:

```sh
docker run --rm \
  -v "$(pwd)/benchmark-data:/firewood/data" \
  firewood-benchmark:latest tenkrandom
```

## Telemetry collector

Telemetry remains disabled by default. When `FIREWOOD_BENCH_TELEMETRY` is set to
true the benchmark will attempt to publish traces to a collector listening on
`http://127.0.0.1:4317` from within the container. Run the collector on the
host and publish the port if you want to receive telemetry data.
