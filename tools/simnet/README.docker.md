# Simnet Docker Usage

This image packages the `simnet` orchestrator together with the bundled example
scenarios so that test networks can be launched without needing the full source
checkout inside the container.

## Building the image

From the repository root:

```sh
docker build -t simnet -f tools/simnet/Dockerfile .
```

The Dockerfile follows the shared multi-stage pattern used across the project:
Rust code is compiled in a builder stage while the runtime stage contains only
runtime dependencies, the compiled binary, and the bundled scenarios. The
runtime user is non-root to help harden the container by default.

## Running scenarios

To run one of the included scenarios:

```sh
docker run --rm \
  --name simnet-demo \
  simnet \
  --scenario /simnet/scenarios/small_world_smoke.ron
```

Mount a host directory to `/simnet/artifacts` (or use `--artifacts-dir`) when
you want to preserve generated artifacts outside the container:

```sh
docker run --rm \
  -v "$(pwd)/artifacts:/simnet/artifacts" \
  simnet \
  --scenario /simnet/scenarios/small_world_smoke.ron \
  --artifacts-dir /simnet/artifacts
```

## Optional health server

Set `SIMNET_HEALTH_ADDR` to enable the lightweight HTTP health server while the
orchestrator is running:

```sh
docker run --rm \
  -e SIMNET_HEALTH_ADDR=0.0.0.0:8080 \
  -p 8080:8080 \
  simnet \
  --scenario /simnet/scenarios/small_world_smoke.ron
```

When enabled, the container responds with `200 OK` on `/health/live` and
`/health/ready` while the orchestrator is active. This is useful when the
orchestrator is expected to supervise long-lived simulations or be managed by a
container orchestrator that polls for liveness and readiness.

For short-lived batch runs that start, execute a scenario, and exit immediately,
the health server usually is not necessary because the container terminates
once the workload completes.
