# `simnet` container

The `simnet` image bundles the simulation orchestrator used to exercise RPP
nodes. It runs as a non-root user and exposes optional HTTP health probes for
orchestrators.

## Build

```sh
docker build -t simnet:local -f tools/simnet/Dockerfile .
```

## Environment

| Variable | Default | Description |
| --- | --- | --- |
| `SIMNET_HEALTH_ADDR` | `0.0.0.0:8090` | Address used by the internal health server. |
| `SIMNET_SCENARIO` | `/simnet/scenarios/small_world_smoke.ron` | Simulation scenario to execute. |
| `SIMNET_ARTIFACTS_DIR` | `/simnet/artifacts` | Directory for captured logs and artifacts. |
| `SIMNET_LOG_LEVEL` | `info` | Rust log level consumed by the binary. |
| `SIMNET_KEEP_ALIVE` | `true` | When `true`, keeps the process alive after scenarios finish. |

Refer to `.env.example` for the values consumed by `docker-compose.yml` when the
service is launched alongside `rpp-node`.

## Health

When `SIMNET_HEALTH_ADDR` is set, the container serves:

- `GET /health/live`
- `GET /health/ready`

## Sample run

```sh
docker run --rm \
  -p 8090:8090 \
  -e SIMNET_HEALTH_ADDR=0.0.0.0:8090 \
  -e SIMNET_SCENARIO=/simnet/scenarios/small_world_smoke.ron \
  simnet:local \
  --scenario /simnet/scenarios/small_world_smoke.ron \
  --artifacts-dir /simnet/artifacts \
  --keep-alive
```

## Flood profiles and reruns

Use the shipping templates under `config/examples/` to keep gossip bandwidth and
queue parameters aligned with the simnet flood scenarios:

* **Flood-safe (CI parity):** `config/examples/flood-safe.toml` keeps the
  128 msgs/s gossip cap and backpressure thresholds used in the partitioned
  flood drill.【F:config/examples/flood-safe.toml†L1-L124】 Point `RPP_CONFIG` at
  this file before launching the harness:

  ```sh
  RPP_CONFIG=config/examples/flood-safe.toml cargo run --locked --package simnet -- \
    --scenario tools/simnet/scenarios/partitioned_flood.ron \
    --artifacts-dir target/simnet/partitioned-flood
  ```

* **High-throughput (production parity):**
  `config/examples/high-throughput.toml` mirrors the validator gossip limits so
  production drills reuse the same mesh parameters.【F:config/examples/high-throughput.toml†L1-L132】
