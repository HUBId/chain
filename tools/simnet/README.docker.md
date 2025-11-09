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
