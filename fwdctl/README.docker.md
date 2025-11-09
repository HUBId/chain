# `fwdctl` container

The `fwdctl` image wraps the Firewood control-plane CLI so that it can be
scheduled as a cron-style job or supporting service next to an `rpp-node`
deployment.

## Build

```sh
docker build -t fwdctl:local -f fwdctl/Dockerfile .
```

## Environment

| Variable | Default | Description |
| --- | --- | --- |
| `FWDCTL_HEALTH_PORT` | `8080` | Port that serves the `/health/ready` probe. |

Additional runtime parameters (database path, log level, etc.) are provided via
CLI flags. See `.env.example` and `docker-compose.yml` for a complete example of
how the container is invoked with persistent volume mounts.

## Health

- `GET /health/ready`

## Sample run

```sh
docker run --rm \
  -p 8081:8080 \
  -e FWDCTL_HEALTH_PORT=8080 \
  -v fwdctl-data:/home/fwdctl/data \
  fwdctl:local \
  --log-level info check --db /home/fwdctl/data/firewood.db --hash-check
```
