# `rpp-node` container

The `rpp-node` image packages the Rust Private Payments node binary with a thin
Debian runtime. It exposes the public RPC interface and readiness probes used by
Compose and Kubernetes samples in this repository.

## Build

```sh
docker build -t rpp-node:local -f rpp/node/Dockerfile .
```

## Environment

| Variable | Default | Description |
| --- | --- | --- |
| `RPP_NODE_RPC_ADDR` | `0.0.0.0` | Host/interface bound by the RPC listener. |
| `RPP_NODE_RPC_PORT` | `7070` | TCP port for HTTP RPC, readiness, and liveness probes. |

Configuration files such as `config/node.toml` can be mounted into the
container. See `.env.example` for values wired into `docker-compose.yml`.

## Health

The container publishes the following HTTP endpoints from the RPC listener:

- `GET /health/live`
- `GET /health/ready`

## Sample run

```sh
docker run --rm \
  -p 7070:7070 \
  -e RPP_NODE_RPC_ADDR=0.0.0.0 \
  -e RPP_NODE_RPC_PORT=7070 \
  -v "$(pwd)/config/node.toml:/app/config/node.toml:ro" \
  rpp-node:local \
  node --config /app/config/node.toml --log-level info
```
