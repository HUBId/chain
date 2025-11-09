# `validator-ui` container

The `validator-ui` image serves the compiled validator dashboard through nginx.
It is intended to run alongside the `rpp-node` API and consumes the same
configuration used in the local compose workflow.

## Build

```sh
docker build -t validator-ui:local -f validator-ui/Dockerfile --build-arg ASSET_BASE_PATH=/ .
```

## Environment and build arguments

| Name | Default | Scope | Description |
| --- | --- | --- | --- |
| `ASSET_BASE_PATH` | `/` | build arg + env | Base path injected into the built assets and nginx config. |
| `VITE_API_BASE_URL` | `http://rpp-node:7070` | runtime env | Upstream API used by the frontend at runtime. |

The compose and Kubernetes samples source these values from `.env.example` to
keep local and cluster deployments aligned.

## Health

- `GET /healthz`

## Sample run

```sh
docker run --rm \
  -p 8082:8080 \
  -e VITE_API_BASE_URL=http://127.0.0.1:7070 \
  validator-ui:local
```
