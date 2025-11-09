# Validator UI Docker Image

This directory contains a multi-stage Docker build for producing a static image of the Validator UI and serving it with NGINX.

## Build-time configuration

The Vite configuration reads the `ASSET_BASE_PATH` environment variable during the build. This value becomes the `base` path for the generated assets and must end with a trailing slash (for example `/` or `/validator/`).

You can override the default (`/`) by passing a build argument:

```sh
docker build \
  --build-arg ASSET_BASE_PATH=/validator/ \
  -t validator-ui:latest \
  validator-ui
```

## Running the image

The runtime stage listens on port `8080` and includes a `/healthz` endpoint that is used by the container healthcheck.

```sh
docker run --rm -p 8080:8080 validator-ui:latest
```

If you built the image with a custom `ASSET_BASE_PATH`, make sure to serve the assets from the corresponding path (for example `/validator/`).

## Container behaviour

- Builder stage: `node:20-bullseye` with Corepack-enabled `pnpm` to produce the Vite build artifacts.
- Runtime stage: `nginx:alpine` serving the static files as a non-root user.
- Healthcheck: `http://127.0.0.1:8080/healthz` returns `ok` when NGINX is healthy.
