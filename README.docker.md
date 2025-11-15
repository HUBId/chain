# Container Images and Local Orchestration

This repository ships a small set of Dockerfiles that make it easy to run the
Rust Private Payments (RPP) node, supporting tooling, and the validator UI in
containerized environments. All runtime images are distilled down to minimal
Debian or Alpine layers and default to non-root users to improve the security
posture of demo deployments.

> 📘 **Wallet Phase 4 operators** – When building wallet-centric containers, read
> [docs/wallet_phase4_advanced.md](docs/wallet_phase4_advanced.md) to understand
> which capabilities require cargo feature flags at image build time versus
> configuration toggles at runtime. For example, mTLS/RBAC enforcement mandates
> compiling with `wallet_rpc_mtls`, while watch-only and backup schedulers live
> entirely under `[wallet.watch_only]` and `[wallet.backup]`. Failing to enable
> the correct feature flag before baking the image will leave the corresponding
> configuration unusable.

## Image matrix

| Image | Dockerfile | Runtime user | Purpose |
| --- | --- | --- | --- |
| `rpp-node` | [`rpp/node/Dockerfile`](rpp/node/Dockerfile) | `app` (UID auto assigned) | Runs the full RPP node binary and exposes RPC + health endpoints. |
| `simnet` | [`tools/simnet/Dockerfile`](tools/simnet/Dockerfile) | `simnet` (UID auto assigned) | Drives lightweight network simulations against a node. |
| `fwdctl` | [`fwdctl/Dockerfile`](fwdctl/Dockerfile) | `fwdctl` (UID 10001) | Firewood control plane CLI packaged for cron/job execution. |
| `validator-ui` | [`validator-ui/Dockerfile`](validator-ui/Dockerfile) | `app` (nginx unprivileged) | Serves the compiled validator UI assets behind nginx. |

Each image is built from a multi-stage Dockerfile that keeps the runtime layer
focused on the compiled artifact and the minimum utilities required for health
checks.

## Building images

All images can be built locally with stock Docker:

```sh
docker build -t rpp-node:local -f rpp/node/Dockerfile .
docker build -t simnet:local -f tools/simnet/Dockerfile .
docker build -t fwdctl:local -f fwdctl/Dockerfile .
docker build -t validator-ui:local -f validator-ui/Dockerfile .
```

Build arguments and environment variables used during the build are documented
next to each Dockerfile in the accompanying `README.docker.md` files.

## Smoke testing with Docker Compose

A ready-to-run [`docker-compose.yml`](docker-compose.yml) orchestrates the full
stack for local testing. To exercise the full workflow:

1. Copy the sample environment configuration:
   ```sh
   cp .env.example .env
   ```
2. Build and launch the stack:
   ```sh
   docker compose up --build
   ```
3. Enable optional tooling (for example the `fwdctl` service) by adding the
   matching profile flag:
   ```sh
   docker compose --profile tooling up --build
   ```

The compose file wires up health checks between services so that dependent
containers only start after their upstreams become ready. The sample `.env`
values expose ports on the host, write persistent state to named volumes, and
select the default simulation scenario.

When the stack is running you can verify the HTTP probes exposed by each
container:

- `rpp-node`: `http://127.0.0.1:7070/health/live` and `/health/ready`
- `simnet`: `http://127.0.0.1:8090/health/live` and `/health/ready`
- `fwdctl`: `http://127.0.0.1:8081/health/ready`
- `validator-ui`: `http://127.0.0.1:8082/healthz`

## Kubernetes and advanced deployments

Operators targeting Kubernetes can start from the example manifests under
[`deploy/k8s/`](deploy/k8s/). The deployment manifest shows how to surface the
same HTTP liveness and readiness probes used in the compose setup, while the
companion Service exposes the selected RPC port inside the cluster. Tailor the
resource requests and probe thresholds to match your target environment before
applying them.

For cloud or production deployments, ensure that you propagate the environment
variables outlined in `.env.example`, bind persistent volumes for stateful data
(e.g. the `rpp-node` data directory), and review any secret material that should
be injected as Kubernetes Secrets or Docker runtime secrets rather than hard
coding them into images.

## Security posture

Every runtime image adheres to the following practices:

- **Non-root default users.** Each container drops privileges to an application
  user (`app`, `simnet`, or `fwdctl`) before executing the entrypoint.
- **Minimal runtime layers.** Only the compiled binaries and the tooling needed
  for health checks (such as `curl`, `wget`, or `ca-certificates`) are included.
- **HTTP health endpoints.** Consistent health probes allow orchestrators to
  gate traffic on readiness and watch for liveness regressions.

If additional capabilities or packages are required for your deployment, prefer
extending the images with new layers rather than editing the base Dockerfiles so
that local smoke tests remain aligned with production.
