# `rpp-node` Operator Guide

This guide documents the CLI tooling that ships with the repository. The
`rpp-node` binary hosts the runtime launchers for every supported mode and the
validator maintenance subcommands. No standalone `rpc-cli` tool exists in this
workspace—the shipped operator interface is the `rpp-node` CLI and the REST/RPC
workflows exposed by the running node.

## Build and install the CLI

Compile the binary with the release profile and the production feature set. The
build installs the multiplexer binary at `target/release/rpp-node` and enables
validator functionality required in staging and production deployments.【F:docs/validator_quickstart.md†L24-L56】

```sh
cargo build --release -p rpp-node --no-default-features --features prod,prover-stwo
```

Keep the repository cloned on the host to rebuild quickly when upgrades ship.

## Runtime launchers

The `rpp-node` binary dispatches to four runtime modes and accepts the shared
runtime options (configuration paths, telemetry overrides, dry runs, log
formatting, and networking flags).【F:rpp/node/src/main.rs†L28-L75】【F:rpp/node/src/lib.rs†L35-L314】

```text
rpp-node node [runtime options]
rpp-node wallet [runtime options]
rpp-node hybrid [runtime options]
rpp-node validator [runtime options] [validator subcommand]
```

Pass `--config`/`--wallet-config` to target custom configuration files or rely
on the precedence chain described in the validator quickstart when the defaults
are sufficient.【F:docs/validator_quickstart.md†L62-L111】 Add `--dry-run` to
validate configuration without starting long-running tasks; the CLI exits after
bootstrap so operators can gate deployments in CI.【F:docs/validator_quickstart.md†L195-L210】

## Validator tooling

Invoke validator-specific helpers through `rpp-node validator`. Subcommands cover
VRF rotation, telemetry diagnostics, and uptime proof management, all backed by
the active node configuration.【F:rpp/node/src/main.rs†L48-L183】 Detailed
workflows—including sample invocations and expected output—live in the
[validator tooling guide](./validator_tooling.md).【F:docs/validator_tooling.md†L14-L137】

Common tasks include:

```sh
# Rotate VRF keys using the configured secrets backend
rpp-node validator vrf rotate --config config/validator.toml

# Inspect collector health by querying the validator telemetry endpoint
rpp-node validator telemetry --rpc-url http://127.0.0.1:7070 --pretty

# Submit and inspect uptime proofs via the validator RPC
rpp-node validator uptime submit --wallet-config config/wallet.toml
rpp-node validator uptime status --rpc-url http://127.0.0.1:7070 --json
```

The light-client helpers (`rpp-node light-client ...`) documented alongside the
validator utilities assist with state-sync and head monitoring for downstream
operators.【F:docs/validator_tooling.md†L53-L105】

## RPC authentication & rate limiting

Node RPC endpoints support optional bearer-token authentication and per-client
rate limiting. Supply the configured token with the `--auth-token` flag when
using CLI helpers or add an `Authorization: Bearer <token>` header to curl
requests.【F:docs/API_SECURITY.md†L10-L37】【F:rpp/node/src/main.rs†L101-L178】 Secure
configurations should rotate tokens alongside other secrets and audit usage via
reverse-proxy logs.

When automation calls the REST endpoints directly, reuse the same tokens and
respect the configured request limits. A `429` response indicates that the node's
rate limiter rejected the request; retry with exponential backoff or throttle
callers as described in the [deployment & observability playbook](./deployment_observability.md).【F:docs/deployment_observability.md†L1-L61】

## Example RPC workflows

Automation typically interacts with the node via authenticated HTTP requests.
The pruning runbook outlines the snapshot APIs, including example `curl`
invocations that enqueue pruning work and inspect receipts.【F:docs/runbooks/pruning.md†L1-L102】
Additional operational runbooks cover startup validation, telemetry wiring, and
upgrade procedures when rolling new binaries into service.【F:docs/runbooks/startup.md†L1-L40】【F:docs/runbooks/observability.md†L1-L120】【F:docs/runbooks/upgrade.md†L1-L60】

Pair this guide with the validator quickstart and troubleshooting references to
fully provision and maintain a production node.【F:docs/validator_quickstart.md†L1-L238】【F:docs/validator_troubleshooting.md†L1-L140】
