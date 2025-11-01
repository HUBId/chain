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

The automated release pipeline exports
`RPP_RELEASE_BASE_FEATURES="prod,prover-stwo"` before invoking
`scripts/build_release.sh`, and the script always forces
`--no-default-features --features "$RPP_RELEASE_BASE_FEATURES"` so every
published artifact includes the STWO prover.【F:.github/workflows/release.yml†L115-L158】【F:scripts/build_release.sh†L1-L87】
Local builds should mirror the same flag set shown in
`scripts/build_release.sh` (or swap in `prover-stwo-simd` on hosts that support
SIMD acceleration) to avoid shipping binaries that fail at runtime due to a
missing production backend.【F:scripts/build_release.sh†L1-L87】

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

### Plonky3 experimental mode

The Plonky3 backend ships as a deterministic stub and must never be enabled in
production without explicit acknowledgement. To start a runtime that links the
Plonky3 feature (`--features backend-plonky3`), pass `--experimental-plonky3`
or set `CHAIN_PLONKY3_EXPERIMENTAL=1`. Otherwise the prover/verifier
construction panics with `plonky3 backend is experimental and provides no
cryptographic soundness`. The flag only unlocks development/testing flows and
emits a warning banner in `/status/node` so automation can detect the
experimental mode.【F:rpp/node/src/lib.rs†L347-L383】【F:rpp/proofs/plonky3/experimental.rs†L1-L76】【F:rpp/runtime/node.rs†L140-L188】【F:rpp/runtime/node.rs†L4719-L4741】

## Validator tooling

Invoke validator-specific helpers through `rpp-node validator`. Subcommands cover
VRF rotation, telemetry diagnostics, and uptime proof management, all backed by
the active node configuration.【F:rpp/node/src/main.rs†L48-L183】 Detailed
workflows—including sample invocations and expected output—live in the
[validator tooling guide](./validator_tooling.md).【F:docs/validator_tooling.md†L14-L137】

### Consensus proof metadata expectations

Finality proofs now encode the epoch/slot context, VRF proofs, and quorum
evidence roots inside the public inputs. Operators must ensure that
`consensus.metadata` in block production includes:

- `epoch`/`slot` counters that match the fork-choice state machine.
- Hex-encoded `quorum_bitmap_root` and `quorum_signature_root` digests from the
  aggregated vote sets.
- Matching pairs of `vrf_outputs` and `vrf_proofs` for each validator included
  in the certificate.

Missing or inconsistent values cause the verifier to reject the consensus proof
bundle, so double-check the witness payload when diagnosing failed block
imports.【F:docs/consensus/finality_proof_story.md†L1-L38】

Common tasks include:

```sh
# Rotate VRF keys using the configured secrets backend
rpp-node validator vrf rotate --config config/validator.toml

# Inspect collector health by querying the validator telemetry endpoint
rpp-node validator telemetry --rpc-url http://127.0.0.1:7070 --auth-token $RPP_RPC_TOKEN --pretty

# Submit and inspect uptime proofs via the validator RPC
rpp-node validator uptime submit --wallet-config config/wallet.toml --auth-token $RPP_RPC_TOKEN
rpp-node validator uptime status --rpc-url http://127.0.0.1:7070 --auth-token $RPP_RPC_TOKEN --json
```

State-sync and head monitoring rely on the public `/state-sync` RPC endpoints;
use `curl`/`wget` or similar tooling to consume the SSE stream and fetch
snapshot chunks as outlined in the validator tooling guide.【F:docs/validator_tooling.md†L53-L118】

## RPC authentication & rate limiting

Node RPC endpoints support optional bearer-token authentication and per-client
rate limiting. Supply the configured token with the `--auth-token` flag when
using CLI helpers or add an `Authorization: Bearer <token>` header to curl
requests.【F:docs/API_SECURITY.md†L10-L37】【F:rpp/node/src/main.rs†L101-L178】 The
flag must match the token configured for the active RPC endpoint; omit it only
when authentication is disabled. Secure configurations should rotate tokens
alongside other secrets and audit usage via reverse-proxy logs.

Expose the RPC to browser dashboards by setting `network.rpc.allowed_origin` in
configuration. Use `--rpc-allowed-origin` for one-off overrides (pass an empty
string to clear the allow-list) and restart without the flag to fall back to the
profile defaults.【F:docs/API_SECURITY.md†L38-L58】

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
