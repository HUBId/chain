# `rpp-node` Operator Guide

This guide documents the CLI tooling that ships with the repository. The
`rpp-node` binary hosts the runtime launchers for every supported mode and the
validator maintenance subcommands. No standalone `rpc-cli` tool exists in this
workspace—the shipped operator interface is the `rpp-node` CLI and the REST/RPC
workflows exposed by the running node.

> **⚠️ Production warning:** The `backend-plonky3` feature remains an
> experimental stub and is not supported in production. The crate now emits a
> hard compile error whenever `backend-plonky3` is combined with the `prod` or
> `validator` feature sets, and the release packaging scripts abort if any
> Plonky3 alias appears in the requested feature list or the compiled metadata.
> Runtime launches for validator or hybrid roles additionally fail fast when the
> binary lacks the STWO backend, so production builds must continue to use the
> official STWO feature set (`--no-default-features --features
> prod,prover-stwo` or `prover-stwo-simd`). Use the release pipeline checklist
> to double-check these guards before publishing artefacts.
> [`feature_guard.rs`](../rpp/node/src/feature_guard.rs) ·
> [`build_release.sh`](../scripts/build_release.sh) ·
> [`verify_release_features.sh`](../scripts/verify_release_features.sh) ·
> [`ensure_prover_backend`](../rpp/node/src/lib.rs) ·
> [Release pipeline checklist](../RELEASE.md#release-pipeline-checklist)

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
published artifact includes the STWO prover.【F:.github/workflows/release.yml†L115-L158】【F:scripts/build_release.sh†L1-L104】
Local builds should mirror the same flag set shown in
`scripts/build_release.sh` (or swap in `prover-stwo-simd` on hosts that support
SIMD acceleration) to avoid shipping binaries that fail at runtime due to a
missing production backend.【F:scripts/build_release.sh†L1-L87】 Release builds
reject both the deterministic mock prover and the experimental Plonky3 stub: if
any `backend-plonky3` alias leaks into the feature list, `scripts/build_release.sh`
fails immediately with `error: backend-plonky3 is experimental and cannot be
enabled for release builds`, and the GitHub release workflow halts before any
artifacts are published.【F:.github/workflows/release.yml†L115-L158】【F:scripts/build_release.sh†L70-L160】

The crate mirrors that protection at compile time. Any attempt to combine the
experimental Plonky3 backend with the `prod` or `validator` features now emits a
hard compile error so production builds cannot accidentally depend on the stub
backend. Local experiments should target non-production profiles, for example
`cargo check -p rpp-node --no-default-features --features backend-plonky3` or
`cargo build -p rpp-node --features dev,backend-plonky3` when pairing the stub
with the developer toolchain.【F:rpp/node/src/feature_guard.rs†L1-L7】【F:rpp/node/Cargo.toml†L9-L21】

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

### Plonky3 backend scaffolding

Das Flag `--features backend-plonky3` aktiviert derzeit weiterhin das Stub-
Backend, das deterministische Fixtures und Telemetrie-Pfade bereitstellt, aber
noch keine vendor Plonky3-Proofs erzeugt oder verifiziert.【F:rpp/proofs/plonky3/prover/mod.rs†L201-L233】【F:rpp/proofs/plonky3/README.md†L1-L34】
Nutze diese Konfiguration, um die Runtime-/CLI-Flows und Dashboards gegen das
spätere Backend zu testen; produktive Rollouts bleiben blockiert, bis der
Vendor-Prover/-Verifier integriert ist. Das `/status/node` RPC exponiert bereits
`backend_health.plonky3.*`, jedoch basieren die Werte auf Stub-Läufen und
sollten nicht für Produktionsalarme herangezogen werden.【F:rpp/runtime/node.rs†L161-L220】【F:docs/interfaces/rpc/examples/validator_status_response.json†L1-L120】
Validator-UI und Metriken spiegeln dieselben Felder wider, dienen aktuell aber
als Vertragstests.【F:validator-ui/src/types.ts†L140-L220】 Der Plonky3-Lauf in
`scripts/test.sh` bleibt Teil der Matrix, verifiziert aber ausschließlich die
Stub-Implementierung, bis die echten Artefakte verfügbar sind.【F:scripts/test.sh†L1-L220】
Kompiliere die Stub-Pfade ausschließlich ohne die `prod`- oder `validator`-
Features, ansonsten schlägt der Build jetzt mit dem oben beschriebenen
Sicherheitsnetz fehl.【F:rpp/node/src/feature_guard.rs†L1-L7】

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
