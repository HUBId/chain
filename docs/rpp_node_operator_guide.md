# `rpp-node` Operator Guide

This guide documents the CLI tooling that ships with the repository. The
`rpp-node` binary hosts the runtime launchers for every supported mode and the
validator maintenance subcommands. No standalone `rpc-cli` tool exists in this
workspace—the shipped operator interface is the `rpp-node` CLI and the REST/RPC
workflows exposed by the running node.

> **Phase 2 update:** The `backend-plonky3` feature now enables the vendor
> Plonky3 prover/verifier pipeline. Production builds may target either the
> STWO (`prover-stwo`/`prover-stwo-simd`) or Plonky3 backend; only the
> deterministic mock backend remains blocked in release artefacts. Use the
> release pipeline checklist to verify that binaries are compiled with one of
> the production backends and that mock features are absent from build metadata.
> [`feature_guard.rs`](../rpp/node/src/feature_guard.rs) ·
> [`build_release.sh`](../scripts/build_release.sh) ·
> [`verify_release_features.sh`](../scripts/verify_release_features.sh) ·
> [`ensure_prover_backend`](../rpp/node/src/lib.rs) ·
> [Release pipeline checklist](../RELEASE.md#release-pipeline-checklist)
> · [Plonky3 runbook](./runbooks/plonky3.md)

## Build and install the CLI

Compile the binary with the release profile and select the backend that matches
the deployment tier. The build installs the multiplexer binary at
`target/release/rpp-node` and enables validator functionality required in
staging and production deployments.【F:docs/validator_quickstart.md†L24-L56】

```sh
# STWO backend
cargo build --release -p rpp-node --no-default-features --features prod,prover-stwo

# Plonky3 backend
cargo build --release -p rpp-node --no-default-features --features prod,backend-plonky3
```

The automated release pipeline exports `RPP_RELEASE_BASE_FEATURES` before
invoking `scripts/build_release.sh`. Point the variable to
`"prod,prover-stwo"`, `"prod,prover-stwo-simd"`, or `"prod,backend-plonky3"`
depending on the backend you intend to ship; the script always forces
`--no-default-features --features "$RPP_RELEASE_BASE_FEATURES"` so every
published artifact includes a production prover and the mock backend remains
disabled.【F:.github/workflows/release.yml†L115-L158】【F:scripts/build_release.sh†L1-L118】
Local builds should mirror the same flag set shown in
`scripts/build_release.sh` to avoid shipping binaries that fail at runtime due
to a missing production backend.

The helper `scripts/verify_release_features.sh` checks the compiled metadata and
fails when the mock prover slips into the feature list; run it as part of
pre-release validation. The compile-time guard mirrors this behaviour by
preventing `backend-plonky3` and `prover-mock` from being enabled at the same
time.【F:scripts/verify_release_features.sh†L1-L146】【F:rpp/node/src/feature_guard.rs†L1-L5】

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

### Plonky3 backend (Phase 2)

`backend-plonky3` aktiviert jetzt den produktiven Plonky3-Prover und -Verifier.
Die Wallet- und Node-Adapter erzeugen und prüfen Vendor-Beweise über dieselben
Traits wie das STWO-Backend, sodass Keygen-, Prover- und Verifier-Hooks im
Produktionspfad identisch orchestriert werden.【F:rpp/proofs/plonky3/prover/mod.rs†L19-L520】【F:rpp/proofs/plonky3/verifier/mod.rs†L1-L212】

Das [Plonky3-Runbook](./runbooks/plonky3.md) beschreibt den vollständigen
Operator-Workflow:

- Circuit-Caches vorbereiten (`rpp-node` legt Proving-/Verifying-Keys im
  Artefaktverzeichnis ab und spiegelt den Zustand über
  `backend_health.plonky3.*`).
- Proof-Generierung und -Verifikation überwachen (`rpp.runtime.proof.generation.*`
  und `rpp.runtime.proof.verification.*` mit Labels `backend="plonky3"`,
  `proof="transaction|state|pruning|consensus"`).
- Acceptance-Kriterien prüfen: die Phase‑2-Grenzwerte orientieren sich an den
  Messwerten aus `tools/simnet/scenarios/consensus_quorum_stress.ron` und sind in
  `performance/consensus_proofs.md` dokumentiert.

Das Nightly-Szenario `consensus-quorum-stress` treibt den Prover mit hoher
Validator- und Witness-Last sowie absichtlich manipulierten VRF-/Quorum-Daten
an. `scripts/analyze_simnet.py` wertet die JSON-Summary aus, bricht bei
Überschreitung der p95-Grenzen ab und meldet unerwartete Tamper-Erfolge. Die
Gegenüberstellung von Erfolgs- und Fehlerpfaden ist ebenfalls im Runbook
festgehalten.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:scripts/analyze_simnet.py†L1-L200】【F:docs/performance/consensus_proofs.md†L1-L160】

Grafana-Panels unter `docs/dashboards/consensus_proof_validation.json`
visualisieren diese Kennzahlen (Latenzen, Fehlerraten, Circuit-Cache-Größe) für
Plonky3 und werden vom CI-Dashboard-Lint überprüft. Binde die Panels in das
Produktions-Dashboard ein, um Phase‑2-Abnahmekriterien sichtbar zu machen.【F:docs/dashboards/consensus_proof_validation.json†L1-L120】

Kombiniere `backend-plonky3` nicht mit dem `prover-mock`-Feature; der Guard
erzwingt weiterhin die Trennung zwischen deterministischen Test-Fixtures und
produktiven Vendor-Artefakten.【F:rpp/node/src/feature_guard.rs†L1-L5】

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
