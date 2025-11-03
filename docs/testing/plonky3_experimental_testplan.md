# Plonky3 Production Validation Checklist

The experimental scaffolding from Phase 1 has been replaced by the production
Plonky3 prover/verifier stack. This checklist records the fixtures, commands and
signals that must succeed before Phase 2 sign-off and during ongoing
operations. Pair it with the [Plonky3 runbook](../runbooks/plonky3.md) and the
[Phase 2 acceptance checklist](../runbooks/phase2_acceptance.md) when preparing
an environment for audit or release promotion.

## 1. Prerequisites

### 1.1 Setup artefacts

Plonky3 proving/verifying keys are shipped as JSON descriptors in
`config/plonky3/setup/`. Each entry embeds (or references) a gzip-compressed
base64 blob for the circuit’s verifying and proving key; the helper script can
regenerate them from the upstream toolchain or ingest pre-built binaries when
keys rotate.【F:config/plonky3/setup/README.md†L1-L41】 The node refuses to start
if any required circuit (transaction, state, pruning, uptime, consensus or
recursive) is missing, duplicated, or cannot be decoded – the loader raises a
`ChainError::Crypto` with the offending circuit name and logs the failure before
returning control to the caller.【F:rpp/proofs/plonky3/crypto.rs†L300-L420】

**Operator actions**

1. Ensure the JSON fixtures for all circuits are present and contain the
   expected compression/encoding metadata.
2. Commit regenerated artefacts alongside the blake3 hashes emitted by
   `scripts/generate_plonky3_artifacts.py` or store the binary files referenced
   via `@`/`file:` paths in the release bundle.【F:config/plonky3/setup/README.md†L11-L33】
3. When rotating keys, re-run the `xtask proof-metadata` report to capture new
   size and hash summaries for audit trails.【F:xtask/src/main.rs†L200-L266】

### 1.2 Feature flags

Activate the vendor backend with the `backend-plonky3` feature on every
component that produces or verifies proofs. The compile-time guard prevents the
mock prover from being enabled simultaneously, so the backend must be compiled
with either the default feature set or explicit production flags such as
`--no-default-features --features prod,backend-plonky3`. Attempting to combine
`backend-plonky3` with `prover-mock` aborts compilation with a dedicated error
message, and the feature-matrix tests assert that the guard remains active.【F:rpp/node/src/feature_guard.rs†L1-L7】【F:rpp/node/tests/feature_matrix.rs†L1-L40】

When using `cargo xtask`, propagate the feature set via environment variables:
`XTASK_NO_DEFAULT_FEATURES=1` to drop defaults and `XTASK_FEATURES="prod,backend-plonky3"`
so every delegated `cargo test`/`cargo run` invocation exercises the production
backend.【F:xtask/src/main.rs†L1-L140】

### 1.3 Runtime configuration

The node exposes Plonky3 prover telemetry through the `/status/node` snapshot.
Successful proofs increment `proofs_generated`, failures populate
`last_error.message`, and the cache size reflects how many circuit contexts were
compiled at runtime.【F:rpp/runtime/node.rs†L4870-L4888】【F:rpp/proofs/plonky3/prover/mod.rs†L90-L248】
Include these fields in release evidence; unexpected gaps usually indicate
missing setup artefacts or feature flags.

## 2. Prover/verifier pipeline

### 2.1 Validate setup artefacts and consensus primitives

Run the package-level tests for the Plonky3 backend to ensure the fixtures load
and consensus primitives reject tampering:

```shell
cargo test -p prover-plonky3-backend
```

**Success signal**: the test suite finishes with `0 failed`, confirming that the
sample witnesses can be proven and that tampered VRF randomness or quorum roots
are rejected by the verifier.【F:prover/plonky3_backend/tests/consensus.rs†L1-L110】

**Failure modes**:

- `no Plonky3 setup artifacts were found` / `missing Plonky3 setup artifact` –
  install or regenerate the JSON fixtures described above.【F:rpp/proofs/plonky3/crypto.rs†L300-L420】
- `failed to decode Plonky3 verifying key` / `failed to prepare Plonky3 consensus circuit`
  – verify the compression/encoding metadata and confirm the blobs match the
  expected byte length from the metadata report.【F:rpp/proofs/plonky3/crypto.rs†L330-L380】【F:xtask/src/main.rs†L200-L266】

### 2.2 Exercise the consensus tamper suite

Phase 2 requires evidence that manipulated consensus certificates fail
verification under the production backend. Use the xtask wrapper with the
Plonky3 features enabled:

```shell
XTASK_NO_DEFAULT_FEATURES=1 \
XTASK_FEATURES="prod,backend-plonky3" \
cargo xtask test-consensus-manipulation
```

This is the same workload invoked by the CI/release "Guard against consensus
manipulation regressions" step; the `--backend` knob is modelled via the
`XTASK_FEATURES` environment so the command line stays uniform across
backends.【F:xtask/src/main.rs†L88-L170】【F:.github/workflows/release.yml†L94-L124】

**Success signal**: the console prints `consensus manipulation checks ... ok` and
the test log contains `baseline verification succeeds` messages followed by
explicit failures for tampered VRF randomness and quorum digests, matching the
assertions in the tamper suite.【F:prover/plonky3_backend/tests/consensus.rs†L52-L109】【F:tests/consensus/consensus_certificate_tampering.rs†L110-L222】
Archive the `target/debug/deps/consensus_certificate_tampering-*.log` artefact or
pipe test output to the Phase 2 evidence folder.

**Failure modes**:

- Any tampered scenario unexpectedly succeeds → treat as a regression; do not
  ship until the verifier changes are reviewed.
- The run aborts with feature errors → confirm the environment variables above
  were exported and that the workspace was built with the production feature
  set.

### 2.3 Full matrix smoke test (optional but recommended)

`scripts/test.sh --backend plonky3 --unit --integration` drives the same backend
through wallet, node and consensus workflows. Use it before release tags or when
introducing dependency upgrades; the script propagates `RUSTFLAGS=-D warnings`
and the backend feature flags automatically.【F:scripts/test.sh†L4-L210】 Collect
the resulting `target/test-logs/plonky3` directory as part of the release notes.

## 3. Interpreting logs and metrics in production

Once the backend is live, monitor the following sources to keep Phase 2 evidence
current:

- **Telemetry snapshot** – `/status/node` surfaces a `plonky3` entry with the
  cached circuit count, success/failure counters and the most recent error
  message. A missing `plonky3` section usually means the backend feature is not
  compiled into the binary.【F:rpp/runtime/node.rs†L4870-L4888】
- **Prometheus metrics** – Proof generation/verification latencies and failure
  counters carry a `backend="plonky3"` label, enabling backend-specific alerting
  and dashboards.【F:rpp/runtime/telemetry/metrics.rs†L900-L940】
- **Node logs** – Prover errors emit `failed to prepare Plonky3 {circuit}` or
  `invalid consensus public inputs supplied` markers; capture these for incident
  response and attach to the acceptance checklist if they appear during audits.【F:rpp/proofs/plonky3/prover/mod.rs†L150-L220】
- **Simnet artefacts** – The `consensus_quorum_stress` scenario remains the
  canonical latency and tamper benchmark. Its JSON/CSV outputs are consumed by
  `scripts/analyze_simnet.py` and should be archived whenever release candidates
  are validated.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:scripts/analyze_simnet.py†L1-L200】

## 4. Production sign-off checklist

Complete the following before declaring Phase 2 production readiness:

- [ ] `cargo test -p prover-plonky3-backend` succeeds and artefacts are archived.
- [ ] `cargo xtask test-consensus-manipulation` (Plonky3 features) passes and the
      console/log output is stored with the release evidence.
- [ ] Latest `xtask proof-metadata` report is bundled with the build so auditors
      can verify key lengths and hashes.【F:xtask/src/main.rs†L200-L266】
- [ ] `scripts/test.sh --backend plonky3 --unit --integration` run (optional for
      hotfixes, mandatory for releases) and telemetry snapshots captured.
- [ ] Observability dashboards and alerts for `backend="plonky3"` counters were
      reviewed; any deviations are documented in the incident log.【F:docs/runbooks/observability.md†L20-L86】

Maintain this checklist alongside the operator runbooks so every rollout embeds
repeatable, audited proof that the Plonky3 backend is healthy.
