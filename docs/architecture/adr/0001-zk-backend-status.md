# ADR 0001: ZK Backend Status and Plonky3 Graduation

## Status

Accepted (2025-09-08)

## Context

Earlier revisions of this ADR codified Plonky3 as an experimental backend. The
acknowledgement guard was a temporary safety rail while the prover and verifier
were still wired to deterministic shims. The backend now ships with production
parameters, emits real proofs, and records detailed telemetry snapshots for
operators.【F:rpp/proofs/plonky3/prover/mod.rs†L1-L210】 The runtime exposes those
signals through RPC payloads so downstream automation can track health alongside
STWO and RPP-STARK metrics.【F:rpp/runtime/node.rs†L161-L218】【F:docs/interfaces/rpc/validator_status_response.jsonschema†L1-L220】

## Decision

* Remove the Plonky3 acknowledgement gate from the prover, verifier, runtime
  bootstrap, and CLI. Enabling `--features backend-plonky3` now yields a
  production configuration without extra flags.【F:rpp/proofs/plonky3/prover/mod.rs†L214-L230】【F:rpp/proofs/plonky3/verifier/mod.rs†L215-L240】【F:rpp/node/src/lib.rs†L240-L360】
* Surface backend health as structured telemetry. `NodeStatus.backend_health`
  publishes verifier counters for every proof system and attaches the Plonky3
  prover snapshot (cache size, success/failure counts, timestamps) when the
  backend is compiled in.【F:rpp/runtime/node.rs†L161-L220】 Client schemas,
  examples, and the validator UI expose the same structure so operators can
  trigger alerts on degradation instead of manual warning banners.【F:docs/interfaces/rpc/validator_status_response.jsonschema†L1-L220】【F:docs/interfaces/rpc/examples/validator_status_response.json†L1-L120】【F:validator-ui/src/types.ts†L140-L220】
* Treat Plonky3 as a first-class backend in automation. Release tooling only
  blocks the mock backend; Plonky3 builds ship through the standard matrix, and
  `scripts/test.sh` exercises the backend by default next to STWO and
  RPP-STARK.【F:scripts/build_release.sh†L100-L160】【F:scripts/test.sh†L1-L220】

## Consequences

* Operators can promote Plonky3 to production without custom flags. Monitoring
  should pivot to the `backend_health` map and the existing OTLP metrics instead
  of guarding against startup failures.【F:rpp/runtime/node.rs†L161-L220】
* CI and release pipelines now validate Plonky3 artefacts automatically, so
  regressions in the backend surface in the same lanes as the other production
  proof systems.【F:scripts/test.sh†L1-L220】【F:scripts/build_release.sh†L100-L160】
* Documentation, schemas, and UI contracts highlight backend health rather than
  experimental warnings, reducing the risk of stale operational guidance.【F:docs/rpp_node_operator_guide.md†L1-L120】【F:docs/blueprint_coverage.md†L1-L120】

## Follow-up

* Expand dashboards and alerting rules to consume the new health metrics (e.g.
  minimum success rate, circuit cache churn) so operators can detect prover
  issues before they impact block production.
* Extend the release checklist with hardware notes (GPU acceleration, circuit
  cache sizing) specific to Plonky3 once production rollouts provide concrete
  thresholds.
