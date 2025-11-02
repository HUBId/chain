# ADR 0001: ZK Backend Status and Plonky3 Graduation

## Status

Accepted – Plonky3 backend graduated to production in Phase 2.

## Context

Earlier revisions of this ADR codified Plonky3 as an experimental backend. The
acknowledgement guard acted as a safety rail while the prover and verifier were
wired to deterministic shims. With Phase 2 the vendor prover/verifier pair ships
in production builds, the runtime exports real latency metrics, and the release
pipeline enforces the `backend-plonky3` feature alongside STWO options.【F:rpp/proofs/plonky3/prover/mod.rs†L19-L520】【F:rpp/proofs/plonky3/verifier/mod.rs†L1-L212】【F:scripts/build_release.sh†L1-L118】

## Decision

* Vendor prover/verifier ship behind the `backend-plonky3` feature flag and are
  required for release artefacts. The guard still prevents combining the mock
  backend with production features.【F:rpp/node/src/feature_guard.rs†L1-L5】
* Runtime telemetry exposes live prover/verifier latencies via Prometheus and
  `/status/node`; dashboards and alerts now rely on these metrics instead of
  stub placeholders.【F:rpp/runtime/node.rs†L161-L220】【F:docs/dashboards/consensus_proof_validation.json†L1-L200】
* CI/nightly pipelines execute the consensus stress harness and enforce p95
  latency/tamper thresholds through `scripts/analyze_simnet.py`. Release
  validation requires attaching the summary and the Grafana export documented in
  the Plonky3 runbook.【F:scripts/analyze_simnet.py†L1-L200】【F:docs/runbooks/plonky3.md†L1-L200】

## Consequences

* Operators may run Plonky3 in production provided the runbook validation steps
  pass and monitoring is in place.【F:docs/runbooks/plonky3.md†L1-L200】
* Release artefacts, CI smoke tests, and nightlies validate real proofs rather
  than deterministic fixtures. Failures block promotion until the acceptance
  criteria in the performance report are satisfied.【F:docs/performance/consensus_proofs.md†L1-L200】
* Documentation, roadmap status, and dashboards now treat Plonky3 as a fully
  supported backend with remaining work limited to GPU benchmarking and
  distribution automation.【F:docs/blueprint_coverage.md†L1-L200】【F:docs/roadmap_implementation_plan.md†L1-L120】

## Follow-up

* Deliver GPU-backed benchmark variants and extend the nightly matrix when
  hardware becomes available.
* Continue refining runbooks for key distribution and alert automation as
  documented follow-up items land.
