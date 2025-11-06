# ADR 0001: ZK Backend Status and Plonky3 Graduation

## Status

Accepted – Plonky3 backend graduated to production in Phase 2.

## Context

Earlier revisions of this ADR codified Plonky3 as an experimental backend. The
acknowledgement guard acted as a safety rail while the prover and verifier were
wired to deterministic shims. With Phase 2 the vendor prover/verifier pair ships
in production builds, backed by signed setup artefacts under
`config/plonky3/setup/` and cache material staged at `proof_cache_dir`
(defaults to `data/proofs`).【F:config/plonky3/setup/README.md†L16-L103】【F:config/node.toml†L5-L20】 Runtime snapshots now expose
the Plonky3 prover health alongside the existing verifier metrics, and the
Prometheus instrumentation publishes generation duration/size and verifier byte
histograms labelled by backend and proof kind.【F:rpp/runtime/node.rs†L4862-L4894】【F:rpp/runtime/telemetry/metrics.rs†L426-L520】
Release packaging closes the supply-chain loop by re-running the snapshot
integrity regression, building signed artefacts into `dist/artifacts/<target>/`,
and verifying that only production prover features are linked before the build
is promoted.【F:scripts/build_release.sh†L1-L118】【F:scripts/verify_release_features.sh†L1-L146】 The deterministic test shims have
been replaced by the vendor Plonky3 prover/verifier flow that reconstructs
public inputs, validates witness payloads, and enforces tamper checks for every
circuit.【F:rpp/proofs/plonky3/prover/mod.rs†L19-L520】【F:rpp/proofs/plonky3/verifier/mod.rs†L1-L212】

## Decision

* Vendor prover/verifier ship behind the `backend-plonky3` feature flag and are
  required for production artefacts. Compile-time guards keep the mock backend
  segregated while release automation double-checks the metadata before
  publishing.【F:rpp/node/src/feature_guard.rs†L1-L7】【F:scripts/verify_release_features.sh†L1-L146】
* Runtime telemetry exposes live prover/verifier latencies via Prometheus and
  `/status/node`; dashboards and alerts now consume
  `rpp.runtime.proof.generation.*`, `rpp_stark_verify_duration_seconds`, and the
  related byte histograms for backend-specific SLOs.【F:rpp/runtime/telemetry/metrics.rs†L426-L520】【F:docs/dashboards/consensus_proof_validation.json†L1-L200】
* CI/nightly pipelines execute the consensus stress harness, capture JSON/CSV
  artefacts under `target/simnet/`, and enforce p95 latency thresholds through
  `scripts/analyze_simnet.py`. Release validation bundles those artefacts with
  the Grafana export documented in the Plonky3 runbook.【F:scripts/analyze_simnet.py†L1-L200】【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:docs/runbooks/plonky3.md†L1-L200】

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
