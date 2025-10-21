# STWO/Plonky3 Blueprint Coverage Assessment

This document cross-references the blueprint requirements with the current
code base to highlight the shape of the abstraction, the status of each
backend, and the remaining work required for production readiness.

## Backend abstraction snapshot

* Proof artifacts continue to flow through the unified `ChainProof` enum, so
  wallets and nodes can exchange bundles without committing to a concrete
  proving system up front.【F:rpp/runtime/types/proofs.rs†L58-L200】
* The verifier registry still instantiates a verifier per backend and routes
  verification requests through shared dispatch helpers, which keeps the block
  import path backend-agnostic.【F:rpp/proofs/proof_system/mod.rs†L217-L311】

## STWO path status

* The blueprint-level STWO prover wiring remains in place: `WalletProver`
  derives witnesses for every circuit, computes traces, and emits
  `StarkProof` artifacts that slot into the `ChainProof::Stwo` branch.【F:rpp/proofs/stwo/prover/mod.rs†L42-L360】
* However, the vendor drop of `stwo::official` still lacks the public API
  surface the production integration expects (Poseidon2 helpers, FRI wrappers,
  byte-serialization hooks, etc.), so the repository cannot yet replace the
  blueprint scaffolding with the real backend.【F:docs/stwo_official_api.md†L1-L37】
* The staged vendor plan captures the operational prerequisites—most notably
  the requirement to build the backend with `nightly-2025-07-14`—but those
  artifacts are not consumed by the runtime today.【F:docs/vendor_log.md†L20-L64】

**Net result:** the STWO flow is functionally complete inside the blueprint
module, yet it remains isolated from the vendor workspace until the missing
API bridges land and the nightly toolchain path is productionised.

## Plonky3 path status

* The Plonky3 prover/verifier pair only exercises the JSON plumbing: witnesses
  are wrapped, hashed, and converted into `ChainProof::Plonky3` values without
  generating real proofs.【F:rpp/proofs/plonky3/prover/mod.rs†L154-L259】
* Proof commitments are derived from canonical JSON, and the “proof” bytes are
  a Blake3 transcript seeded by the mocked verifying key, confirming that the
  backend still behaves as a deterministic stub rather than talking to a real
  Plonky3 engine.【F:rpp/proofs/plonky3/crypto.rs†L360-L436】

**Net result:** the Plonky3 pathway remains a mock that validates the plumbing
but provides no cryptographic guarantees until real setup artifacts and prover
executables are integrated.

## Outstanding work tracked in the blueprint backlog

The end-to-end blueprint keeps the open items for both backends in the
`rpp::blueprint` catalogue. The tasks below remain in `Todo` state and must be
closed before the document can claim production readiness:

* **Firewood ↔ STWO interfaces** – extract lifecycle APIs, persist block
  metadata, and automate pruning once the real backend is wired in. Tracking:
  [`state.lifecycle_api`](../rpp/proofs/blueprint/mod.rs#L111-L127),
  [`state.block_metadata`](../rpp/proofs/blueprint/mod.rs#L117-L120), and
  [`state.pruning_jobs`](../rpp/proofs/blueprint/mod.rs#L122-L125).
* **Wallet/STWO workflows** – extend the wallet side with UTXO/tier policies,
  ZSI flows, and the production STWO circuits so end users can produce the
  upgraded proofs. Tracking:
  [`wallet.utxo_policies`](../rpp/proofs/blueprint/mod.rs#L135-L139),
  [`wallet.zsi_workflow`](../rpp/proofs/blueprint/mod.rs#L141-L145),
  [`wallet.stwo_circuits`](../rpp/proofs/blueprint/mod.rs#L147-L152), and
  [`wallet.uptime_proofs`](../rpp/proofs/blueprint/mod.rs#L153-L157).
* **Plonky3 backend enablement** – replace the deterministic stub with the
  real proving system, including setup artifact management and integration test
  coverage. Tracking: addenda to the backend backlog captured in the roadmap’s
  proof system phase (see
  [`Schritt 3`](roadmap_implementation_plan.md#3-wallet-zsi-und-stwo-workflows-blueprint-22)).【F:docs/roadmap_implementation_plan.md†L19-L77】

## Follow-up once integrations land

When the tasks above are complete and the real backends are enabled:

1. Refresh this document to confirm end-to-end proof generation and
   verification against the production stacks (STWO vendor crates via nightly
   toolchains, Plonky3 setup artifacts, CI coverage).
2. Document the operational requirements for operators—nightly toolchain
   availability, artifact provisioning, and any new telemetry knobs—so the
   blueprint reflects the production-ready posture recorded in the vendor log
   and release tooling.【F:docs/vendor_log.md†L20-L64】

