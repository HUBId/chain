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

## Backend status summary

| Backend | Current integration | Production gaps |
| --- | --- | --- |
| **STWO (`official`)** | The [`StwoBackend`](../rpp/zk/prover_stwo_backend/src/backend.rs) now drives key generation, proving, and verification through the vendor crates when the `official` feature is enabled. The adapter wraps the official [`WalletProver`](../rpp/zk/prover_stwo_backend/src/official/prover.rs) for every circuit family and delegates verification to the [`NodeVerifier`](../rpp/zk/prover_stwo_backend/src/official/verifier/mod.rs). Feature wiring is captured in the crate manifest so production builds can opt into the vendor dependency.【F:rpp/zk/prover_stwo_backend/src/backend.rs†L35-L496】【F:rpp/zk/prover_stwo_backend/src/official/prover.rs†L18-L199】【F:rpp/zk/prover_stwo_backend/src/official/verifier/mod.rs†L1-L120】【F:rpp/zk/prover_stwo_backend/Cargo.toml†L1-L21】 | Runtime services still need to surface the proofs to Firewood, wallets, and pruning automation. The relevant blueprint tasks remain in `Todo`: lifecycle services, block metadata, pruning jobs, wallet workflows, and uptime propagation.【F:rpp/proofs/blueprint/mod.rs†L110-L157】 Operationally, operators must provision the nightly toolchain and vendor artifacts recorded in the integration log before enabling the feature in production.【F:docs/vendor_log.md†L20-L68】 |
| **Plonky3 (mock)** | The mock backend continues to wrap witnesses in JSON and emit deterministic transcripts instead of real proofs, maintaining the blueprint plumbing without cryptographic soundness.【F:rpp/proofs/plonky3/prover/mod.rs†L154-L259】【F:rpp/proofs/plonky3/crypto.rs†L360-L436】 | The roadmap still tracks the work to replace the stub with a full Plonky3 integration, including setup artifact handling and verification coverage.【F:docs/roadmap_implementation_plan.md†L19-L77】 |

## Official STWO backend details

With the `official` feature enabled, [`StwoBackend`](../rpp/zk/prover_stwo_backend/src/backend.rs) exposes all blueprint
circuits through the shared backend interface:

* Key generation returns encoded proving/verifying keys for every circuit type by
  instantiating the official parameter set and embedding the circuit identifier
  into the payload.【F:rpp/zk/prover_stwo_backend/src/backend.rs†L56-L144】
* Proving delegates to [`WalletProver`](../rpp/zk/prover_stwo_backend/src/official/prover.rs),
  which evaluates the official circuits, generates execution traces, runs FRI,
  and assembles `StarkProof` payloads for transactions, identity, state,
  pruning, recursive aggregation, uptime, and consensus flows.【F:rpp/zk/prover_stwo_backend/src/backend.rs†L146-L289】【F:rpp/zk/prover_stwo_backend/src/official/prover.rs†L31-L199】
* Verification reconstructs public inputs, validates commitments, and feeds the
  decoded proofs into [`NodeVerifier`](../rpp/zk/prover_stwo_backend/src/official/verifier/mod.rs),
  ensuring the official verifier logic is exercised across all circuits.【F:rpp/zk/prover_stwo_backend/src/backend.rs†L291-L488】【F:rpp/zk/prover_stwo_backend/src/official/verifier/mod.rs†L1-L120】

These adapters provide the concrete keygen/prove/verify hooks the blueprint
anticipated, making the `official` integration the canonical STWO backend for
production builds.

## Plonky3 path status

* The Plonky3 prover/verifier pair only exercises the JSON plumbing: witnesses
  are wrapped, hashed, and converted into `ChainProof::Plonky3` values without
  generating real proofs.【F:rpp/proofs/plonky3/prover/mod.rs†L154-L259】
* Proof commitments are derived from canonical JSON, and the “proof” bytes are
  a Blake3 transcript seeded by the mocked verifying key, confirming that the
  backend still behaves as a deterministic stub rather than talking to a real
  Plonky3 engine.【F:rpp/proofs/plonky3/crypto.rs†L360-L436】

## Poseidon VRF coverage

The Poseidon-backed VRF stack that the blueprint scoped is now fully wired:

* `rpp/crypto-vrf` ships the VRF key lifecycle, Poseidon input tuple helpers,
  and randomness/proof derivation utilities so operators can generate and store
  the required key material without relying on external tooling.【F:rpp/crypto-vrf/src/lib.rs†L247-L360】
* The same crate covers epoch rotation, replay protection, and threshold
  selection: `VrfEpochManager` deduplicates submissions per epoch, while
  `select_validators` applies the weighted lottery, entropy beacon updates, and
  fallback handling described in the blueprint.【F:rpp/crypto-vrf/src/lib.rs†L648-L999】
* Consensus integrates the VRF outputs directly; `ConsensusRound::new` loads the
  validated submissions, captures the selection audit trail, and records the
  per-round metrics that `NodeStatus` exposes through the runtime RPC layer.
  Operators can now query `/status/node` for `vrf_metrics` alongside the usual
  consensus health information.【F:rpp/consensus/node.rs†L360-L450】【F:rpp/runtime/node.rs†L3921-L3936】

These additions retire the `vrf.poseidon_impl`, `vrf.epoch_management`, and
`vrf.monitoring` backlog items in the blueprint module.【F:rpp/proofs/blueprint/mod.rs†L190-L210】

**Net result:** the Plonky3 pathway remains a mock that validates the plumbing
but provides no cryptographic guarantees until real setup artifacts and prover
executables are integrated.

## Production backlog alignment

The blueprint backlog keeps the remaining integration work visible. The table
below mirrors the current `Todo` entries so roadmap consumers can cross-check
progress without digging into the Rust module:

| Workstream | Blueprint keys | Status |
| --- | --- | --- |
| Firewood ↔ STWO interfaces | `state.lifecycle_api`, `state.block_metadata`, `state.pruning_jobs` | Lifecycle-Trait und Block-Metadaten werden inzwischen implementiert und getestet; Pruning-Jobs stehen weiter aus.【F:rpp/storage/state/lifecycle.rs†L11-L218】【F:rpp/storage/mod.rs†L277-L335】【F:rpp/proofs/blueprint/mod.rs†L110-L127】 |
| Wallet/STWO workflows | `wallet.utxo_policies`, `wallet.zsi_workflow`, `wallet.stwo_circuits`, `wallet.uptime_proofs` | Todo【F:rpp/proofs/blueprint/mod.rs†L135-L157】 |
| Plonky3 backend enablement | Roadmap Schritt 3 (Proof system phase) | Todo【F:docs/roadmap_implementation_plan.md†L19-L77】 |
| VRF validator selection | `vrf.poseidon_impl`, `vrf.epoch_management`, `vrf.monitoring` | Done – VRF keygen, thresholding, and telemetry are live; alerting still relies on the manual checks in the VRF troubleshooting runbook, so follow-up automation remains open.【F:rpp/proofs/blueprint/mod.rs†L190-L210】【F:rpp/crypto-vrf/src/lib.rs†L247-L999】【F:rpp/runtime/node.rs†L3921-L3936】【F:docs/validator_troubleshooting.md†L9-L38】 |

## Historical note

Earlier revisions of this document warned that the vendor drop lacked the
necessary Poseidon2, FRI, and serialization helpers. Those gaps have been
bridged by the in-tree adapters above, but the original survey is preserved for
context in [`docs/stwo_official_api.md`](stwo_official_api.md), together with
the staged vendor plan in [`docs/vendor_log.md`](vendor_log.md).【F:docs/stwo_official_api.md†L1-L37】【F:docs/vendor_log.md†L20-L68】

## Follow-up

1. Track the remaining `Todo` items in the blueprint backlog until Firewood,
   wallet, and pruning services consume the official proofs end-to-end.【F:rpp/proofs/blueprint/mod.rs†L110-L157】
2. Capture operational readiness (nightly toolchain availability, artifact
   provisioning, CI coverage) in the release runbooks once operators begin
   enabling the `official` feature in production.【F:docs/vendor_log.md†L20-L68】

