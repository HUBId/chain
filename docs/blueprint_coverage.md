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
| **STWO (`official`)** | The [`StwoBackend`](../rpp/zk/prover_stwo_backend/src/backend.rs) now drives key generation, proving, and verification through the vendor crates when the `official` feature is enabled. The adapter wraps the official [`WalletProver`](../rpp/zk/prover_stwo_backend/src/official/prover.rs) for every circuit family and delegates verification to the [`NodeVerifier`](../rpp/zk/prover_stwo_backend/src/official/verifier/mod.rs). Feature wiring is captured in the crate manifest so production builds can opt into the vendor dependency.【F:rpp/zk/prover_stwo_backend/src/backend.rs†L35-L496】【F:rpp/zk/prover_stwo_backend/src/official/prover.rs†L18-L199】【F:rpp/zk/prover_stwo_backend/src/official/verifier/mod.rs†L1-L120】【F:rpp/zk/prover_stwo_backend/Cargo.toml†L1-L21】 Firewood integration now runs end-to-end: lifecycle helpers apply snapshots, block metadata persists pruning proofs, and the pruning worker streams job status while RPC endpoints issue receipts for rebuild/snapshot requests backed by documented runbooks.【F:rpp/storage/state/lifecycle.rs†L10-L130】【F:rpp/storage/mod.rs†L267-L352】【F:rpp/node/src/services/pruning.rs†L120-L200】【F:rpp/runtime/node.rs†L3580-L3639】【F:rpp/rpc/src/routes/state.rs†L1-L26】【F:rpp/storage/pruner/receipt.rs†L1-L58】【F:docs/runbooks/pruning.md†L1-L120】【F:docs/runbooks/pruning_operations.md†L1-L120】 | Production gaps now concentrate on wallet integrations and uptime propagation; the remaining `Todo` entries sit under the wallet workflow keys in the blueprint module while Firewood-facing tasks have been closed out.【F:rpp/proofs/blueprint/mod.rs†L130-L157】 Operationally, operators must still provision the nightly toolchain and vendor artifacts recorded in the integration log before enabling the feature in production.【F:docs/vendor_log.md†L20-L68】 |
| **Plonky3** | The dedicated [`plonky3_backend`](../prover/plonky3_backend/src/lib.rs) crate now drives circuit key generation, proof construction, and verification using the configured setup artifacts. Wallet-facing code compiles the circuits once per parameter set, commits to canonical public inputs, and hands the resulting proofs to the unified verifier registry.【F:prover/plonky3_backend/src/lib.rs†L1-L130】【F:rpp/proofs/plonky3/prover/mod.rs†L60-L135】【F:rpp/proofs/plonky3/crypto.rs†L1-L189】 End-to-end tests exercise the real backend against canonical fixtures so regressions in keygen/prove/verify behaviour are caught automatically.【F:rpp/proofs/plonky3/tests/mod.rs†L1-L120】【F:rpp/proofs/plonky3/tests/fixtures/transaction_roundtrip.json†L1-L24】 | Production enablement now focuses on pipeline integration (exposing proofs to Firewood and pruning automation) rather than backend plumbing, as tracked in the roadmap.【F:docs/roadmap_implementation_plan.md†L19-L77】 |

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

* `plonky3_backend` compiles each circuit once per `(security_bits, gpu)` pair
  and caches the resulting proving/verifying keys so repeat proofs avoid
  redundant setup work.【F:rpp/proofs/plonky3/prover/mod.rs†L60-L135】
* Proof generation now feeds canonical public inputs into the backend crate,
  which derives the commitment, transcript digests, and proof bytes alongside
  the verifying key payload expected by the unified proof envelope.【F:prover/plonky3_backend/src/lib.rs†L1-L130】【F:rpp/proofs/plonky3/crypto.rs†L130-L189】
* Verification rehydrates the backend circuit from the setup artifacts,
  recomputes the commitment from the submitted public inputs, and delegates the
  transcript checks to the backend so tampering is detected before proofs reach
  the consensus or wallet layers.【F:rpp/proofs/plonky3/crypto.rs†L151-L189】
* Regression tests load canonical fixtures for keygen/prove/verify paths to
  guarantee deterministic output across releases.【F:rpp/proofs/plonky3/tests/mod.rs†L1-L120】【F:rpp/proofs/plonky3/tests/fixtures/transaction_roundtrip.json†L1-L24】

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

**Net result:** the Plonky3 pathway now produces and verifies structured
proof artifacts via the backend crate, clearing the blueprint milestone for a
feature-complete prover/verifier integration.

## Production backlog alignment

The blueprint backlog keeps the remaining integration work visible. The table
below mirrors the current `Todo` entries so roadmap consumers can cross-check
progress without digging into the Rust module:

| Workstream | Blueprint keys | Status |
| --- | --- | --- |
| Firewood ↔ STWO interfaces | `state.lifecycle_api`, `state.block_metadata`, `state.pruning_jobs` | Alle drei Aufgaben sind abgeschlossen: Lifecycle-Service und Block-Metadaten persistieren Firewood-Snapshots und Pruning-Proofs, während der Hintergrunddienst Jobs automatisiert ausführt und Statusmeldungen veröffentlicht.【F:rpp/storage/state/lifecycle.rs†L10-L130】【F:rpp/storage/mod.rs†L267-L352】【F:rpp/node/src/services/pruning.rs†L120-L200】【F:rpp/runtime/node.rs†L3580-L3639】【F:rpp/proofs/blueprint/mod.rs†L110-L137】 |
| Block Lifecycle | `lifecycle.state_sync` | Done – LightClientVerifier und Runtime-State-Sync-Cache prüfen Snapshot-Pläne samt Pruning- und Recursive-Proofs; RPC-Tests und Dokumentation decken Status-/SSE-Endpunkte ab.【F:rpp/node/src/state_sync/light_client.rs†L24-L424】【F:rpp/runtime/node.rs†L2607-L3875】【F:rpp/rpc/tests/state_sync.rs†L71-L436】【F:docs/state_sync.md†L1-L71】【F:docs/interfaces/rpc/state_sync_status_response.jsonschema†L1-L53】 |
| Libp2p Backbone | `p2p.integrate_libp2p`, `p2p.admission_control`, `p2p.snapshot_sync` | Done – `Network::new` wires the Noise-XX handshake, peerstore bookkeeping, and behaviour hooks so runtime events surface authenticated peers, admission outcomes, and snapshot sessions.【F:rpp/p2p/src/swarm.rs†L849-L1115】 Tier-gated publish/subscribe checks and reputation penalties flow through `AdmissionControl` to enforce the blueprint’s access policies.【F:rpp/p2p/src/admission.rs†L14-L210】【F:rpp/p2p/tests/access_control.rs†L423-L515】 Snapshot streaming runs over the dedicated request/response behaviour while the runtime tracks progress and completion via `SnapshotStreamStatus`; integration tests drive end-to-end resume/ack paths.【F:rpp/p2p/src/behaviour/snapshots.rs†L58-L520】【F:rpp/runtime/node_runtime/node.rs†L375-L503】【F:rpp/p2p/tests/snapshot_stream.rs†L1-L200】 |
| Witness QoS & Rewards | `consensus.witness_channels` | Done – Witness-Proof- und Meta-Pipelines laufen über dedizierte Buffer mit Token-Bucket-Limits, Topics tragen explizite QoS/Prio-Metadaten und Reward-Snapshots buchen Treasury- und Fee-Pools automatisch. Dokumentation und Regressionstests decken Konfiguration sowie Accounting ab.【F:rpp/p2p/src/behaviour/witness.rs†L1-L164】【F:rpp/p2p/src/topics.rs†L1-L113】【F:tests/consensus/witness_distribution.rs†L1-L55】【F:docs/consensus/witness_channels.md†L1-L70】 |
| Malachite BFT | `consensus.malachite_distributed` | Done – Der `DistributedOrchestrator` bündelt Proposal-, Vote- und Commit-Streams für mehrere Validatoren, während der `TopicRouter` Commit-Nachrichten automatisch an die Witness-Themen weiterleitet.【F:rpp/consensus/src/malachite/distributed.rs†L1-L120】【F:rpp/consensus/src/network/topics.rs†L1-L62】 Der Evidence-Pool priorisiert Double-Sign-, Availability-, Witness-, Censorship- und Inaktivitätsmeldungen, koppelt sie an die Slashing-Heuristiken und telemetriert Zeiger in den Konsens-Status.【F:rpp/consensus/src/evidence/mod.rs†L10-L205】【F:rpp/consensus/src/state.rs†L928-L989】 Regressionstests decken die Mehrknoten-Orchestrierung sowie die Priorisierung und Witness-/Uptime-Auslöser ab.【F:tests/consensus/malachite_distributed.rs†L1-L200】【F:tests/consensus/evidence_slashing.rs†L1-L205】 Rewards verteilen Basis- und Leader-Bonus inklusive Witness-Pools und Penalty-Einbehalt, abgesichert durch Governance- und Konsenstests.【F:rpp/consensus/src/rewards.rs†L1-L120】【F:rpp/consensus/src/state.rs†L948-L989】【F:tests/consensus/timetoke_rewards.rs†L1-L54】 |
| Wallet/STWO workflows | `wallet.utxo_policies`, `wallet.zsi_workflow`, `wallet.stwo_circuits`, `wallet.uptime_proofs` | Done – Die tierbasierte Policy-Engine erzwingt Spend-Limits im Wallet und wird durch Docs/Regressionstests abgedeckt.【F:rpp/wallet/ui/policy/mod.rs†L1-L176】【F:docs/wallet/policies.md†L1-L41】【F:tests/wallet/utxo_policies.rs†L1-L104】 Der vollständige ZSI-Lifecycle (Library, CLI, RPC) ist umgesetzt und durch Dokumentation sowie Integrations-Tests verlinkt.【F:rpp/wallet/src/zsi/lifecycle.rs†L1-L233】【F:docs/wallet/zsi.md†L1-L52】【F:tests/zsi/lifecycle_flow.rs†L1-L145】 Uptime-Proofs laufen end-to-end vom Scheduler über Reputation bis zum Gossip und werden durch Tests/Docs verifiziert.【F:rpp/node/src/services/uptime.rs†L1-L200】【F:tests/consensus/uptime.rs†L1-L200】【F:docs/consensus/uptime_proofs.md†L1-L34】 |
| Electrs & wallet UI | `electrs.modes`, `electrs.ui_rpc` | Done – Wallet- und Hybrid-Profile booten Electrs-Tracker und UI-Tab-Modelle für History-, Send-, Receive- und Node-Ansichten; die Handler bereiten Skriptstatus, Sendevorschauen und Knotenmetriken für UI-Clients auf.【F:rpp/wallet/ui/wallet.rs†L736-L924】 Die RPC-Schicht exponiert kontraktversionierte `/wallet/ui/*`-Routen parallel zu den klassischen Wallet-Endpunkten, inklusive Auth-/Rate-Limits für Send/History/Node-Flows.【F:rpp/rpc/api.rs†L1405-L1440】【F:rpp/rpc/api.rs†L1806-L2690】 JSON-Schema-Tests verankern die UI-Verträge, sodass Dashboard- und Client-Integrationen auf stabile Payloads bauen können.【F:rpp/rpc/tests/wallet_ui_contract.rs†L1-L120】 |
| Plonky3 backend enablement | Roadmap Schritt 3 (Proof system phase) | Todo【F:docs/roadmap_implementation_plan.md†L19-L77】 |
| VRF validator selection | `vrf.poseidon_impl`, `vrf.epoch_management`, `vrf.monitoring` | Done – VRF keygen, thresholding, and telemetry are live; OTLP exporters plus the VRF observability blueprint now cover dashboards and alert thresholds so operators no longer depend on ad-hoc runbooks.【F:rpp/proofs/blueprint/mod.rs†L190-L210】【F:rpp/crypto-vrf/src/lib.rs†L247-L999】【F:rpp/crypto-vrf/src/telemetry.rs†L1-L123】【F:docs/observability/vrf.md†L1-L64】 |

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

