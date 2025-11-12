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
| **STWO (`official`)** | The [`StwoBackend`](../prover/prover_stwo_backend/src/backend.rs) now drives key generation, proving, and verification through the vendor crates when the `official` feature is enabled. The adapter wraps the official [`WalletProver`](../prover/prover_stwo_backend/src/official/prover.rs) for every circuit family and delegates verification to the [`NodeVerifier`](../prover/prover_stwo_backend/src/official/verifier/mod.rs). Feature wiring is captured in the crate manifest so production builds can opt into the vendor dependency.【F:prover/prover_stwo_backend/src/backend.rs†L35-L496】【F:prover/prover_stwo_backend/src/official/prover.rs†L18-L199】【F:prover/prover_stwo_backend/src/official/verifier/mod.rs†L1-L120】【F:prover/prover_stwo_backend/Cargo.toml†L1-L21】 Firewood integration now runs end-to-end: lifecycle helpers apply snapshots, block metadata persists pruning proofs, and the pruning worker streams job status while RPC endpoints issue receipts for rebuild/snapshot requests backed by documented runbooks.【F:rpp/storage/state/lifecycle.rs†L10-L130】【F:rpp/storage/mod.rs†L267-L352】【F:rpp/node/src/services/pruning.rs†L120-L200】【F:rpp/runtime/node.rs†L3580-L3639】【F:rpp/rpc/src/routes/state.rs†L1-L26】【F:rpp/storage/pruner/receipt.rs†L1-L58】【F:docs/runbooks/pruning.md†L1-L120】【F:docs/runbooks/pruning_operations.md†L1-L120】 | Production gaps now concentrate on wallet integrations and uptime propagation; the remaining `Todo` entries sit under the wallet workflow keys in the blueprint module while Firewood-facing tasks have been closed out.【F:rpp/proofs/blueprint/mod.rs†L130-L157】 Operationally, operators must still provision the nightly toolchain and vendor artifacts recorded in the integration log before enabling the feature in production.【F:docs/vendor_log.md†L20-L68】 |
| **Plonky3** | The [`Plonky3Prover`](../rpp/proofs/plonky3/prover/mod.rs) / [`Plonky3Verifier`](../rpp/proofs/plonky3/verifier/mod.rs) adapters now execute the vendor backend exported by [`plonky3_backend`](../prover/plonky3_backend/src/lib.rs) end-to-end. Circuit caches, public-input validation, and proof payloads mirror the STWO implementation, the runtime exposes `backend_health.plonky3.*` snapshots plus Prometheus metrics for generation/verification latencies, and the consensus circuit now ships VRF/quorum binding checks so public inputs are derived from the canonical witness representation.【F:rpp/proofs/plonky3/prover/mod.rs†L19-L520】【F:rpp/proofs/plonky3/verifier/mod.rs†L1-L212】【F:prover/plonky3_backend/src/lib.rs†L1-L120】【F:prover/plonky3_backend/src/circuits/consensus.rs†L1-L245】【F:rpp/runtime/node.rs†L161-L220】 Manipulation paths stay covered by the dedicated tamper suites (`consensus_certificate_tampering.rs`, `plonky3_consensus.rs`) and the Simnet stress scenario documented below.【F:tests/consensus/consensus_certificate_tampering.rs†L1-L156】【F:tests/consensus/plonky3_consensus.rs†L1-L120】【F:docs/testing/simulations.md†L1-L120】 | **Done –** witness validation and tamper detection for the consensus circuit remain live; the release gate runs `cargo xtask test-consensus-manipulation` while Nightly `nightly-simnet` (`cargo xtask test-simnet` + `scripts/analyze_simnet.py`) enforces the Phase‑2 VRF/quorum thresholds as part of CI coverage.【F:.github/workflows/release.yml†L103-L136】【F:.github/workflows/nightly.yml†L1-L86】【F:docs/testing/simulations.md†L1-L120】 |

The blueprint module records both `proofs.plonky3_vendor_backend` and `proofs.plonky3_ci_matrix` as `Done`, aligning the status table with the production backend and CI enforcement described above.【F:rpp/proofs/blueprint/mod.rs†L133-L154】

## Official STWO backend details

  With the `official` feature enabled, [`StwoBackend`](../prover/prover_stwo_backend/src/backend.rs) exposes all blueprint
circuits through the shared backend interface:

* Key generation returns encoded proving/verifying keys for every circuit type by
  instantiating the official parameter set and embedding the circuit identifier
    into the payload.【F:prover/prover_stwo_backend/src/backend.rs†L56-L144】
* Proving delegates to [`WalletProver`](../prover/prover_stwo_backend/src/official/prover.rs),
  which evaluates the official circuits, generates execution traces, runs FRI,
  and assembles `StarkProof` payloads for transactions, identity, state,
    pruning, recursive aggregation, uptime, and consensus flows.【F:prover/prover_stwo_backend/src/backend.rs†L146-L289】【F:prover/prover_stwo_backend/src/official/prover.rs†L31-L199】
* Verification reconstructs public inputs, validates commitments, and feeds the
  decoded proofs into [`NodeVerifier`](../prover/prover_stwo_backend/src/official/verifier/mod.rs),
  ensuring the official verifier logic is exercised across all circuits.【F:prover/prover_stwo_backend/src/backend.rs†L291-L488】【F:prover/prover_stwo_backend/src/official/verifier/mod.rs†L1-L120】
* The backend regression matrix now executes every `SupportedCircuit` witness
  through a success path as well as public-input tampering and malformed witness
  scenarios, and CI invokes the suite for both the default backend and the
  `backend-rpp-stark` feature gate.【F:prover/prover_stwo_backend/src/backend.rs†L1193-L1740】【F:xtask/src/main.rs†L137-L181】

These adapters provide the concrete keygen/prove/verify hooks the blueprint
anticipated, making the `official` integration the canonical STWO backend for
production builds.

## Plonky3 path status

* `Plonky3Parameters` steuern Sicherheitsniveau, GPU-Betrieb und Circuit-Caching;
  die Prover-Implementierung lädt vendorisierte Proving-/Verifying-Keys und
  persistiert sie für wiederholte Läufe.【F:rpp/proofs/plonky3/prover/mod.rs†L42-L122】
* `Plonky3Prover` und `Plonky3Verifier` erzeugen/prüfen jetzt echte Beweise für
  Transaktions-, State-, Pruning-, Uptime- und Konsensus-Circuits. Telemetrie
  (Prometheus + `/status/node`) spiegelt Cache-Größe, Erfolgs-/Fehlerzähler und
  Zeitstempel.【F:rpp/proofs/plonky3/prover/mod.rs†L123-L520】【F:rpp/runtime/node.rs†L161-L220】
* Das Backend liefert mit `ConsensusCircuit`/`ConsensusWitness` nun VRF- und
  Quorum-Bindings, validiert die Zeugenstruktur symmetrisch in Prover und
  Verifier und deckt Manipulationen via Regressionstests ab.【F:prover/plonky3_backend/src/circuits/consensus.rs†L1-L245】【F:rpp/proofs/plonky3/verifier/mod.rs†L1-L212】【F:tests/consensus/plonky3_consensus.rs†L1-L134】【F:prover/plonky3_backend/tests/consensus.rs†L1-L69】
* Die Nightly-Suite `consensus-quorum-stress` validiert Keygen/Prover/Verifier
  unter hoher Validator-/Witness-Last und injiziert VRF-/Quorum-Manipulationen.
  Die Messwerte (p50/p95/max) werden in `performance/consensus_proofs.md`
  dokumentiert und dienen als Acceptance-Kriterien für Phase 2.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:docs/performance/consensus_proofs.md†L1-L160】
* Grafana-Panels (`docs/dashboards/consensus_proof_validation.json`) visualisieren
  die Plonky3-Latenzen und Fehlerpfade; das Dashboard-Lint im CI stellt sicher,
  dass die Exporte konsistent bleiben.【F:docs/dashboards/consensus_proof_validation.json†L1-L120】【F:.github/workflows/ci.yml†L12-L42】
* Operative Abläufe (Key-Rotation, Cache-Seeding, Alerting) sind im
  [Plonky3-Runbook](runbooks/plonky3.md) verankert. Das Runbook verweist auf die
  relevanten Telemetrie-Namen, Nightly-Artefakte und Tamper-Erwartungen.

## Consensus Phase‑2 evidence

* **Circuit-level constraints:** The Plonky3 consensus circuit binds VRF outputs
  and quorum roots directly in the witness, rejecting tampered bundles during
  proof generation and verification.【F:prover/plonky3_backend/src/circuits/consensus.rs†L1-L245】【F:rpp/proofs/plonky3/verifier/mod.rs†L1-L212】
* **Unit & tamper tests:** `tests/consensus/consensus_certificate_tampering.rs`
  injects manipulated VRF outputs, quorum bitmaps, and signature roots across
  both backends; the suite is wired into `cargo xtask test-consensus-manipulation`
  and referenced by the validation strategy.【F:tests/consensus/consensus_certificate_tampering.rs†L1-L156】【F:xtask/src/main.rs†L1-L140】【F:docs/test_validation_strategy.md†L1-L83】
* **Simulation evidence:** `cargo xtask test-simnet` executes the scenarios
  `ci_block_pipeline`, `ci_state_sync_guard`, and
  `consensus_quorum_stress`, producing JSON/CSV summaries that are analyzed via
  `scripts/analyze_simnet.py`. Threshold violations (P2P p95, prove/verify p95,
  tamper acceptance) fail Nightly runs and surface in the weekly status report.【F:docs/testing/simulations.md†L1-L160】【F:.github/workflows/nightly.yml†L1-L86】【F:docs/status/weekly.md†L1-L70】
* **Telemetry & reporting:** Metrics (`consensus_vrf_verification_time_ms`,
  `consensus_quorum_verifications_total`) feed dashboards and are cross-referenced
  in the observability/runbook docs so auditors can map Nightly artifacts to
  production alerting.【F:docs/observability/consensus.md†L1-L70】【F:docs/runbooks/observability.md†L1-L120】

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

**Net result:** the Plonky3 pathway now matches the blueprint expectations.
Runtime telemetry, dashboards, and the Nightly consensus stress test provide the
Phase‑2 acceptance evidence; remaining work focuses on scaling the GPU/offline
key distribution playbooks documented in the runbook.

## Production backlog alignment

The blueprint backlog keeps the remaining integration work visible. The table
below mirrors the current `Todo` entries so roadmap consumers can cross-check
progress without digging into the Rust module:

| Workstream | Blueprint keys | Status |
| --- | --- | --- |
| Firewood ↔ STWO interfaces | `state.lifecycle_api`, `state.block_metadata`, `state.pruning_jobs` | Alle drei Aufgaben sind abgeschlossen: Lifecycle-Service und Block-Metadaten persistieren Firewood-Snapshots und Pruning-Proofs, während der Hintergrunddienst Jobs automatisiert ausführt und Statusmeldungen veröffentlicht.【F:rpp/storage/state/lifecycle.rs†L10-L130】【F:rpp/storage/mod.rs†L267-L352】【F:rpp/node/src/services/pruning.rs†L120-L200】【F:rpp/runtime/node.rs†L3580-L3639】【F:rpp/proofs/blueprint/mod.rs†L110-L137】 State-Sync-Handler propagieren nun `ProofError::IO` direkt als `IoProof`-Antworten, markieren die Failures in `rpp_node_pipeline_root_io_errors_total` und verweisen im Runbook auf die zugehörige Diagnose-Checkliste, sodass Betreiber korrekte Wurzelfehler von erwarteten Ausfällen unterscheiden können.【F:rpp/runtime/node.rs†L4029-L4075】【F:rpp/node/src/state_sync/light_client.rs†L360-L401】【F:rpp/node/src/telemetry/pipeline.rs†L1-L88】【F:docs/runbooks/observability.md†L1-L38】 Regressionstests decken sowohl das Telemetrie-Signal (`proof_error_io.rs`) als auch den Wurzelschutz gegen beschädigte Snapshots (`root_corruption.rs`) ab und sind in den Auditrichtlinien verlinkt.【F:tests/state_sync/proof_error_io.rs†L1-L111】【F:tests/state_sync/root_corruption.rs†L1-L53】【F:docs/runbooks/observability.md†L88-L96】 |
| Block Lifecycle | `lifecycle.pipeline`, `lifecycle.state_sync`, `lifecycle.observability` | Done – Der Pipeline-Orchestrator koppelt Wallet, Proof, BFT und Firewood, erzeugt `PipelineStageEvent`s für Tests und veröffentlicht die Stage-Historie im Dashboard-Snapshot.【F:rpp/runtime/orchestration.rs†L34-L88】【F:rpp/node/src/pipeline/mod.rs†L1-L136】 Die Hooks speisen Telemetrie-Metriken (`rpp.node.pipeline.stage_latency_ms`, `.stage_total`, `.commit_height`) und ergänzend die Snapshot-SLIs (`snapshot_bytes_sent_total`, `snapshot_stream_lag_seconds`), sodass Dashboards Latenzen, Commit-Höhen und Stream-Lag abbilden.【F:rpp/node/src/pipeline/mod.rs†L137-L164】【F:rpp/node/src/telemetry/pipeline.rs†L1-L66】【F:rpp/p2p/src/behaviour/snapshots.rs†L462-L518】【F:docs/observability/pipeline.md†L1-L98】 Regressionstests überwachen den End-to-End-Fluss über SSE, Dashboard und Prometheus (inklusive Lag- und Byte-Countern) und sichern damit die Produktionsreife der Pipeline.【F:tests/pipeline/end_to_end.rs†L1-L122】【F:tests/observability/snapshot_timetoke_metrics.rs†L70-L180】【F:docs/lifecycle/pipeline.md†L1-L75】 LightClientVerifier und Runtime-State-Sync-Cache prüfen weiterhin Snapshot-Pläne samt Pruning- und Recursive-Proofs; RPC-Tests und Dokumentation decken Status-/SSE-Endpunkte ab.【F:rpp/node/src/state_sync/light_client.rs†L24-L424】【F:rpp/runtime/node.rs†L2607-L3875】【F:rpp/rpc/tests/state_sync.rs†L71-L436】【F:docs/state_sync.md†L1-L71】【F:docs/interfaces/rpc/state_sync_status_response.jsonschema†L1-L53】 |
| Libp2p Backbone | `p2p.integrate_libp2p`, `p2p.admission_control`, `p2p.snapshot_sync` | Done – `Network::new` wires the Noise-XX handshake, peerstore bookkeeping, and behaviour hooks so runtime events surface authenticated peers, admission outcomes, and snapshot sessions.【F:rpp/p2p/src/swarm.rs†L849-L1115】 Tier-gated publish/subscribe checks and reputation penalties flow through `AdmissionControl` to enforce the blueprint’s access policies, und der Peerstore persistiert die Allow-/Blocklisten gemeinsam mit append-only Audit-Einträgen pro Änderung, abgesichert durch Tests, die die JSONL-Historie erneut laden.【F:rpp/p2p/src/admission.rs†L14-L210】【F:rpp/p2p/src/peerstore.rs†L1180-L1299】【F:rpp/p2p/src/peerstore.rs†L1795-L1828】 Operators können die Policies über die RPC-Schicht (`GET /p2p/admission/policies`, `POST /p2p/admission/policies`, `GET /p2p/admission/audit`) inklusive Dual-Control-Validierung inspizieren und anpassen.【F:rpp/rpc/src/routes/p2p.rs†L232-L379】 Snapshot streaming runs über die dedizierte Request/Response-Behaviour, exportiert `snapshot_bytes_sent_total`/`snapshot_stream_lag_seconds`, und wird durch Snapshot-/Observability-Tests validiert, die Lag- und Byte-Counter prüfen, während die Runtime den Fortschritt via `SnapshotStreamStatus` verfolgt.【F:rpp/p2p/src/behaviour/snapshots.rs†L462-L518】【F:rpp/runtime/node_runtime/node.rs†L375-L503】【F:tests/observability/snapshot_timetoke_metrics.rs†L70-L180】【F:rpp/p2p/tests/snapshot_stream.rs†L1-L200】 |
| Witness QoS & Rewards | `consensus.witness_channels` | Done – Witness-Proof- und Meta-Pipelines laufen über dedizierte Buffer mit Token-Bucket-Limits, Topics tragen explizite QoS/Prio-Metadaten und Reward-Snapshots buchen Treasury- und Fee-Pools automatisch. Dokumentation und Regressionstests decken Konfiguration sowie Accounting ab.【F:rpp/p2p/src/behaviour/witness.rs†L1-L164】【F:rpp/p2p/src/topics.rs†L1-L113】【F:tests/consensus/witness_distribution.rs†L1-L55】【F:docs/consensus/witness_channels.md†L1-L70】 |
| Malachite BFT | `consensus.malachite_distributed` | Done – Der `DistributedOrchestrator` bündelt Proposal-, Vote- und Commit-Streams für mehrere Validatoren, während der `TopicRouter` Commit-Nachrichten automatisch an die Witness-Themen weiterleitet.【F:rpp/consensus/src/malachite/distributed.rs†L1-L120】【F:rpp/consensus/src/network/topics.rs†L1-L62】 Der Evidence-Pool priorisiert Double-Sign-, Availability-, Witness-, Censorship- und Inaktivitätsmeldungen, koppelt sie an die Slashing-Heuristiken und telemetriert Zeiger in den Konsens-Status.【F:rpp/consensus/src/evidence/mod.rs†L10-L205】【F:rpp/consensus/src/state.rs†L928-L989】 Regressionstests decken die Mehrknoten-Orchestrierung sowie die Priorisierung und Witness-/Uptime-Auslöser ab.【F:tests/consensus/malachite_distributed.rs†L1-L200】【F:tests/consensus/evidence_slashing.rs†L1-L205】 Rewards verteilen Basis- und Leader-Bonus inklusive Witness-Pools und Penalty-Einbehalt, abgesichert durch Governance- und Konsenstests.【F:rpp/consensus/src/rewards.rs†L1-L120】【F:rpp/consensus/src/state.rs†L948-L989】【F:tests/consensus/timetoke_rewards.rs†L1-L54】 |
| Wallet/STWO workflows | `wallet.utxo_policies`, `wallet.zsi_workflow`, `wallet.stwo_circuits`, `wallet.uptime_proofs` | Done – Die tierbasierte Policy-Engine erzwingt Spend-Limits im Wallet und wird durch Docs/Regressionstests abgedeckt.【F:rpp/wallet/ui/policy/mod.rs†L1-L176】【F:docs/wallet/policies.md†L1-L41】【F:tests/wallet/utxo_policies.rs†L1-L104】 Der vollständige ZSI-Lifecycle (Library, CLI, RPC) ist umgesetzt und durch Dokumentation sowie Integrations-Tests verlinkt.【F:rpp/wallet/src/zsi/lifecycle.rs†L1-L233】【F:docs/wallet/zsi.md†L1-L52】【F:tests/zsi/lifecycle_flow.rs†L1-L145】 Uptime-Proofs laufen end-to-end vom Scheduler über Reputation bis zum Gossip und werden durch Tests/Docs verifiziert.【F:rpp/node/src/services/uptime.rs†L1-L200】【F:tests/consensus/uptime.rs†L1-L200】【F:docs/consensus/uptime_proofs.md†L1-L34】 |
| Electrs & wallet UI | `electrs.modes`, `electrs.ui_rpc` | Done – Wallet- und Hybrid-Profile booten Electrs-Tracker und UI-Tab-Modelle für History-, Send-, Receive- und Node-Ansichten; die Handler bereiten Skriptstatus, Sendevorschauen und Knotenmetriken für UI-Clients auf.【F:rpp/wallet/ui/wallet.rs†L736-L924】 Die RPC-Schicht exponiert kontraktversionierte `/wallet/ui/*`-Routen parallel zu den klassischen Wallet-Endpunkten, inklusive Auth-/Rate-Limits für Send/History/Node-Flows.【F:rpp/rpc/api.rs†L1405-L1440】【F:rpp/rpc/api.rs†L1806-L2690】 JSON-Schema-Tests verankern die UI-Verträge, sodass Dashboard- und Client-Integrationen auf stabile Payloads bauen können.【F:rpp/rpc/tests/wallet_ui_contract.rs†L1-L120】 |
| Plonky3 backend enablement | Roadmap Schritt 3 (Proof system phase) | **Completed 2026-02-18** – Vendor-Prover/-Verifier laufen end-to-end (`scripts/test.sh --backend plonky3`), Nightly-Simnet misst Konsensus-Latenzen inklusive Tamper-Erkennung und das Runbook dokumentiert Betrieb, Monitoring und Incident-Response.【F:scripts/test.sh†L1-L220】【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:docs/runbooks/plonky3.md†L1-L200】 |
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

