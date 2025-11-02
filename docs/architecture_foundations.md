# Architecture Foundations

## 1. Runtime Node and Execution Pipeline
- `NodeInner` owns the Firewood storage handle, ledger, and dedicated queues for
  transactions, identities, votes, uptime proofs, witness gossip, and VRF
  submissions. It also keeps consensus state, pruning jobs, and the
  `ProofVerifierRegistry` so proof verifications execute inside the runtime
  boundary.【F:rpp/runtime/node.rs†L760-L796】
- `NodeHandle` exposes submission APIs for every mempool and wires the gossip
  runtime. When a libp2p handle is attached the node spawns dedicated tasks to
  publish witness payloads, process gossip events (blocks, votes, VRF
  submissions, evidence, timetoke deltas, witness channels), and forward them
  into the consensus queues.【F:rpp/runtime/node.rs†L2061-L2075】【F:rpp/runtime/node.rs†L2544-L2680】
- The runtime persists post-finalisation state through the `StateLifecycle`
  helper: after sealing a block it emits Firewood commitments, stores pruning
  proofs, and calls `StateLifecycle::apply_block` to derive the
  `StateTransitionReceipt` used by downstream snapshot tooling.【F:rpp/runtime/node.rs†L5938-L6011】
  `StateLifecycle` exposes uniform `apply_block`, `prove_transition`, and
  `verify_transition` hooks so integration tests and alternative storage backends
  can drive transitions without reaching into internal structs.【F:rpp/storage/state/lifecycle.rs†L13-L86】

## 2. Wallet Orchestration
- The wallet keeps an embedded runtime configuration, boots the node process on
  demand, and tracks the resulting `NodeHandle` so UI commands can reuse the
  existing node instance.【F:rpp/wallet/ui/wallet.rs†L1067-L1122】
- Pipeline state (orchestrator dashboards, error feeds, witness gossip) is
  streamed into the UI by subscribing to the orchestrator channels and the node’s
  witness gossip topics, ensuring the wallet mirrors the node pipeline in real
  time.【F:rpp/wallet/ui/wallet.rs†L1123-L1197】
- Electrs tracker integration shares the same infrastructure: once tracker
  handles are configured the wallet attaches to witness gossip topics exposed by
  the node adapters and forwards finality telemetry into long-running UI tasks.【F:rpp/wallet/ui/wallet.rs†L945-L1015】

## 3. Consensus Proof Flow (VRF → Witness → Quorum)
### VRF-Erzeugung und Datenpfad
- `NodeInner::gather_vrf_submissions` filtert das VRF-Mempool nach Epoche und
  Seed, erzeugt lokale Poseidon-Ausgaben und persistiert sie. Fehler beim
  Signieren werden über strukturierte Warnungen propagiert, die Submission bleibt
  dadurch für die Quorum-Auswertung nachvollziehbar.【F:rpp/runtime/node.rs†L5036-L5099】
- `Block::verify_consensus_certificate_with_metrics` validiert die im Header
  eingebetteten VRF-Daten gegen den vorherigen Block-Hash. Die Methode misst
  Verifikationslatenzen und markiert misslungene Prüfungen (`invalid_vrf_proof`)
  über Prometheus-Metriken, bevor sie einen `ChainError::Crypto` auslöst.【F:rpp/runtime/types/block.rs†L2008-L2050】
- Tests wie `tests/vrf_selection.rs` prüfen, dass die Konsens-Runde die VRF-
  Historie korrekt rekonstruiert und dass Knoten ohne gültige VRF-Ausgaben keine
  Quoren erreichen.【F:tests/vrf_selection.rs†L12-L120】

### Witness-Bündel und Constraints
- `WalletProver::build_consensus_witness` stellt sicher, dass VRF-Ausgaben,
  Witness-Commitments und Reputation-Roots vollständig und größenkonform sind,
  bevor der STWO-Zeugnisdatensatz erzeugt wird. Abweichungen führen zu
  `ChainError::Crypto` mit aussagekräftigen Fehlermeldungen, die das Monitoring
  unmittelbar korrelieren kann.【F:rpp/proofs/stwo/prover/mod.rs†L419-L472】
- `Block::verify_consensus_certificate_with_metrics` erzwingt zusätzliche
  Invarianten: Vote-Sets müssen den erwarteten Rundenzähler, Block-Hash und
  Quorum-Schwellen erfüllen, Witness-Teilnehmer müssen mit den Commit-Votes
  übereinstimmen, und doppelte Stimmen werden abgewiesen. Jeder Bruch setzt
  spezifische `consensus_quorum_verification_failure`-Labels, um Runbooks direkt
  auf die Metrikwerte zu verweisen.【F:rpp/runtime/types/block.rs†L2051-L2332】
- Das Witness-Commitment wird parallel über die Konsens-Gossip-Pipeline
  repliziert (`witness_events` im Node-Status), wodurch Quorum-Entscheidungen in
  Wallet und Operator-Dashboards synchron bleiben.【F:rpp/runtime/node.rs†L5036-L5099】【F:rpp/runtime/node.rs†L5005-L5019】

### Quorum-Auswertung und Fehlerbehandlung
- Die Quorum-Logik sammelt Vote-Gewichte, prüft Schwellenwerte (`quorum_threshold`,
  `commit_power`) und verweist bei Abweichungen auf dedizierte
  Fehlermeldungen. Gleichzeitig zeichnet der Runtime-Metrikexporter erfolgreiche
  und fehlerhafte Quorum-Verifikationen auf, sodass Dashboards wie
  `docs/dashboards/consensus_grafana.json` automatisiert regressionswarnungen
  auslösen.【F:rpp/runtime/types/block.rs†L2140-L2328】【F:docs/dashboards/consensus_grafana.json†L1-L200】
- Runbooks (`docs/runbooks/observability.md`) führen Operatoren durch die
  Auswertung dieser Metriken: Simulationstests und `curl /status/consensus`
  dienen als erste Fehlerlokalisierung, während das Konsens-Grafana-Board die
  Resultate der VRF- und Witness-Prüfpfade kontrastiert.【F:docs/runbooks/observability.md†L27-L59】
- Automatisierte Szenarien wie `tools/simnet/scenarios/consensus_quorum_stress.ron`
  werden über das Observability-Runbook und den Simnet-Harness verlinkt, um
  Fehlpfade (z. B. manipulierte Witness-Bundles) reproduzierbar zu machen.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】
- Bei persistierenden Fehlern aktualisiert `consensus_proof_status` das
  Node-API-Abbild; das Wallet und externe Auditoren können dadurch den letzten
  gültigen Nachweis samt Witness-Commitments abfragen und Runbook-Schritte
  sequentiell ausführen.【F:rpp/runtime/node.rs†L5005-L5035】【F:rpp/rpc/src/routes/consensus.rs†L30-L95】

## 4. Gossip and Network Backbone
- Gossip topics are versioned under `/rpp/gossip/*` and cover block proposals,
  votes, proof bundles, VRF submissions, snapshot sync, and witness relays. The
  topic set is centralised in `rpp_p2p::topics::GossipTopic`, ensuring every
  network component references the same canonical identifiers.【F:rpp/p2p/src/topics.rs†L6-L85】
- Once the node attaches to a libp2p handle it consumes structured `NodeEvent`
  messages: block proposals feed the proposal inbox, votes enter the consensus
  queues, VRF submissions update the epoch lottery, evidence and timetoke deltas
  adjust local state, and witness payloads are re-broadcast over the dedicated
  witness fan-out channels.【F:rpp/runtime/node.rs†L2544-L2680】
- Schema snapshots for all gossip payloads live under
  [`docs/interfaces/p2p`](interfaces/p2p_payloads.md) and are validated by the
  `rpp_p2p` schema round-trip tests, keeping the documentation aligned with the
  `rpp_p2p` ingestion pipeline.【F:rpp/p2p/src/pipeline.rs†L2204-L2339】

## 5. Interface Contract
- [`docs/interfaces/spec.md`](interfaces/spec.md) consolidates the canonical JSON
  Schemas for gossip topics, RPC endpoints, and state transition receipts. Each
  table links to the schema snapshot, the handler or topic in code, and the test
  module that enforces the contract.【F:docs/interfaces/spec.md†L1-L133】
- Runtime payload schemas (transactions, uptime, state transition receipts) are
  validated by unit tests in `rpp::runtime::types` and `rpp::storage`, while the
  RPC and gossip schemas are validated by their respective module tests. These
  schema tests run in CI via the standard `cargo test` workflows, providing
  automated drift detection for the published contracts.【F:rpp/runtime/types/mod.rs†L41-L124】【F:rpp/runtime/types/mod.rs†L125-L160】【F:rpp/storage/mod.rs†L664-L760】【F:rpp/storage/mod.rs†L842-L924】【F:rpp/rpc/api.rs†L2968-L3088】【F:rpp/p2p/src/pipeline.rs†L2204-L2339】

## 6. Updated Diagrams
- `docs/architecture/wallet_node_sequence.drawio` and the derived SVG illustrate
  the wallet → prover → node → storage flow with crate-qualified component names
  and the witness feedback loop for telemetry.
- `docs/architecture/rpp_domain_model.drawio` and its SVG capture the runtime,
  storage, proof, VRF, consensus, and gossip domains with the crate names used in
  the current implementation.

## 7. Blueprint Alignment (`Blueprint::rpp_end_to_end`)

| SectionId / Task-Key | Blueprint Description | Coverage in this Document |
| --- | --- | --- |
| `architecture.document_foundations` | Document the current architecture | Sections 1–4 describe the live runtime, wallet, proof, and gossip flows backed by code references. |
| `architecture.spec_interfaces` | Publish interface specifications | Section 5 links to the consolidated interface spec and enumerates the schema tests guarding it. |
| `firewood-stwo.state.lifecycle_api` | Extract lifecycle services | Sections 1 & 3 call out the `StateLifecycle` API and how it is used by the node. |
| `firewood-stwo.state.block_metadata` | Extend block metadata | Sections 1 & 4 describe the Firewood receipts and gossip metadata that expose pruning commitments. |
| `firewood-stwo.state.pruning_jobs` | Automate pruning proofs | Section 1 references the runtime’s pruning job tracking and storage receipts. |
| `wallet-workflows.wallet.utxo_policies` | Model wallet UTXO/tier policies | Section 2 covers the wallet runtime orchestration and pipeline feeds. |
| `wallet-workflows.wallet.zsi_workflow` | Capture ZSI identity lifecycle | Sections 2 & 3 detail how identities are orchestrated through wallet proofs and node mempools. |
| `wallet-workflows.wallet.stwo_circuits` | Expand STWO circuits | Section 3 documents how witnesses and proofs map to the prover traits. |
| `wallet-workflows.wallet.uptime_proofs` | Integrate uptime proofs | Sections 2 & 3 cover wallet scheduling and STWO uptime witnesses. |
| `libp2p.p2p.integrate_libp2p` | Integrate libp2p backbone | Section 4 outlines the gossip topic wiring and node event handling. |
| `libp2p.p2p.admission_control` | Admission control | Section 4 highlights witness fan-out and gossip ingestion points controlling network flows. |
| `libp2p.p2p.snapshot_sync` | Snapshot sync | Section 4 references snapshot topics and schemas under `docs/interfaces/p2p`. |
| `vrf.poseidon_impl` / `vrf.epoch_management` | VRF implementation & epochs | Sections 1 & 4 cover the VRF mempool, submission handling, and epoch manager usage. |
| `vrf.monitoring` | VRF monitoring | Sections 1 & 4 describe VRF metrics exposed by the runtime. |
| `bft.*` | BFT loops, evidence, rewards | Sections 1 & 4 note the consensus state, evidence pool, and gossip integration. |
| `lifecycle.*` | Lifecycle orchestration | Sections 1, 3, & 5 show the end-to-end pipeline and contract tests. |
| `testing.*` | Test and validation suite | Section 5 enumerates the schema tests enforced in CI. |

## 8. Open Questions/Follow-ups
- GPU-gestütztes Witness-Caching und Circuit-Optimierung zur Reduktion der VRF-
  und Quorum-Latenzen stehen weiterhin aus und sind für Phase 2.1 eingeplant.
- Das Observability-Runbook sieht zusätzliche Drill-down-Dashboards für Witness-
  Outliers vor; die Panels werden nach Abschluss der erweiterten Telemetrie
  (zusätzliche Labels für Witness-Pipelines) ergänzt.
- Performance-Regressionstests für das Simnet-Quorum-Szenario laufen aktuell nur
  nightly. Eine Integration in den PR-Gating-Fluss bleibt ein offener Punkt.
