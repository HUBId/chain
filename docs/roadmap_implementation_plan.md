# Schrittweiser Implementierungsplan für den RPP End-to-End Blueprint

Dieser Plan ordnet die offenen Arbeiten aus dem Blueprint in eine umsetzbare Sequenz ein. Er verknüpft die bereits in `src/blueprint` katalogisierten Aufgaben mit konkreten Deliverables, Abhängigkeiten und Qualitätsnachweisen. Jeder Abschnitt endet mit klaren "Definition of Done"-Kriterien und Testanforderungen, damit der Fortschritt objektiv messbar bleibt.

## 0. Vorbereitungsphase
- **Quellcode-Inventur**: Blueprint-Datenstruktur, Wallet-Workflows, Firewood-State-Lifecycle und P2P-Roadmap sichten. Identifizieren, welche Module Stub-Implementierungen enthalten (z. B. VRF, BFT, libp2p).
- **Tooling & CI**: Sicherstellen, dass Formatierung (`cargo fmt`), Lints (`cargo clippy`) und Tests (`cargo test --all`) in der CI verankert sind. Ziel: Jede Blaupausenaufgabe besitzt mindestens einen automatisierten Test.
- **Teamabstimmung**: Deliverables pro Phase mit Domain-Teams (Node, Wallet, Proofs, Networking) abklären, gemeinsame Definition-of-Done dokumentieren.

## 1. Architekturgrundlagen schärfen (Blueprint 2.0)
1. **Ist-Architektur dokumentieren**
   - Deliverable: Aktualisiertes Architektur-Doc (siehe `docs/architecture_foundations.md`) mit Sequenzdiagrammen für Node, Wallet, Proof-Pipeline.
   - Abhängigkeiten: Vorbereitungsphase abgeschlossen.
   - DoD: Doc reviewed, Referenzdiagramme in Repo, Abgleich mit aktuellem Code.
2. **Schnittstellen spezifizieren**
   - Deliverable: Spezifikation der Gossip-Themen, Protobuf-/Serde-Schemata, REST-/RPC-Endpunkte.
   - Tests: Schema-Snapshots, Protobuf Roundtrip-Tests.

## 2. Firewood ↔ STWO Schnittstellen (Blueprint 2.1)
1. **Lifecycle-Services extrahieren**
   - Deliverable: Module `apply_block`, `prove_transition`, `verify_transition` mit klaren Traits.
   - Abhängigkeiten: Schnittstellendefinition aus Phase 1.
   - Tests: Unit-Tests für gültige/ungültige Übergänge, Property-Tests für Idempotenz.
2. **Block-Metadaten erweitern**
   - Deliverable: Persistente Speicherung von `(root_old, root_new, proof_hash, recursion_anchor)`.
   - Tests: Ledger-Integrationstest, der Rollbacks prüft.
3. **Pruning-Proof-Automatisierung**
   - Deliverable: Hintergrunddienst für Pruning-Verkettung + Rebuild-API.
   - Tests: Snapshot-Wiederherstellung aus historischen Proof-Ketten.

## 3. Wallet, ZSI und STWO Workflows (Blueprint 2.2)
1. **UTXO- und Tier-Policies**
   - Deliverable: UTXO-Modell im Wallet mit Reputation/Tier-Beschränkungen.
   - Tests: Wallet-E2E-Test (UTXO-Selektion, Fee-Berechnung, Tier-Verletzung).
2. **ZSI-ID Lifecycle**
   - Deliverable: Genesis- und BFT-basierte Attestierungsprozesse, Wallet-API für ID-Erneuerung.
   - Tests: Simulation von Attestierungsfehlern, Signatur-Verifikation.
3. **STWO-Circuits erweitern**
   - Deliverable: Circuits für Ownership, Balance, Double-Spend, Reputation.
   - Tests: Circuit-Korrektheit via Witness-Generator, Negativtests.
4. **Uptime-Proofs integrieren**
   - Deliverable: Periodische Proof-Generierung + Gossip-Verteilung.
   - Tests: Integration mit Node-Acceptance und Reputation-Updates.

## 4. Libp2p Netzwerk-Backbone (Blueprint 2.3)
1. **Transport & Handshake**
   - Deliverable: Libp2p mit Noise-XX, Peerstore, Identitätsprüfung (ZSI + VRF).
   - Tests: Verbindungsmatrix-Test (Peers unterschiedlicher Reputation).
2. **Gossip-Kanäle & Admission-Control**
   - Deliverable: GossipSub-Kanäle (`blocks`, `votes`, `proofs`, `snapshots`, `meta`) mit Tier-Gating.
   - Tests: Kanalzugriff je Tier-Level, Reputation-Update-Propagierung.
3. **Snapshot-Sync & Telemetrie**
   - Deliverable: Light-Client-Snapshots, Peer-Monitoring über `meta`.
   - Tests: Sync eines Light-Clients aus Snapshot, Telemetrie-Roundtrip.

## 5. VRF Validator-Selektion (Blueprint 2.4)
1. **Poseidon-VRF Implementation**
   - Deliverable: VRF-Keygen, Proof-Erstellung & -Verifikation, Gossip-Distribution.
   - Tests: Konsistenztests (Leader-Verifikation), RNG-Statistiken.
2. **Epoch Management**
   - Deliverable: Epoch-Wechsel, Validator-Set-Rotation, Weighted Lottery.
   - Tests: Epoch-Übergang ohne Double-Selection.
3. **Monitoring & Replay-Schutz**
   - Deliverable: Anti-Replay-Mechanismen, Telemetrie-Dashboards.
   - Tests: Integration mit meta-Kanal, Replay-Testfälle.

## 6. Malachite BFT & Slashing (Blueprint 2.5)
1. **Mehrknoten-BFT**
   - Deliverable: Gossip-basierte Proposal/PreVote/PreCommit-Schritte, Aggregation ≥2/3.
   - Tests: Netzwerktests mit byzantinischen Knoten.
2. **Evidence & Slashing**
   - Deliverable: Evidence-Pool, Slashing-Logik, Reputation-Anpassung.
   - Tests: Double-Sign-Simulationen, falsche Proof-Erfassung.
3. **Reward-Distribution**
   - Deliverable: Leader-/Validator-Belohnungen, Uptime-Rewards.
   - Tests: Auszahlungskonsistenz pro Block.

## 7. Electrs Binary & UI (Blueprint 2.6)
1. **Modus-Trennung**
   - Deliverable: CLI/Config für Node-, Wallet-, Hybrid-Modus.
   - Tests: Start/Stop-Skripte, Config-Roundtrips.
2. **UI-/RPC-Erweiterungen**
   - Deliverable: Tabs `History`, `Send`, `Receive`, `Node` mit den beschriebenen Daten.
   - Tests: UI-Snapshot-Tests, RPC-Contract-Tests.
3. **Validator-Werkzeuge**
   - Deliverable: VRF-Key-Management, Uptime-Reporting, Konsens-Telemetrie.
   - Tests: End-to-End-Validator-Setup-Skript.

## 8. End-to-End Block Lifecycle & Orchestrierung
1. **Pipeline-Verknüpfung**
   - Deliverable: Orchestrator, der Wallet-Gossip → Node-Mempool → VRF → BFT → Firewood → Rewards abbildet.
   - Tests: End-to-End-Blockproduktion über mehrere Prozesse.
2. **State-Sync & Light-Clients**
   - Deliverable: Snapshot-Download, Proof-Verifikation, Head-Abonnements.
   - Tests: Light-Client-Validierung, Catch-Up unter Latenz.
3. **Observability**
   - Deliverable: Tracing, Metrics, Dashboards.
   - Tests: Monitoring-Regressionstests.

## 9. Test-, Validierungs- und Simulationssuite (Blueprint 4)
1. **Unit- & Integrationstests**
   - Deliverable: Testbatterien für STWO, Firewood, VRF, BFT, Networking.
   - Tests: Automatisiert in CI, Code-Coverage-Tracking.
2. **Simulationsframework**
   - Deliverable: Szenarien mit ≥100 Wallets/20 Validatoren, parametrisiert für Latenzen.
   - Tests: Non-Regression-Reports, Reputation-Evolution-Analysen.
3. **Security & Performance Audits**
   - Deliverable: Fuzzing, Key-Management-Review, Benchmark-Suite.
   - Tests: Reproduzierbare Benchmarks, Audit-Findings geschlossen.

## 10. Deployment-Readiness & Governance
- **Konfigurations-Updates**: `config/node.toml` erweitern (Ports, Policies, Proof-Limits).
- **Sicherheitsreviews**: Threat-Model, Key-Rotation, Admission-Control.
- **Upgrade-Prozesse**: Rollback/Snapshot-Strategien, Migrationspfade.
- **Abschlusskriterien**: Erfolgreiche Simulationen, Public-Testnet mit Monitoring, vollständige Dokumentation.

## Tracking & Kommunikation
- Jede Aufgabe verweist auf den entsprechenden Schlüssel in `src/blueprint::Blueprint`.
- Fortschritt wird über ein zentrales Dashboard (z. B. `progress.json` + Grafana) transparent gemacht.
- Wöchentliche Reviews pro Sektion, monatliche Milestone-Demos (A–C).

Mit dieser Sequenz lassen sich Abhängigkeiten minimieren, Teams parallel arbeiten und der End-to-End-Blueprint schrittweise in produktionsreifen Code überführen.
