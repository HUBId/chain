# Schrittweiser Implementierungsplan für den RPP End-to-End Blueprint

Dieser Plan ordnet die offenen Arbeiten aus dem Blueprint in eine umsetzbare Sequenz ein. Er verknüpft die bereits in `rpp/proofs/blueprint` katalogisierten Aufgaben mit konkreten Deliverables, Abhängigkeiten und Qualitätsnachweisen. Jeder Abschnitt endet mit klaren "Definition of Done"-Kriterien und Testanforderungen, damit der Fortschritt objektiv messbar bleibt.

## Phase A Reporting & Evidenzlinks

Phase A verfolgt die externe Härtung der Snapshot-Kette. Der wöchentliche Statusbericht referenziert jetzt die drei Kernnachweise direkt, und die [Phase‑A Acceptance Checklist](runbooks/phaseA_acceptance.md) bündelt die verbindlichen Exit-Kriterien für Releases:

- `snapshot-verify-report` (CI-Job `snapshot-verifier`) für aggregierte Manifest-Prüfungen samt Hash-Artefakten.
- `worm-export-smoke` (Nightly-Job) für Export-Summaries und Checksummen der WORM-Streams.
- `threat-model-review` (Security-Workflow) für das Review-Protokoll und aktualisierte Threat-Model-Einträge.

Die Controls **Snapshot Manifest Verification** und **Audit Log WORM Export**
sind seit dem 24. Juli 2026 im [Security Risk Register](security/register.md#implemented-controls)
als *Implemented* dokumentiert, inklusive Links zur Phase‑A-Checkliste und zum
[Threat Model Addendum](security/threat_model.md#phase-a-review-summary), damit
Audit-Stakeholder die Artefakte (`snapshot-verify-report.json`,
`worm-export-summary.json`) unmittelbar nachvollziehen können.

Die entsprechende Vorlage (`docs/status/weekly_template.md`) enthält feste Platzhalterlinks auf die Actions-Runs, damit Phase‑A-Audits jede Woche denselben Nachweisumfang erhalten.

## Phase 1 abgeschlossen (Stand: 2025-09-12)

Die erste Tranche des End-to-End-Blueprints ist abgeschlossen. Die folgenden Arbeitspakete wurden geliefert und entsprechen der dokumentierten Definition of Done:

- [Plonky3-Arbeiten](testing/plonky3_experimental_testplan.md) – Der Vendor-Prover/-Verifier laufen in Produktion; Testplan, Leistungsreport und Runbook dokumentieren Acceptance-Kriterien, Nightly-Stresstests und Betriebsabläufe.【F:docs/testing/plonky3_experimental_testplan.md†L1-L120】【F:docs/performance/consensus_proofs.md†L1-L200】【F:docs/runbooks/plonky3.md†L1-L200】
- [Root-Guards & Telemetrie](observability/firewood_root_integrity.md) – Firewood-Snapshots und Trie-Wurzeln werden überwacht; Regressionstests schützen gegen Root-Korruption und dokumentieren das Incident-Playbook.【F:docs/observability/firewood_root_integrity.md†L1-L52】【F:tests/state_sync/root_corruption.rs†L1-L53】
- [CI-Erweiterung](test_validation_strategy.md#4-cicd-integration) – Die verpflichtenden Checks erzwingen `fmt`, `clippy`, die vollständige Backend-Testmatrix und das neue Runtime-Smoke-Gate, das Health-/Metrics-Endpunkte prüft und Artefakte bereitstellt. Contributors erhalten passende Reproduktionskommandos direkt in der Dokumentation.【F:docs/test_validation_strategy.md†L41-L89】【F:docs/test_validation_strategy.md†L98-L134】

### Akzeptanzkriterien (Phase 1)

- Alle Proof-Pfade (STWO & Plonky3) werden durch die in `scripts/test.sh` orchestrierte Backend-Matrix (Default, STWO, RPP-STARK, Plonky3) abgedeckt.【F:scripts/test.sh†L1-L210】
- Root-Integritätsverletzungen lösen dokumentierte Telemetrie- und Testsignale aus (`firewood_root_integrity`, `root_corruption`-Regression), sodass Operatoren sie im Dashboard nachvollziehen können.【F:docs/observability/firewood_root_integrity.md†L1-L52】【F:tests/state_sync/root_corruption.rs†L1-L53】
- Die CI-Gates spiegeln die lokalen Reproduktionsschritte wider und blockieren Merges, solange `fmt`, `clippy` oder die vollständige Testmatrix fehlschlagen.【F:docs/test_validation_strategy.md†L41-L83】

## Phase 2 Exit Criteria (Arbeitsstand)

Die vollständige Artefakt- und Nachweisliste für die Freigabe ist in der
[Phase‑2 Acceptance Checklist](runbooks/phase2_acceptance.md) gebündelt.

## Phase C Fortschritt (Stand: 2026-08-01)

Phase C bündelt die Betriebskontrollen für Langzeit-Retention, Evidenz-
Integrität und Chaos-Drills. Die Acceptance-Checklist erfasst jetzt die
zusätzlichen Exit-Kriterien für WORM-Verifikation, Evidence-Bundle-Abnahme
und Chaos-Test-Auswertung; die Playbook-Reviews sind Teil des Sign-offs.

- **WORM-Retention:** Nightly-Artefakte `worm-retention-report.json` werden im
  Phase‑C-Bundle archiviert und durch Storage Engineering via
  `cargo xtask worm-retention-check` gegengeprüft, bevor das Audit-Ticket
  geschlossen wird.【F:docs/runbooks/phaseC_acceptance.md†L60-L66】
- **Evidence-Bundle:** `phase3-evidence-<timestamp>` enthält jetzt die
  Phase‑C-Artefakte (`worm-export/`, `snapshot-signatures/`,
  `chaos-reports/`); Manifest-Hash und Index-Eintrag sichern die
  Nachvollziehbarkeit.【F:docs/runbooks/phaseC_acceptance.md†L67-L72】【F:docs/governance/evidence_bundle_index.md†L1-L85】
- **Chaos-Drills:** Die jüngsten `snapshot_partition_report.json`-Ergebnisse
  werden mit Prometheus-/Grafana-Exports abgeglichen und im Incident-Log
  dokumentiert, bevor der Phase‑C-Sign-off erfolgt.【F:docs/runbooks/phaseC_acceptance.md†L73-L77】
- **Incident-Playbook Review:** Der Abschnitt "Phase‑C Kontrollen" im Incident
  Response Playbook ist durch Compliance, Release Engineering und Security
  abgestimmt und im On-Call-Handbuch verlinkt.【F:docs/runbooks/phaseC_acceptance.md†L78-L82】【F:docs/runbooks/incident_response.md†L1-L200】

Der wöchentliche Statusbericht verlinkt die neuen Artefakte und festigt den
Phase‑C-Fortschritt in den Compliance-Logs.【F:docs/status/weekly.md†L1-L200】

Der Nightly-Workflow erstellt zusätzlich den Markdown-Block `phaseC_status.md`,
der die jüngsten `worm-retention-report.json`- und
`snapshot_partition_report.json`-Ergebnisse aggregiert und in den Weekly-Report
einspeist. Fehlende Artefakte oder Warnungen werden dort als ⚠️/❌ markiert,
wodurch Storage und Operations offene Checks direkt sehen und die betroffenen
Nightly-Artefakte nachziehen können.【F:.github/workflows/nightly.yml†L1-L200】【F:scripts/update_nightly_status.py†L1-L360】【F:docs/status/weekly.md†L1-L40】【F:phaseC_status.md†L1-L3】

## Phase 2 abgeschlossen (Stand: 2026-04-15)

Phase 2 ist offiziell abgeschlossen. Die erweiterten Proof-Pfade (ENG‑742/ENG‑743) laufen stabil in STWO und Plonky3, die dreistufige Test-Suite (`unit-suites`, `integration-workflows`, `simnet-smoke`) ist als Pflichtgate aktiv, und neue Observability-Artefakte (Dashboards, Alerts, Runbooks) sichern VRF-/Quorum-Metriken für Audits und Betrieb.

Die dreistufige Test-Suite aus `cargo xtask`-Läufen ist vollständig grün und in die verpflichtenden Branch-Protections eingebunden. Damit sind die Unit-, Integrations- und Simulationsabdeckungen aus Phase 2 messbar abgeschlossen.

- **`unit-suites` (CI):** Führt `cargo xtask test-unit` über Default-, Produktions-, Plonky3-, GUI- und Wallet-Sicherheits-Varianten aus (~12 Minuten gesamt), archiviert deterministische Proof-/VRF-Suites und legt redaktierte Artefakte pro Feature-Set ab.【F:.github/workflows/ci.yml†L635-L700】【F:tests/zsi_renewal.rs†L1-L165】【F:scripts/ci/collect_test_artifacts.sh†L1-L55】
- **`integration-workflows` (CI):** Reproduziert die End-to-End-Workflows über alle Feature-Varianten (~18 Minuten) und stellt für jede Kombination ein redaktiertes Artefaktpaket bereit.【F:.github/workflows/ci.yml†L768-L830】【F:scripts/ci/collect_test_artifacts.sh†L1-L55】
- **`simnet-smoke` (CI):** Orchestriert alle drei Simnet-Szenarien (`ci_block_pipeline`, `ci_state_sync_guard`, `consensus_quorum_stress`) für jedes Feature-Set (~22 Minuten) und publiziert Summaries plus Sanitized-Logs (`simnet-smoke-<variant>`).【F:.github/workflows/ci.yml†L864-L918】【F:scripts/ci/collect_test_artifacts.sh†L1-L55】
- **`runtime-smoke` (CI):** Baut `rpp-node`, startet die Node-, Wallet- und Hybrid-Modi seriell, prüft die Health-/Metrics-Endpunkte und veröffentlicht Log-/Metrik-Artefakte (`runtime-smoke`). Fehlerhafte Health- oder Metrics-Antworten stoppen den Merge sofort.【F:.github/workflows/ci.yml†L185-L316】
- **`validation` & `simnet` (Nightly):** Das Nightly-Pendant (`cargo xtask test-all` sowie das dedizierte Simnet-Harness) bestätigt die Phase‑2-Abdeckung täglich und lädt die Artefakte (`simnet-nightly`) zur Nachvollziehbarkeit hoch. Die Matrix benötigt ~35 Minuten, der Simnet-Harness ~15 Minuten für Analyse und Packaging.【F:.github/workflows/nightly.yml†L88-L124】【F:.github/workflows/nightly.yml†L148-L183】

Die Jobs sind als verpflichtende Statuschecks verdrahtet und bilden die Grundlage für Audits und Regressionen der Phase‑2-Abnahme.

- **Tests:** `cargo xtask test-consensus-manipulation` läuft in beiden Backends und dokumentiert VRF-/Quorum-Manipulationen.
  Ergebnisse werden in den Simnet-/Testreports verlinkt.【F:xtask/src/main.rs†L1-L120】【F:tests/consensus/consensus_certificate_tampering.rs†L1-L160】
- **Observability:** Neue Panels in `docs/dashboards/consensus_grafana.json` zeigen VRF-Latenzen und Quorum-Fehlerquoten; das
  Konsens-Observability-Handbuch beschreibt Schwellenwerte und Alarmierung.【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:docs/observability/consensus.md†L1-L70】
- **Runbooks & Operator-Guides:** `docs/rpp_node_operator_guide.md` und `docs/runbooks/observability.md` dokumentieren die
  erforderlichen CLI-/RPC-Schritte inklusive Simnet-Belege und Dashboard-Screenshots für Auditor:innen.【F:docs/rpp_node_operator_guide.md†L120-L174】【F:docs/runbooks/observability.md†L1-L120】

### Phase 3 Preview

**Abschluss (2026-06-19):** Die Admission-Control-Strecke persistiert Allow-/Blocklisten inklusive Audit-Trail im Peerstore, exponiert Dual-Control-gesicherte RPCs und exportiert Snapshot-SLIs (`snapshot_bytes_sent_total`, `snapshot_stream_lag_seconds`), die durch Observability-Tests validiert werden.【F:rpp/p2p/src/peerstore.rs†L1180-L1299】【F:rpp/p2p/src/peerstore.rs†L1795-L1828】【F:rpp/rpc/src/routes/p2p.rs†L232-L379】【F:rpp/p2p/src/behaviour/snapshots.rs†L462-L518】【F:tests/observability/snapshot_timetoke_metrics.rs†L70-L180】 Phase‑3 schließt damit den Networking-/Snapshot-Schwerpunkt ab.

- **Runbook:** Das [Network Snapshot Failover Runbook](runbooks/network_snapshot_failover.md) dokumentiert Diagnose-, Resume- und Recovery-Schritte inklusive RPC-/CLI-Beispielen und verweist auf die relevanten SLOs und Tests.【F:docs/runbooks/network_snapshot_failover.md†L1-L176】
- **Dashboard:** `docs/dashboards/pipeline_overview.json` liefert Panels für Snapshot-Durchsatz und Stream-Lag, die direkt auf den neuen SLIs aufsetzen.【F:docs/dashboards/pipeline_overview.json†L200-L260】
- **Alerts:** `docs/observability/alerts/snapshot_stream.yaml` definiert Warning-/Critical-Regeln für Lag, Durchsatz und Chunk-Fehler und verlinkt das Runbook für Eskalationen.【F:docs/observability/alerts/snapshot_stream.yaml†L1-L66】

Die folgenden Arbeiten bleiben als Fokus für Phase‑3-Nacharbeiten und spätere Erweiterungen:

- **Netzwerk & Snapshot-Verteilung:** Ausbau der verteilten Snapshot-Pipeline mit Fokus auf inkrementelle Resume-Pfade und Gossip-Backpressure (siehe Abschnitt 4.3 „Snapshot-Sync & Telemetrie“ und `SnapshotsBehaviour`).
- **Tier-Admission-Härtung:** Weiterführung der Admission-Control-Arbeiten aus Abschnitt 4.2 inklusive Witness-Kanäle und Observer-Handshakes, gekoppelt mit Reputation-Decay und Ban-Propagation.
- **State Sync & Firewood/Proof-Verzahnung:** Vorziehen der Tasks aus Abschnitt 2 (`prove_transition`, Snapshot-Rebuild-Service) zur Vorbereitung der Witness-Gossip-Feeds.
- **Witness- und Tier-Networking:** Anschlussarbeiten an Abschnitt 6.4/6.5, um Witness-Gossip und Reward-Pools in die härtere Admission-Control zu integrieren.
- **Abnahme-Nachweise bündeln:** Die Phase‑3-Artefakte (Snapshot-SLIs, Admission-Persistenz, Timetoke-Replay, Observability-Drills) werden zentral in der [Phase‑3 Acceptance Checklist](runbooks/phase3_acceptance.md) nachgehalten.

<a id="eng-742-constraint-layer-vrfquorum-enforcement"></a>
### ENG-742 – Constraint-layer VRF/quorum enforcement *(Status: ✅ Delivered)*

- **Scope:** STWO- und Plonky3-Backends erweitern, damit sie VRF-Transkripte deterministisch nachrechnen, Merkle-Bindungen
  validieren und den Quorum-Threshold im AIR/Gate-Set erzwingen.
- **Deliverables:**
  - STWO Consensus-Circuit rechnet jede VRF-Eintragung mit Schnorrkel nach, vergleicht das abgeleitete Randomness-Feld,
    prüft Epoch-/Header-Kohärenz und faltet die Poseidon-Bindings zurück in die Public Inputs.【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L300-L586】【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L1068-L1135】
  - Plonky3 spiegelt den Pfad über `ConsensusCircuit::validate`, das VRF- und Binding-Felder sanitized, den AIR-Trace mit
    Poseidon-Schwämmen rekonstruiert und Quorum-Schwellenwerte erzwingt.【F:prover/plonky3_backend/src/circuits/consensus.rs†L520-L690】【F:prover/plonky3_backend/src/circuits/consensus.rs†L1230-L1340】
  - Öffentliche Dokumentation der neuen Constraint-Zählungen via `cargo xtask proof-metadata`.
- **Statusbeleg:** Tamper-Zertifikate schlagen in beiden Backends fehl (`cargo xtask test-consensus-manipulation`), womit die
  Constraint-Layer-Verstärkungen unter Realbedingungen überprüft werden.【F:tests/consensus/consensus_proof_tampering.rs†L100-L320】【F:xtask/src/main.rs†L78-L125】

<a id="eng-743-tamper-regression-hardening"></a>
### ENG-743 – Tamper regression hardening *(Status: ✅ Delivered)*

- **Scope:** Test-Suites erweitern (`tests/consensus/consensus_proof_tampering.rs`, Backend-spezifische Tests), um gefälschte
  VRF-Outputs, Proofs, Bitmap-Roots und Signaturwurzeln abzulehnen, sobald ENG-742 die Constraint-Ebene liefert.
- **Deliverables:**
  - Integrationstests, die valide Zeugendaten verfälschen und `verify_consensus` für STWO und Plonky3 fehlschlagen lassen.【F:tests/consensus/consensus_proof_tampering.rs†L100-L320】【F:prover/plonky3_backend/tests/consensus.rs†L520-L690】
  - Nightly-/CI-Jobs, die die neuen Szenarien automatisch ausführen (`cargo xtask test-consensus-manipulation`).【F:xtask/src/main.rs†L78-L125】【F:.github/workflows/nightly.yml†L80-L120】
- **Statusbeleg:** Die Regressionstabelle `docs/testing/consensus_regressions.md` führt die Tamper-Szenarien mit beiden Backends
  als ✅ und dient als Referenz in Acceptance- und Operator-Dokumentation.【F:docs/testing/consensus_regressions.md†L1-L32】

## 0. Vorbereitungsphase
- **Quellcode-Inventur**: Blueprint-Datenstruktur, Wallet-Workflows, Firewood-State-Lifecycle und P2P-Roadmap sichten. Identifizieren, welche Module noch experimentelle Pfade enthalten (z. B. GPU-Optimierung für Plonky3, erweiterte VRF-Distribution).
- **Tooling & CI**: Der Workflow [`CI`](../.github/workflows/ci.yml) erzwingt neben dem Dashboard-Lint drei verpflichtende Gates: `fmt` (`cargo fmt --all -- --check`), `clippy` (`cargo clippy --workspace --all-targets --all-features -- -D warnings`) und `test` (`./scripts/test.sh --all`). Jede Blaupausenaufgabe muss diese Jobs grün halten; Reproduktionen laufen lokal mit denselben Kommandos, bevor Änderungen gemergt werden.
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
   - Status: ✅ Abgeschlossen – `Network::new` setzt Noise-XX-Handshakes um, signiert die Payload mit dem Node-Keypair und verankert Peerstore-/Telemetry-Hooks, sodass authentifizierte Peers und ihre Tier-Attribute im Runtime-Event-Stream landen.【F:rpp/p2p/src/swarm.rs†L849-L1009】
   - Tests: Integrationstests wie `access_control` fahren signierte Handshakes über das vendorte Libp2p-Stack und prüfen Tier- und Sperrlistenpfade.【F:rpp/p2p/tests/access_control.rs†L423-L515】
2. **Gossip-Kanäle & Admission-Control**
   - Status: ✅ Abgeschlossen – `AdmissionControl` erzwingt pro Topic Publish-/Subscribe-Policies, vergibt Reputation und sperrt Peers bei Verstößen, während das Swarm-Hook-System Remote-Zugriffe unmittelbar ablehnt.【F:rpp/p2p/src/admission.rs†L14-L210】【F:rpp/p2p/src/swarm.rs†L1034-L1115】
   - Tests: Tier-Gating, Reputation-Decay und Ban-Propagation werden durch die `access_control`-Suite abgedeckt.【F:rpp/p2p/tests/access_control.rs†L423-L515】
3. **Snapshot-Sync & Telemetrie**
   - Status: ✅ Abgeschlossen – `SnapshotsBehaviour` betreibt das `/rpp/snapshots/1.0.0` Request/Response-Protokoll, während der Runtime-`SnapshotStreamStatus` Fortschritt, Resume-Offsets und Fehler für RPC/Telemetry verfolgt.【F:rpp/p2p/src/behaviour/snapshots.rs†L58-L520】【F:rpp/runtime/node_runtime/node.rs†L375-L503】
   - Tests: `snapshot_stream` validiert Plan-/Chunk-/Ack-Flows inklusive Resume-Gating über eine Mock-Provider-Implementierung.【F:rpp/p2p/tests/snapshot_stream.rs†L1-L200】

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
4. **Timetoke-Synchronisation härten** *(neu)*
   - Deliverable: Netzwerkweiter Sync-Plan für `timetoke_snapshot`/`sync_timetoke_records` inkl. Replay-Schutz und Delta-Gossip.
   - Tests: Snapshot-Replay gegen manipulierte/alte Timetoke-Daten, Roundtrip über mehrere Nodes.

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
4. **Witness-Gossip & Admission-Control** *(neu)*
   - Deliverable: Dedizierte Witness-Kanäle (`proofs`, `meta`) mit Tier-Gating und Observer-Handshakes.
   - Tests: Zugriffskontrollen für Tier 1–2, Witness-Abstimmungen gegen byzantinische Leader.
5. **Reward-Parametrisierung für Witnesses** *(neu)*
   - Deliverable: Konfigurierbare Pools für Validator-, Leader- und Witness-Rewards (z. B. Anteil Leader-Bonus, Witness-Quoten).
   - Tests: Auszahlungssimulation mit variierenden Pools, ökonomische Regressionstests.

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
   - Deliverable: Testbatterien für STWO, Plonky3 (opt-in), Firewood, VRF, BFT, Networking.
   - Tests: Automatisiert in CI; `cargo xtask` akzeptiert Matrix-Flags wie `XTASK_NO_DEFAULT_FEATURES=1 XTASK_FEATURES="prod,prover-stwo"` bzw. `...backend-plonky3`.
   - Laufzeiten: Standard-Lauf ~85 s (Cold) / 11 s (Warm) auf `ubuntu-latest`; Feature-Läufe verlängern den Cold-Start um wenige Sekunden.【F:.github/workflows/ci.yml†L66-L118】【F:xtask/src/main.rs†L1-L91】【f3105d†L1-L5】【f3e57e†L1-L5】
2. **Simulationsframework**
   - Deliverable: Szenarien mit ≥100 Wallets/20 Validatoren, parametrisiert für Latenzen.
   - Status: `tools/simnet` orchestriert Nodes, Wallets und die bestehenden `rpp/sim`-Topologien; Nightly-CI (`.github/workflows/nightly.yml`) fährt die referenzierte Szenariobibliothek (inkl. `ci_state_sync_guard.ron`) und wertet sie mit `scripts/analyze_simnet.py` aus.
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
- Jede Aufgabe verweist auf den entsprechenden Schlüssel in `rpp::proofs::blueprint::Blueprint`.
- Fortschritt wird über ein zentrales Dashboard (z. B. `progress.json` + Grafana) transparent gemacht.
- Wöchentliche Reviews pro Sektion, monatliche Milestone-Demos (A–C).

Mit dieser Sequenz lassen sich Abhängigkeiten minimieren, Teams parallel arbeiten und der End-to-End-Blueprint schrittweise in produktionsreifen Code überführen.
