# Libp2p-Netzwerk-Backbone – Umsetzungsplan

Dieser Plan gliedert die Umsetzung des Blueprint 2.3 in klar umrissene Liefergegenstände mit definierten Abhängigkeiten, Qualitätskriterien und Tests. Jeder Abschnitt endet mit „Definition of Done“ (DoD), damit Fortschritt messbar bleibt.

> **Aktueller Stand:** Die öffentliche RPC-Schnittstelle verwaltet keinen Libp2p-Knoten. Runtime-Handles werden ausschließlich innerhalb der Runtime verwendet und nicht via `ApiContext` exponiert. Operator-Steuerung des Netzwerks bleibt damit ausdrücklich Teil der nachstehenden Deliverables.

## Phase 0 – Grundlagen & Infrastruktur
1. **Libp2p-Abhängigkeiten und Runtime integrieren**
   - `libp2p`-, `tokio`- und `futures`-Versionen wählen, die mit dem bestehenden Async-Stack kompatibel sind.
   - Eigenes `NodeKeypair` (Ed25519) auf Persistenz heben.
   - DoD: `cargo check`, `cargo fmt`, Smoke-Test mit initiiertem Swarm.

2. **Noise-XX Handshake + Peerstore**
   - Noise-Konfiguration mit statischem Schlüssel + Ephemeral Keypair aufsetzen.
   - ZSI-ID + VRF-Proof im Handshake transportieren (Custom Protocol oder secio Peer Records).
   - Peerstore implementieren (Memory + persistente Cache-Option) mit Reputation-/Tier-Attributen.
   - DoD: Zwei Nodes stellen Noise-XX Verbindung her und tauschen Metadaten aus.

3. **Kanal- und Topic-Definitionen**
   - GossipSub-Topics (`blocks`, `votes`, `proofs`, `snapshots`, `meta`) als Konstanten inkl. Message-Schema definieren.
   - Canonical Binary Encoding (z. B. Prost) festlegen, Schema-Validierungen via unit tests.
   - DoD: Message-Typen und Encoding-Tests vorhanden, Topics registriert.

## Phase 1 – Gossip-Backbone & Admission Control
4. **GossipSub-Konfiguration**
   - Mesh/Peer-Score-Parameter an Reputation/Tier koppeln.
   - Heartbeat, Mesh-Pruning und Score-Decay konfigurieren.
   - DoD: Nodes können sich gegenseitig Nachrichten in allen Topics senden, Peer-Score aktualisiert sich.

5. **Admission Control Layer**
   - Reputation-/Tier-Logik anbinden: TL0 (read-only), TL1 (Proof-Publish), TL3+ (Consensus).
   - Subscription-Gating pro Topic, Reject-Mechanismen bei Downgrades oder Sperrlisten.
   - DoD: Integrationstest simuliert Peers verschiedener Tiers und überprüft Zugriffe.
   - Hinweis: Tier-Gating und Reputation werden gemeinsam durch den Integrationstest `rpp/p2p/tests/access_control.rs` abgesichert.

6. **Reputation-Updates & Sperrlisten**
   - Netzwerkweite Reputation-Events (Uptime, Slashing, Votes) konsumieren und Peerstore aktualisieren.
   - Dynamic Penalties (Score-Decay, Ban Windows) implementieren.
   - DoD: Telemetrie zeigt Reputation-Änderungen, gebannte Peers verlieren Zugriff.

## Phase 2 – Datenpfade & Synchronisation
7. **Proofs- und Transaction-Pipeline**
   - Gossip-Nachrichten in lokale Queues (Proof-Mempool) einspeisen.
   - Deduplication + Validation Hooks (STWO, Reputation) einbauen.
   - DoD: Eingehende Proofs werden persistiert und validiert.

8. **Blocks & Votes**
   - Blockvorschläge über `blocks` Topic verteilen, Votes über `votes` Topic.
   - Konsensmodul an Gossip-Ereignisse anschließen (Proposal, PreVote, PreCommit).
   - DoD: Multi-Node-Test produziert Block mit >=2/3 Votes.
   - DoD-Nachweis: `rpp/p2p/tests/multi_node_quorum.rs` deckt Block- und Vote-Gossip ab, inklusive Neustart der Knoten und Persistenzprüfung der Abstimmungszustände.

9. **Snapshots & Light-Client-Sync**
   - Snapshot-Streaming nutzt das dedizierte Request/Response-Behaviour (`SnapshotsBehaviour`) mit Resume-/Ack-Unterstützung, das Pläne, Chunks und Light-Client-Updates über `/rpp/snapshots/1.0.0` austauscht.【F:rpp/p2p/src/behaviour/snapshots.rs†L58-L957】
   - Der Node-Runtime-Session-Manager verfolgt jedes Streaming über `SnapshotStreamStatus`, kann Sitzungen fortsetzen und meldet Fehler/EOL-Ereignisse an RPC und Telemetrie.【F:rpp/runtime/node_runtime/node.rs†L375-L1288】
   - Light-Clients konsumieren den Stream via `LightClientSync`, validieren Recursive Proofs und veröffentlichen neue Köpfe erst nach vollständiger Verifikation.【F:rpp/p2p/src/pipeline.rs†L1311-L1497】【F:rpp/runtime/node_runtime/node.rs†L1005-L1015】
   - DoD: Integrationstest `tests/network/snapshots.rs` startet den RPC-Flow gegen einen realen Cluster, streamt Snapshots und überprüft, dass der Light-Client-Head den verifizierten Höhestand erreicht.【F:tests/network/snapshots.rs†L1-L120】

10. **Meta-Kanal & Telemetrie**
    - Peer-Heartbeat, Latenzen, Versionen über `meta` Topic publizieren.
    - Dashboard/Prometheus-Exporter füttern.
    - Libp2p-Metriken werden über eine gemeinsame `libp2p_metrics::Registry` registriert; `NetworkMetricsSnapshot` exportiert Bandbreiten- und Peer-Score-Kennzahlen der Gossip-Themen in die Telemetrie.
    - Schema-Referenz: `docs/interfaces/p2p/meta_reputation.jsonschema`, `docs/interfaces/p2p/meta_evidence.jsonschema` (inkl. Beispiele unter `docs/interfaces/p2p/examples/`).
    - DoD: Telemetrie-Events sichtbar, Alerts bei Offline-Peers.

## Phase 3 – Robustheit & Betrieb
11. **Persistence & Crash-Recovery**
    - Peerstore + Gossip-State auf Disk sichern.
    - Rejoin-Logic für Mesh/Topics nach Neustart.
    - DoD: Node rebooted und nimmt Mesh wieder auf ohne manuellen Eingriff.
    - DoD-Nachweis: `rpp/p2p/tests/gossip_state_rehydration.rs` startet zwei Knoten mit persistentem Peerstore/Gossip-State, stoppt den Konsumentenknoten kontrolliert, rehydriert `bootstrap_subscriptions`/`bootstrap_known_peers` und verifiziert, dass der `ReplayProtector` gespeicherte Digests blockiert.

12. **Security Hardening**
    - Replay-Schutz (Message-IDs, seqno), Flood-Prevention, Rate-Limits.
    - Fuzzing/Property-Tests für Decoder und Admission-Control.
    - Konfigurierbare Zugriffslisten: `p2p.allowlist` (Default: `[]`) fixiert Tier-Level erlaubter Peers,
      `p2p.blocklist` (Default: `[]`) sperrt Peers dauerhaft bereits beim Handshake.
    - Hot-Reload der Allow-/Blocklists erfolgt per RPC `POST /p2p/access-lists`; der Peerstore persistiert die aktiven Listen,
      damit Neustarts ohne Konfigurationsdatei-Anpassungen konsistent bleiben.
    - DoD-Nachweis: `rpp/p2p/tests/access_control.rs` prüft Hot-Reload, Persistenz und das Entfernen von Blocklist-Einträgen.
    - DoD: Sicherheits-Tests laufen in CI, bekannte Angriffsvektoren mitigiert.

13. **Simulation & Stresstests**
    - Netz-Simulator (lokal via Tokio oder verteilte Container) mit 20+ Peers.
    - Metriken für Latenz, Gossip-Mesh-Stabilität, Reputation-Drift.
    - DoD: Simulation läuft automatisiert, produziert Report.
    - CI-Integration: `scripts/ci/sim_smoke.sh` ruft `cargo test -p rpp-sim --features ci-sim --test sim_smoke` auf und archiviert `target/sim-smoke-summary.json` sowie Detailverzeichnisse unter `ci-artifacts/sim-smoke/`.
    - Laufzeitüberwachung: Ziel < 10 Minuten pro Run; Thresholds via GitHub Action Timeout (15 Minuten) oder Pipeline-Konfiguration absichern.

## Cross-Cutting Deliverables
- **Dokumentation:** Architekturgrafik, Config-Referenz, Operator-Guides.
- **CI-Integration:** Linting, Unit-Tests, Integrationstests, Simulation Entry-Points.
- **Fuzzing:** Nightly GitHub-Action `nightly-fuzz` führt `cargo fuzz run` für `handle_meta`, `handle_blocks`, `handle_votes` und `admission_evaluate_publish` mit Seed `0x5A17F00D` aus (`-max_total_time=120`, `-timeout=5`). Die jeweils aktualisierten Corpora werden nach `rpp/p2p/fuzz/corpus/<target>` exportiert und als Workflow-Artefakt abgelegt. Regressionen werden über `rpp/p2p/tests/fuzz_regressions.rs` aus diesen minimierten Fällen gespeist.
- **Observability:** Logs (structured), Tracing spans, Metrics.

## Abhängigkeiten & Milestones
1. *Milestone A (Phasen 0–1):* Funktionsfähiger Gossip-Backbone mit Admission-Control. **Status:** ✅ Tier-basierte Zugriffslogik aktiv, abgesichert durch Integrationstests (`rpp/p2p/tests/access_control.rs`).
2. *Milestone B (Phase 2):* Block- und Snapshot-Datenpfade live, Light-Client-Sync möglich. **Status:** ✅ Gossip-Quorum in `rpp/p2p/tests/multi_node_quorum.rs` und Snapshot-Streaming über `/rpp/snapshots/1.0.0` inkl. Light-Client-Verifikation stehen.【F:rpp/p2p/src/behaviour/snapshots.rs†L58-L957】【F:tests/network/snapshots.rs†L1-L120】
   - Gossip-Quorum nachgewiesen, Persistenz inkl. Neustart-Checks vorhanden.
   - Snapshot-Pipeline + Light-Client-Sync laufen über `SnapshotStreamStatus` und `LightClientSync`, RPCs dokumentiert in `docs/network/snapshots.md`.【F:rpp/runtime/node_runtime/node.rs†L375-L1288】【F:rpp/p2p/src/pipeline.rs†L1311-L1497】【F:docs/network/snapshots.md†L1-L120】
3. *Milestone C (Phase 3):* Produktionsreife mit Security, Persistenz, Simulation.

Jede Milestone-Abnahme setzt neben den DoD-Kriterien auch Peer-to-Peer-Tests über mindestens drei Knoten voraus.
