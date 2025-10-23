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

9. **Snapshots & Light-Client-Sync**
   - Streaming von Firewood-Snapshots via libp2p-Request/Response oder Chunked Gossip.
   - Light-Clients empfangen nur Headers + Recursive Proofs, validieren Roots.
   - DoD: Light-Client-Test lädt Snapshot + Proof, validiert erfolgreich.

10. **Meta-Kanal & Telemetrie**
    - Peer-Heartbeat, Latenzen, Versionen über `meta` Topic publizieren.
    - Dashboard/Prometheus-Exporter füttern.
    - DoD: Telemetrie-Events sichtbar, Alerts bei Offline-Peers.

## Phase 3 – Robustheit & Betrieb
11. **Persistence & Crash-Recovery**
    - Peerstore + Gossip-State auf Disk sichern.
    - Rejoin-Logic für Mesh/Topics nach Neustart.
    - DoD: Node rebooted und nimmt Mesh wieder auf ohne manuellen Eingriff.

12. **Security Hardening**
    - Replay-Schutz (Message-IDs, seqno), Flood-Prevention, Rate-Limits.
    - Fuzzing/Property-Tests für Decoder und Admission-Control.
    - Konfigurierbare Zugriffslisten: `p2p.allowlist` (Default: `[]`) fixiert Tier-Level erlaubter Peers,
      `p2p.blocklist` (Default: `[]`) sperrt Peers dauerhaft bereits beim Handshake.
    - DoD: Sicherheits-Tests laufen in CI, bekannte Angriffsvektoren mitigiert.

13. **Simulation & Stresstests**
    - Netz-Simulator (lokal via Tokio oder verteilte Container) mit 20+ Peers.
    - Metriken für Latenz, Gossip-Mesh-Stabilität, Reputation-Drift.
    - DoD: Simulation läuft automatisiert, produziert Report.

## Cross-Cutting Deliverables
- **Dokumentation:** Architekturgrafik, Config-Referenz, Operator-Guides.
- **CI-Integration:** Linting, Unit-Tests, Integrationstests, Simulation Entry-Points.
- **Observability:** Logs (structured), Tracing spans, Metrics.

## Abhängigkeiten & Milestones
1. *Milestone A (Phasen 0–1):* Funktionsfähiger Gossip-Backbone mit Admission-Control. **Status:** ✅ Tier-basierte Zugriffslogik aktiv, abgesichert durch Integrationstests (`rpp/p2p/tests/access_control.rs`).
2. *Milestone B (Phase 2):* Block- und Snapshot-Datenpfade live, Light-Client-Sync möglich. **Status:** 🚧 Datenpfade folgen nach Abschluss der Gossip-Gating-Tests (`rpp/p2p/tests/access_control.rs`).
3. *Milestone C (Phase 3):* Produktionsreife mit Security, Persistenz, Simulation.

Jede Milestone-Abnahme setzt neben den DoD-Kriterien auch Peer-to-Peer-Tests über mindestens drei Knoten voraus.
