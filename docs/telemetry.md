# Telemetrie-Übersicht

Die Runtime exportiert Telemetriedaten in zwei Richtungen:

* **Node-spezifische Laufzeitmetriken (`NodeMetrics`)** werden periodisch über Heartbeats
  an den Telemetrie-Worker gemeldet.
* **Meta-Telemetrie (`MetaTelemetryReport`)** fasst Informationen über die aktuell
  verbundenen Peers zusammen und wird sowohl intern als auch über die RPC-Schnittstelle
  weitergereicht.

Die Implementierung der Strukturen und der Aktualisierungspfad befindet sich im
[`rpp/runtime/node_runtime/node.rs`](../rpp/runtime/node_runtime/node.rs), der wiederum vom
`node`-Runtime-Dienst (`rpp/runtime/node.rs`) orchestriert wird. Für Tests, die den
Ende-zu-Ende-Fluss der Telemetrie validieren (inklusive Gossip-Brücke), siehe
[`rpp/runtime/node_runtime/tests/gossip_bridge.rs`](../rpp/runtime/node_runtime/tests/gossip_bridge.rs).

## `NodeMetrics`

`NodeMetrics` bildet den aktuellen Zustand des Nodes ab. Die Felder werden direkt aus
Konsens- und Runtime-Komponenten befüllt:

* `block_height`, `block_hash` – letzter bestätigter Block sowie dessen Hash.
* `transaction_count` – Anzahl der Transaktionen im aktuellen Block.
* `reputation_score` – heuristische Bewertung des lokalen Nodes für Meta-/Admission-Entscheidungen.
* `verifier_metrics` – verdichtete STARK-Verifikationsmetriken (siehe `VerifierMetricsSnapshot`).
* `round_latencies_ms` – Latenzen einzelner Konsensrunden.
* `leader_changes` – beobachtete Leader-Wechsel.
* `quorum_latency_ms` – optionale Gesamtlatenz vom Rundestart bis zur Quorum-Bildung.
* `witness_events`, `slashing_events`, `failed_votes` – Zähler für relevante Konsensereignisse.

Die Felder spiegeln exakt die Struktur in
[`rpp/runtime/node_runtime/node.rs`](../rpp/runtime/node_runtime/node.rs) wider und werden im
`NodeRuntime` nach jedem abgeschlossenen Konsenszyklus aktualisiert.

## `MetaTelemetryReport`

Meta-Telemetrie fasst Peerinformationen zusammen, die sowohl im Meta-Gossip als auch über
RPC ausgegeben werden:

* `local_peer_id` – PeerId des lokalen Nodes.
* `peer_count` – Anzahl der zur Laufzeit bekannten Peers.
* `peers` – Liste von `PeerTelemetry`-Einträgen (`peer`, `version`, `latency_ms`, `last_seen`).

Das RPC-Modul serialisiert die Struktur als `NetworkMetaTelemetryReport` für Clients; die
Konvertierungen finden in `node_runtime/node.rs` statt. Für das Meta-Gossip wird derselbe
Pfad genutzt, wodurch Konsistenz zwischen internem und externem Bericht sichergestellt ist.

## Netzwerkmetriken (libp2p)

Bandwidth- und Peer-Metriken des libp2p-Stacks werden derzeit **nicht** automatisch in den
oben beschriebenen Reports exportiert. Stattdessen bietet das P2P-Modul dedizierte Helper,
insbesondere `NetworkMetricsSnapshot` aus
[`rpp/p2p/src/swarm.rs`](../rpp/p2p/src/swarm.rs), der Byte-Volumina, Topic-Metriken und
Peer-Scores aus der libp2p-Instrumentierung aggregiert.

Die Runtime nutzt diesen Snapshot bislang nur intern; für externe Telemetrie-Dashboards
müsste eine zusätzliche Serialisierungsschicht implementiert werden. Folgende Schritte
bleiben offen, falls eine vollständige libp2p-Export-Pipeline gewünscht ist:

1. Einbettung der `NetworkMetricsSnapshot`-Daten in einen neuen oder erweiterten Telemetrie-
   Endpunkt (z. B. Ergänzung von `NodeMetrics` oder Bereitstellung eines separaten RPC).
2. Sicherstellung, dass die Prometheus-Exporter dieselben Daten liefern, um Doppelarbeit zu vermeiden.
3. Erweiterung der Dokumentation um die konkreten JSON- oder OpenAPI-Schemata, sobald die
   Export-Pipeline steht.

Bis dahin steht libp2p-Telemetrie ausschließlich über die Prometheus-Registry (Feature
`metrics`) und den `NetworkMetricsSnapshot`-Helper zur Verfügung.
