# Telemetrie-Übersicht

Die Runtime exportiert Telemetriedaten in zwei Richtungen:

* **Node-spezifische Laufzeitmetriken (`NodeMetrics`)** werden periodisch über Heartbeats
  an den Telemetrie-Worker gemeldet.
* **Meta-Telemetrie (`MetaTelemetryReport`)** fasst Informationen über aktuell verbundene
  Peers zusammen – inklusive Peer-Liste und aggregierter Zähler – und wird sowohl intern
  als auch über die RPC-Schnittstelle weitergereicht.

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

`MetaTelemetryReport` stellt einen kompakten Überblick über den aktuellen Peer-Kontext
bereit. Die Struktur wird direkt im
[`node_runtime::Node`](../rpp/runtime/node_runtime/node.rs) gepflegt und enthält:

* `local_peer_id` – PeerId des lokalen Nodes.
* `peers` – Liste der aktuell beobachteten Peers inklusive Version, Latenz- und
  Sichtbarkeitsinformationen (`PeerTelemetry`).
* `peer_count` – aggregierte Anzahl der Peers aus obiger Liste.

Die Definition und Ableitungen befinden sich in
[`rpp/runtime/node_runtime/node.rs`](../rpp/runtime/node_runtime/node.rs), wodurch diese
Dokumentation mit zukünftigen Strukturänderungen synchron gehalten werden kann. Das
RPC-Modul serialisiert den Report als `NetworkMetaTelemetryReport`; derselbe Codepfad
liefert auch den Meta-Gossip-Report, sodass interne und externe Konsumenten dieselben Daten
erhalten.

## Netzwerkmetriken (libp2p)

Bandwidth- und Peer-Metriken aus dem libp2p-Stack werden derzeit **nicht** automatisch in
`NodeMetrics` oder `MetaTelemetryReport` aufgenommen. Stattdessen liefert – sofern das Modul
gebaut wird – das P2P-Subsystem (`rpp/p2p`) dedizierte Helfer wie
`NetworkMetricsSnapshot` in [`rpp/p2p/src/swarm.rs`](../rpp/p2p/src/swarm.rs). Diese Snapshots
aggregieren Byte-Volumina, Topic-Metriken und Peer-Scores aus der libp2p-Instrumentierung
und stehen lokalen Komponenten zur Verfügung.

Die Runtime nutzt diese Daten bislang nur intern. Für reichhaltigere Exporte (z. B. zusätzliche
RPC-Endpunkte oder Prometheus-Metriken) ist ein nachgelagerter Ausbau geplant, der die
libp2p-Snapshots mit den bestehenden Telemetrie-Strömen verknüpft und eine öffentliche
Serialisierungsschicht definiert.

## Prometheus-Scrape-Endpunkt

Zusätzlich zum OTLP-Export richtet die Runtime nun standardmäßig einen Prometheus-kompatiblen
Recorder ein. Alle Aufrufe der `metrics::*`-Makros (Counter, Gauge, Histogramm) landen damit in einer
prozessweiten Registry, die optional über HTTP exponiert wird. Operatoren aktivieren den Scrape-Port
in der Knotenkonfiguration:

```toml
[rollout.telemetry.metrics]
listen = "127.0.0.1:9797"          # Bind-Adresse des HTTP-Endpunkts
auth_token = "change-me"           # optional; erwartet ein Bearer-Token im Authorization-Header
```

Wird `auth_token` gesetzt, muss jeder Abruf einen `Authorization: Bearer …`-Header mitsenden. Der
Endpunkt liefert Metriken unter `/metrics` im Prometheus-Textformat und setzt `Cache-Control: no-cache`.
Ohne explizite Konfiguration bleibt die Registry lokal (Makros produzieren trotzdem Messwerte, es
existiert jedoch kein öffentlicher HTTP-Port).

Beispiel-Scrape-Konfiguration in Prometheus:

```yaml
scrape_configs:
  - job_name: rpp-node
    static_configs:
      - targets: ["validator-01:9797"]
    metrics_path: /metrics
    authorization:
      credentials: Bearer change-me
```

Die Registry führt automatisch Upkeep-Ticks aus, sodass Histogramme und Counter auch bei geringer
Scrape-Frequenz konsistente Werte liefern.
