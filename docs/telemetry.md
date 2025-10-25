# Telemetrie-Pipeline & Netzwerkmetriken

Die Runtime exportiert periodisch `TelemetrySnapshot`-Strukturen an den Telemetrie-Worker. Neben Block- und Proof-Daten enthält der Snapshot jetzt einen neuen Abschnitt `network_metrics`, der direkt aus der libp2p-Instrumentierung gespeist wird.

## Struktur `TelemetrySnapshot`

```json
{
  "block_height": 123,
  "block_hash": "0x…",
  "transaction_count": 42,
  "peer_count": 8,
  "node_id": "12D3KooW…",
  "reputation_score": 0.82,
  "timestamp": "2025-01-01T12:00:00Z",
  "verifier_metrics": { "per_backend": {} },
  "consensus_round_latencies_ms": [320, 275, 410],
  "consensus_leader_changes": 5,
  "consensus_quorum_latency_ms": 480,
  "consensus_witness_events": 128,
  "consensus_slashing_events": 2,
  "consensus_failed_votes": 3,
  "network_metrics": {
    "bandwidth": {
      "inbound_bytes": 2048,
      "outbound_bytes": 4096
    },
    "topics": [
      {
        "topic": "meta",
        "inbound_bytes": 1024,
        "outbound_bytes": 2048,
        "mesh_peers": 6
      }
    ],
    "peer_scores": [
      { "peer": "12D3KooW…", "score": 9.5 }
    ]
  }
}
```

Alle Einträge werden über eine gemeinsame `libp2p_metrics::Registry` registriert. Dadurch können Prometheus-Exporter dieselben Daten auslesen, während `NetworkMetricsSnapshot` eine verdichtete Ansicht für Dashboards liefert.

Die neuen Konsensfelder spiegeln unmittelbar die Instrumentierung aus `produce_block` sowie den Gossip-/Vote-Handlern wider. Sie liefern Laufzeit-Histogramme, Zähler für Witness- und Slashing-Ereignisse sowie Fehlstimmen. Damit lassen sich Leader-Rotation, Quorum-Latenzen und Fehlverhalten pro Runde in Dashboards und Alerting-Regeln nachvollziehen.

## Dashboards

* **Bandwidth Overview** – aggregiert `network_metrics.bandwidth` sowie die Topic-spezifischen Byte-Zähler. Ideal für Traffic-Budgets und Alerting bei Anomalien.
* **Peer Score Drilldown** – visualisiert `network_metrics.peer_scores`, um Abweichungen in Gossip-Qualität oder Reputation schnell zu erkennen.

Bestehende Dashboards sollten das neue Feld als optionales Panel aufnehmen. Backwards-Kompatibilität bleibt erhalten: falls das P2P-Stack ohne Metrics-Feature gebaut wird, liefert `network_metrics` eine leere Default-Struktur.

## Runtime-Metriken und Pfade

Neben den Netzwerkmetriken exportiert die Runtime seit dem neuen Telemetrie-Stack zusätzliche OpenTelemetry-Instrumente. Die wichtigsten Pfade, die jetzt in Dashboards oder Abfragen verwendet werden können, sind:

* `rpp.runtime.proof.generation.duration` und `rpp.runtime.proof.generation.size` – messen Dauer und Größe aller vom Wallet erzeugten STWO-Artefakte.
* `rpp.runtime.proof.generation.count` – Zähler für generierte Proofs, gruppiert nach Backend.
* `rpp.runtime.proof.verification.*` – Latenzen, Byte-Verteilungen und Stage-Resultate für die RPP-STARK-Verifikation im Node.
* `rpp.runtime.storage.header_flush.*` sowie `rpp.runtime.storage.wal_flush.*` – alle Flush-Versuche des Firewood-NodeStores inklusive Outcome und Transfergröße.
* `rpp.runtime.rpc.request.latency` und `rpp.runtime.rpc.request.total` – instrumentieren Wallet- und Proof-RPC-Endpunkte.

Für Integrationen ist wichtig: `RuntimeMetrics` implementiert `firewood_storage::StorageMetrics`. Das bedeutet, dass jede Stelle, die bisher `noop_storage_metrics()` erhalten hat, optional ein geklontes `Arc<RuntimeMetrics>` injiziert bekommen kann, um Persistenzmetriken direkt an die NodeStore-Schicht durchzureichen.
