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

### Prometheus/Grafana/OTLP-Referenz-Stacks

* **Docker Compose** – `telemetry/docker-compose.prom-grafana-otel.yml` startet einen OTLP-
  Collector (OTLP gRPC/HTTP + Prometheus-Exporter), Prometheus und Grafana in einem lokalen
  Stack. Passe `telemetry/prometheus.yml` an den gewünschten Scrape-Host an (z. B.
  `host.docker.internal:9797` für den lokalen Node) und starte den Stack mit
  `docker compose -f telemetry/docker-compose.prom-grafana-otel.yml up -d`. Der Collector
  exportiert OTLP-Metriken auf 4317/4318 und hält die Prometheus-kompatible Ausgabe unter
  `http://localhost:9464/metrics` bereit.【F:telemetry/docker-compose.prom-grafana-otel.yml†L1-L38】【F:telemetry/otel-collector.yaml†L1-L22】【F:telemetry/prometheus.yml†L1-L17】
* **Helm (Kubernetes)** – `telemetry/helm/otel-collector-values.yaml` und
  `telemetry/helm/prom-grafana-values.yaml` liefern Werte-Dateien für den
  `opentelemetry-collector`-Chart sowie den `kube-prometheus-stack`. Die Werte aktivieren einen
  Prometheus-Exporter (Port 9464) für OTLP-Metriken und fügen Scrape-Jobs für den rpp-Node hinzu.
  Passe die Hostnamen und optional den Authorization-Block an deine Cluster-Topologie an und
  installiere die Charts gemäß `telemetry/helm/README.md`.【F:telemetry/helm/README.md†L1-L21】【F:telemetry/helm/otel-collector-values.yaml†L1-L32】【F:telemetry/helm/prom-grafana-values.yaml†L1-L35】

## Wallet-spezifische Proof- und Lifecycle-Telemetrie

Der Wallet-Stack meldet eigene Metriken und Events, sobald `[wallet.telemetry].metrics`
aktiviert ist und die GUI/CLI mit Telemetrie-Feature gebaut werden:

- Runtime-Metriken wie `rpp.runtime.wallet.rpc_latency` und
  `rpp.runtime.wallet.sync.active` decken RPC-Latenzen, Proof-/Sync-Liveness und
  Budget-Exhaustion ab.【F:docs/wallet_phase1_minimal.md†L271-L285】
- Die GUI sendet Events wie `wallet.gui.send_attempt`, `wallet.gui.prover_retry`
  und `wallet.gui.error`, sobald Tabs gewechselt oder Prover-Recoveries
  ausgelöst werden.【F:docs/wallet_phase3_gui.md†L148-L162】
- Lifecycle-Kontrollen wie Rescans (`[wallet.rescan]`) und Auto-Lock greifen
  ebenfalls auf dieselbe Telemetrie-Senke zu, sodass Proof-Enforcement und
  Replay-Jobs in Dashboards korrelierbar bleiben.【F:config/wallet.toml†L69-L102】

Die Wallet-Ereignisse nutzen dieselben OTLP-/Prometheus-Pfade wie die
Validator-Telemetrie, sodass Betreiber keine zusätzlichen Exporter konfigurieren
müssen. Aktivieren Sie die Opt-ins in `config/wallet.toml` und verifizieren Sie
die neuen Events über den Telemetrie-Collector oder lokale JSON-Spools, bevor
Sie sie an zentrale Backends weiterleiten.

## Fallback-/Localhost-Stack

Für isolierte Tests steht ein geprüfter Localhost-Stack bereit, der ohne
Netzwerkanbindung Prometheus, Grafana und einen Wallet-Scrape-Endpunkt startet.
Er orientiert sich an den Wallet-Voreinstellungen aus `config/wallet.toml` und
nutzt ausschließlich Loopback-Adressen und kurzlebige Volumes.

1. Telemetrie im Wallet lokal einschalten (Prometheus-Port, Auth-Token, OTLP-
   Fallback):

   ```toml
   [wallet.telemetry]
   metrics = true
   crash_reports = false
   endpoint = "http://localhost:4317"   # OTLP (optional, Collector im Compose-Stack)
   machine_id_salt = "dev-local"

   [wallet.telemetry.fallback]
   enabled = true
   prometheus_listen = "127.0.0.1:9797"
   auth_token = "dev-change-me"
   otlp_grpc = "0.0.0.0:4317"
   otlp_http = "0.0.0.0:4318"
   ```

2. Beispiel-Compose-Datei (Prometheus-Grafana-Fallback) unter `telemetry/docker-compose.local.yml`:

   ```yaml
   version: "3.9"
   services:
     prometheus:
       image: prom/prometheus:v2.52.0
       command:
         - --config.file=/etc/prometheus/prometheus.yml
         - --web.listen-address=:9090
       volumes:
         - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
       ports:
         - "9090:9090"

     grafana:
       image: grafana/grafana:10.4.2
       environment:
         - GF_SECURITY_ADMIN_PASSWORD=admin
       ports:
         - "3000:3000"
   
   # `prometheus.yml` im selben Verzeichnis:
   # scrape_configs:
   #   - job_name: rpp-wallet
   #     metrics_path: /metrics
   #     static_configs:
   #       - targets: ["host.docker.internal:9797"]
   #     authorization:
   #       credentials: Bearer dev-change-me
   ```

   Ergänzend stehen vollständige OTLP/Prometheus/Grafana-Stacks unter
   `telemetry/docker-compose.prom-grafana-otel.yml` sowie Kubernetes-Helm-Werte unter
   `telemetry/helm/` bereit. Die Beispiele sind so vordefiniert, dass sie den Node-Metrik-Port
   `9797` ohne Authentifizierung scrapen; setze bei Bedarf einen Bearer-Token in
   `telemetry/prometheus.yml` bzw. `telemetry/helm/prom-grafana-values.yaml`.

3. Stack starten und Smoke-Test ausführen:

   ```bash
   docker compose -f telemetry/docker-compose.local.yml up -d
   curl -H "Authorization: Bearer dev-change-me" http://localhost:9797/metrics | head -n 5
   curl http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {health,labels}'
   curl http://localhost:3000/api/health
   ```

   *Ein erfolgreicher Smoke-Test liefert HTTP-Status 200 für alle drei Aufrufe,
   meldet Prometheus-Targets im `up`-Zustand und zeigt einen `database`-Status
   `ok` von Grafana an.*
