# Wallet Runtime & Electrs Integration

## Initialisierungsablauf

1. **Konfiguration laden:** Beim Start liest das Wallet die persistierte
   `ElectrsConfig` aus dem Storage (`wallet_electrs_config`).【F:rpp/wallet/ui/wallet.rs†L788-L839】
2. **Handles aufbauen:** `Wallet::reload_electrs_handles` ruft `initialize` mit
   den konfigurierten Firewood-/Index-Pfaden und optionalen Runtime-Adaptern
   auf. Die Routine erzeugt fehlende Verzeichnisse, prüft Feature-Abhängigkeiten
   und spannt Firewood-Adapter, Daemon sowie Tracker entsprechend der
   Feature-Gates auf.【F:rpp/wallet/ui/wallet.rs†L821-L924】【F:rpp/wallet/src/vendor/electrs/init.rs†L28-L138】
3. **Gossip koppeln:** Während der Initialisierung werden Tracker-Topics
   dedupliziert, ungültige Topics abgewiesen und fehlende Einträge für den
   Daemon ergänzt, sodass Runtime-Gossip und Tracker-Abonnements synchron
   laufen.【F:rpp/wallet/src/vendor/electrs/init.rs†L96-L152】
4. **Synchronisation starten:** Nach erfolgreicher Initialisierung wird ein
   Tracker-Task erzeugt, der Gossip-Benachrichtigungen und Dashboard-Snapshots
   verarbeitet, um Skriptstatus, Proof-Digests und VRF-Audits aktuell zu halten.【F:rpp/wallet/ui/wallet.rs†L845-L924】

## Konfigurationsanforderungen

* **WalletConfig:** `data_dir`, `key_path` und `rpc_listen` folgen dem
  Node-Schema; bei deaktiviertem Embedded-Node müssen Gossip-Endpunkte
  angegeben werden.【F:rpp/runtime/config.rs†L487-L546】
* **Electrs-Feature-Gates:** `runtime` aktiviert Runtime-Adapter und Daemon;
  `tracker` erfordert `runtime` und startet den Index-Tracker.【F:rpp/wallet/src/config.rs†L46-L113】【F:rpp/runtime/config.rs†L563-L568】
* **Verzeichnisstruktur:** Sobald Runtime oder Tracker aktiviert sind, legt das
  Wallet `<data_dir>/electrs/firewood` sowie `<data_dir>/electrs/index` an und
  nutzt diese Pfade für Firewood-Snapshots und den Electrs-Index.【F:rpp/runtime/config.rs†L552-L578】
* **Gossip & P2P:** Standardmäßig abonnieren Daemon und Tracker
  `/rpp/gossip/blocks/1.0.0`; zusätzliche Topics können über
  `[electrs.p2p.gossip_topics]` und `[electrs.tracker.notifications.topic]`
  gesetzt werden.【F:rpp/wallet/src/config.rs†L94-L142】【F:rpp/wallet/src/vendor/electrs/init.rs†L96-L152】

## Beispielkonfigurationen

### Runtime-aktiviertes Profil

```toml
[electrs]
network = "signet"

[electrs.features]
runtime = true
tracker = true

[electrs.tracker]
telemetry_endpoint = "127.0.0.1:9200"

[electrs.tracker.notifications]
p2p = true
topic = "/rpp/gossip/blocks/1.0.0"

[electrs.p2p]
enabled = true
metrics_endpoint = "127.0.0.1:9300"
network_id = "rpp-signet"
gossip_topics = ["/rpp/gossip/blocks/1.0.0", "/rpp/gossip/finality/1.0.0"]
```

*Start:* `Wallet::reload_electrs_handles` benötigt Runtime-Adapter (z. B. aus dem
 eingebetteten Node), damit Daemon und Tracker den Runtime-Knoten spiegeln.【F:rpp/wallet/ui/wallet.rs†L821-L924】

### Offline-Firewood-Profil

```toml
[electrs]
network = "regtest"

[electrs.features]
runtime = false
tracker = false
```

*Ergebnis:* Der Firewood-Adapter läuft im Dateimodus; Tracker und Daemon bleiben
 aus, sodass das Wallet nur lokale Skript-Daten liest.【F:rpp/wallet/src/vendor/electrs/init.rs†L84-L112】

## Migration bestehender Wallets

1. **Konfiguration anpassen:** Ergänzen oder aktualisieren Sie den `[electrs]`-
   Block und setzen Sie die gewünschten Feature-Gates. Die Validierung verhindert
   Tracker ohne Runtime.【F:rpp/runtime/config.rs†L563-L568】
2. **Verzeichnisse erzeugen:** Rufen Sie `WalletConfig::ensure_directories` auf
   oder starten Sie das Wallet neu, damit Firewood- und Index-Pfade im
   Datenverzeichnis erstellt werden.【F:rpp/runtime/config.rs†L552-L578】
3. **Neu initialisieren:** Nach der Änderung `Wallet::reload_electrs_handles`
   ausführen (z. B. beim Programmstart), um Daemon und Tracker mit der neuen
   Konfiguration zu booten.【F:rpp/wallet/ui/wallet.rs†L821-L924】

## Auswirkungen auf RPC & UI

* **RPC-Felder:** `WalletBalanceResponse` liefert optional `mempool_delta`; die
  History-Antwort enthält `script_metadata` und `tracker`, sobald der Electrs-
  Tracker aktiv ist.【F:rpp/rpc/interfaces.rs†L268-L311】
* **UI:** `WalletTrackerHandle` signalisiert den Tracker-Status, während
  `ScriptStatusMetadata` bestätigte Guthaben, Mempool-Deltas, Status-Digests und
  optionale Proof-/VRF-Daten pro Skript bereitstellt.【F:rpp/wallet/ui/wallet.rs†L320-L420】【F:rpp/wallet/ui/wallet.rs†L736-L776】
