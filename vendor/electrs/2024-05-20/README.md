# Electrs Vendor Snapshot (2024-05-20)

- **Upstream-Quelle:** `vendor/electrs-master.zip`
- **Referenz-Commit:** `4a5af61668a1414f112fe8b07b23bff554779a4f`
- **Importumfang:** `src/chain.rs`, `src/types.rs`, `src/signals.rs`

## Aktualisierungsschritte

1. Lade das gewünschte Upstream-Archiv (z. B. über `curl`/`wget`) in `vendor/electrs-master.zip`.
2. Prüfe den Commit-Hash (der GitHub-Archive im Dateikopf ausgeben) und dokumentiere ihn in
   [`manifest/upstream_commit.txt`](manifest/upstream_commit.txt).
3. Entpacke die benötigten Dateien in `src/` und passe Importe sowie Modul-Pfade an die
   RPP-spezifischen Typen (`rpp-ledger`).
4. Ergänze ggf. TODO-Stubs, damit `cargo check --features vendor_electrs` erfolgreich durchläuft.
5. Formatiere die Änderungen mit `cargo fmt --all`.
6. Vergleiche die modifizierten Dateien mit dem Upstreamstand, z. B. über `diff -u` oder `git difftool`,
   um Abweichungen nachvollziehen zu können.

## Konfiguration & Feature-Gates

Die Wallet-Bibliothek konfiguriert die Tracker-Integration über `ElectrsConfig`
(`rpp/wallet/src/config.rs`). Wesentliche Schalter:

| Schlüssel | Beschreibung |
|-----------|--------------|
| `network` | Wählt das Ledger-Netzwerk (`regtest`, `testnet`, `signet`, `mainnet`). Der Wert wird nach `rpp-ledger`-Netzwerken übersetzt und bestimmt den Genesis-Header des Index. |
| `features.runtime` | Aktiviert die Runtime-Adapter (`FirewoodAdapter::open_with_runtime`) und startet den Daemon, sodass der Tracker gegen einen RPP-Laufzeitknoten spiegelt.【F:rpp/wallet/src/config.rs†L10-L55】【F:rpp/wallet/src/vendor/electrs/firewood_adapter.rs†L18-L118】|
| `features.tracker` | Startet den High-Level-Tracker, der Index und Daemon verknüpft. Dieses Flag setzt `features.runtime` voraus.【F:rpp/wallet/src/config.rs†L57-L109】【F:rpp/wallet/src/vendor/electrs/init.rs†L34-L82】|
| `tracker.telemetry_endpoint` | Socket-Adresse, unter der der Tracker seine Mempool-Metriken registriert. Standardmäßig wird `127.0.0.1:0` verwendet, womit die Handles nur intern verdrahtet werden.【F:rpp/wallet/src/config.rs†L86-L137】|
| `tracker.notifications.p2p` | Aktiviert den Broadcast-Listener, der neue Blöcke direkt aus der Runtime-Gossip-Pipeline konsumiert.【F:rpp/wallet/src/config.rs†L110-L137】【F:vendor/electrs/2024-05-20/src/tracker.rs†L40-L125】|
| `tracker.notifications.topic` | Definiert den Gossip-Topic (z. B. `/rpp/gossip/blocks/1.0.0`), den der Tracker beim Daemon abonniert.【F:rpp/wallet/src/config.rs†L110-L137】【F:vendor/electrs/2024-05-20/src/tracker.rs†L40-L135】|
| `p2p.enabled` | Schaltet die P2P-Brücke ein, sodass der Daemon Header und Blöcke via Netzwerkmodul bezieht (Fallback auf Firewood-Streams bleibt aktiv).【F:rpp/wallet/src/config.rs†L68-L109】【F:vendor/electrs/2024-05-20/src/daemon.rs†L70-L210】|
| `p2p.metrics_endpoint` | Telemetrie-Socket für die P2P-Verbindungsmetriken (`electrs_p2p_*`). Standard `127.0.0.1:0` registriert nur interne Handles.【F:rpp/wallet/src/config.rs†L68-L109】【F:vendor/electrs/2024-05-20/src/daemon.rs†L70-L210】|
| `p2p.network_id` | Kennzeichnet die P2P-Netzwerk-ID, die beim Join des Swarms annonciert wird.【F:rpp/wallet/src/config.rs†L68-L109】【F:vendor/electrs/2024-05-20/src/daemon.rs†L52-L120】|
| `p2p.auth_token` | Optionales Authentifizierungs-Token, das bei Bedarf an nachgelagerte Services weitergereicht wird.【F:rpp/wallet/src/config.rs†L68-L109】【F:vendor/electrs/2024-05-20/src/daemon.rs†L52-L120】|
| `p2p.gossip_topics` | Liste erlaubter Gossip-Themen, die der Daemon für Broadcast-Abonnements freischaltet (z. B. Blöcke oder Snapshots).【F:rpp/wallet/src/config.rs†L68-L109】【F:vendor/electrs/2024-05-20/src/daemon.rs†L70-L210】|

Die Workspace-Feature-Flag `vendor_electrs` aktiviert sämtliche optionalen
Abhängigkeiten (`serde`, `tokio`, `storage-firewood`, `rpp`-Runtime usw.) und
bindet die vendorten Module in `rpp-wallet` ein.【F:rpp/wallet/Cargo.toml†L8-L27】【F:rpp/wallet/src/lib.rs†L13-L27】

### P2P-Konfiguration

Die optionale P2P-Brücke erlaubt es dem Daemon, Header und Blöcke über das
Netzwerkmodul zu beziehen und Gossip-Abonnements auf definierte Topics zu
beschränken. Ist `p2p.enabled` gesetzt, wird eine Verbindung mit dem angegebenen
`network_id` aufgebaut; der Wert wird als Kennung gegenüber dem Swarm
annonciert. Falls ein `auth_token` hinterlegt ist, steht es nachgelagerten
Systemen zur Verfügung, ohne dass der Daemon selbst Validierungen erzwingt.
`gossip_topics` legt fest, welche Topics der Daemon akzeptiert – Anfragen für
nicht freigeschaltete Topics werden abgewiesen. Bei Fehlern im P2P-Pfad fällt
der Daemon automatisch auf die Firewood-Streams zurück, sodass RPC-Aufrufe
weiterhin funktionieren.【F:rpp/wallet/src/config.rs†L68-L137】【F:rpp/wallet/src/vendor/electrs/init.rs†L34-L135】【F:vendor/electrs/2024-05-20/src/daemon.rs†L52-L320】

Tracker können optional den Broadcast-Kanal abonnieren (`tracker.notifications`)
und wählen darüber den gewünschten Gossip-Topic aus. Die Konfiguration stellt
sicher, dass der gewählte Topic im Daemon freigeschaltet ist, bevor der
Broadcast-Kanal geöffnet wird.【F:rpp/wallet/src/config.rs†L86-L137】【F:rpp/wallet/src/vendor/electrs/init.rs†L34-L135】【F:vendor/electrs/2024-05-20/src/tracker.rs†L40-L220】

### Wallet-Initialisierung & Laufzeit-Erwartungen

Wallet-Einbettungen speichern ihre Electrs-Konfiguration (`ElectrsConfig`) im
Wallet-Storage und laden sie beim Start erneut. `Wallet::reload_electrs_handles`
ruft `initialize` mit den aktuellen Pfaden und optionalen Runtime-Adaptern auf;
das erzeugt fehlende Firewood- und Index-Verzeichnisse und verknüpft Runtime-
abhängige Komponenten nur, wenn die Feature-Gates dies erlauben.【F:rpp/wallet/ui/wallet.rs†L788-L924】【F:rpp/wallet/src/vendor/electrs/init.rs†L28-L152】
`WalletConfig::ensure_directories` legt `<data_dir>/electrs/firewood` sowie
`<data_dir>/electrs/index` automatisch an, sobald Runtime- oder Tracker-Features
gesetzt sind.【F:rpp/runtime/config.rs†L552-L578】

Der Initialisierer validiert außerdem Gossip-Topics: Tracker- und Daemon-Topics
werden dedupliziert, fehlende Topics werden ergänzt und ungültige Werte
abgewiesen.【F:rpp/wallet/src/vendor/electrs/init.rs†L96-L152】 Für Runtime-
betriebe sind Adapter (`RuntimeAdapters`) Pflicht; werden sie nicht übergeben,
bricht `initialize` frühzeitig ab.【F:rpp/wallet/src/vendor/electrs/init.rs†L84-L112】

### Konfigurationsbeispiele

**Runtime + Tracker (Daemon aktiv, Gossip & Telemetrie eingeschaltet)**

```toml
data_dir = "./data"
key_path = "./keys/wallet.toml"
rpc_listen = "127.0.0.1:9090"

[node]
embedded = true
gossip_endpoints = ["/ip4/127.0.0.1/tcp/7600"]

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

**Offline Firewood (Daemon deaktiviert, Tracker aus)**

```toml
data_dir = "./data"
key_path = "./keys/wallet.toml"
rpc_listen = "127.0.0.1:9090"

[node]
embedded = false
gossip_endpoints = ["/dns4/bootstrap.rpp.invalid/tcp/7600"]

[electrs]
network = "regtest"

[electrs.features]
runtime = false
tracker = false
```

Beim Offline-Profil bleibt der Firewood-Adapter im reinen Dateimodus aktiv,
damit lokale Indizes und Skriptmetadaten verfügbar bleiben, ohne dass Gossip-
Kanäle benötigt werden.【F:rpp/wallet/src/vendor/electrs/init.rs†L84-L112】

### Migration bestehender Wallets

1. **Konfigurationsdatei aktualisieren:** Ergänzen Sie den `[electrs]`-Block im
   bestehenden `wallet.toml` und wählen Sie die gewünschten Feature-Gates (siehe
   Beispiele oben). Die Validierung stellt sicher, dass Tracker nur zusammen mit
   Runtime aktiviert wird.【F:rpp/runtime/config.rs†L563-L568】
2. **Verzeichnisse vorbereiten:** Führen Sie `WalletConfig::ensure_directories`
   aus oder starten Sie das Wallet einmalig neu; dadurch werden die Electrs-
   Unterordner im Datenverzeichnis angelegt.【F:rpp/runtime/config.rs†L552-L578】
3. **Handles neu initialisieren:** Rufen Sie `Wallet::reload_electrs_handles`
   nach der Konfigurationsänderung auf (z. B. beim Wallet-Start). Dadurch wird
   der Daemon ggf. mit Runtime-Adaptern gebootet, der Tracker verbunden und der
   Synchronisations-Task gestartet.【F:rpp/wallet/ui/wallet.rs†L821-L924】

### RPC- & UI-Erweiterungen

Der Electrs-Tracker erweitert Wallet-RPC-Antworten um `mempool_delta`,
`script_metadata` und `tracker`. Downstream-Integrationen sollten die Felder
optional behandeln und neue Skriptstatus-Hashes sowie Mempool-Fingerprints
persistieren.【F:rpp/rpc/interfaces.rs†L268-L311】 Die Wallet-UI stellt über
`WalletTrackerHandle` und `ScriptStatusMetadata` die gleichen Metadaten bereit,
inklusive Status-Digests, Proof-Envelopes und optionaler VRF-Audits.【F:rpp/wallet/ui/wallet.rs†L320-L420】【F:rpp/wallet/ui/wallet.rs†L736-L776】

### Telemetrie-Integration

* **Feature-Gate:** Die optionale Flag `vendor_electrs_telemetry` koppelt die vendorten Module an `malachite::telemetry` und
  `rpp::telemetry`. Ohne diese Funktion bleiben die Wrapper aus `metrics.rs` No-Ops, sodass sich Builds auch ohne Telemetrie
  erstellen lassen.【F:rpp/wallet/Cargo.toml†L8-L27】【F:vendor/electrs/2024-05-20/src/metrics.rs†L1-L352】
* **Cache:** `CacheTelemetry` registriert Gauges für Treffer, Fehltreffer, Einträge, Bytes sowie Warmup-Kennzahlen und zeichnet
  die Größe eingefügter Transaktionen über das Histogramm `electrs_cache_insert_size_bytes` auf.【F:vendor/electrs/2024-05-20/src/cache.rs†L1-L290】
* **Mempool:** Der Tracker initialisiert das dedizierte Mempool-Modul und registriert Gauges für Transaktionen, Identitäten,
  Votes, Uptime-Proofs sowie Queue-Gewichte über den in `tracker.telemetry_endpoint` definierten Socket.【F:vendor/electrs/2024-05-20/src/mempool.rs†L1-L240】【F:vendor/electrs/2024-05-20/src/tracker.rs†L1-L220】
* **P2P/Daemon:** Block-Gossip-Abonnements sowie die Latenz von `get_block`-Aufrufen fließen als `electrs_p2p_*`-Metriken in das
  Telemetrie-Backend ein.【F:vendor/electrs/2024-05-20/src/daemon.rs†L1-L420】

Ein begleitendes Beispiel zum Registrieren einer Gauge und zum Auslesen über `malachite::telemetry` befindet sich unter
[`docs/vendor/electrs-metrics.md`](../../../docs/vendor/electrs-metrics.md).

### Beispiel: Tracker initialisieren

```rust
use rpp_wallet::config::{
    CacheConfig, ElectrsConfig, FeatureGates, NetworkSelection, P2pConfig, TrackerConfig,
};
use rpp_wallet::vendor::electrs::firewood_adapter::RuntimeAdapters;
use rpp_wallet::vendor::electrs::init::{initialize, ElectrsHandles};

fn bootstrap(config: ElectrsConfig, runtime: RuntimeAdapters) -> anyhow::Result<ElectrsHandles> {
    let firewood_dir = "/var/lib/rpp/wallet/firewood";
    let index_dir = "/var/lib/rpp/wallet/index";
    initialize(&config, firewood_dir, index_dir, Some(runtime))
}

let config = ElectrsConfig {
    network: NetworkSelection::Regtest,
    features: FeatureGates {
        runtime: true,
        tracker: true,
    },
    cache: CacheConfig::default(),
    tracker: TrackerConfig {
        telemetry_endpoint: "127.0.0.1:0".parse().unwrap(),
        ..TrackerConfig::default()
    },
    p2p: P2pConfig::default(),
};
```

Der zurückgelieferte `ElectrsHandles`-Container enthält den Firewood-Adapter,
den Runtime-gestützten Daemon sowie den Tracker, der den Index aktualisiert und
Skripthash-Statusabfragen bedient.【F:rpp/wallet/src/vendor/electrs/init.rs†L13-L135】

### CLI-Szenarien

* `wallet_tracker_rpp.toml` aktiviert Runtime und Tracker, erzeugt einen Demo-Block
  und überprüft die Index-Synchronisation inklusive History-/VRF-Daten. Das
  Szenario wird vom Integrationstest `vendor_electrs_tracker_scenario` geladen
  und eignet sich als Smoke-Test für Firewood-basierte Workflows.【F:scenarios/wallet_tracker_rpp.toml†L1-L20】【F:rpp/wallet/tests/vendor_electrs_tracker_scenario.rs†L1-L239】
* `wallet_tracker_p2p.toml` erweitert das Setup um P2P-spezifische Parameter:
  Netzwerk-ID, Auth-Token sowie explizite Gossip-Topics. Der Tracker abonniert
  den Broadcast-Kanal, wodurch sich P2P-Weg und Firewood-Fallback gemeinsam
  testen lassen.【F:scenarios/wallet_tracker_p2p.toml†L1-L25】【F:rpp/wallet/src/vendor/electrs/init.rs†L34-L135】

## Diff-Empfehlung

Um lokale Anpassungen sichtbar zu machen, empfiehlt sich eine Referenzkopie der entpackten Dateien:

```bash
TMP_DIR=$(mktemp -d)
unzip vendor/electrs-master.zip 'electrs-master/src/chain.rs' 'electrs-master/src/types.rs' -d "$TMP_DIR"
diff -u "$TMP_DIR"/electrs-master/src/chain.rs vendor/electrs/2024-05-20/src/chain.rs
```

Auf diese Weise bleiben Upstream-Änderungen transparent und können in zukünftigen Updates gezielt
übernommen werden.
