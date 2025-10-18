# Electrs Vendor Snapshot (2024-05-20)

- **Upstream-Quelle:** `vendor/electrs-master.zip`
- **Referenz-Commit:** `4a5af61668a1414f112fe8b07b23bff554779a4f`
- **Importumfang:** `src/chain.rs`, `src/types.rs`

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
| `tracker.telemetry_endpoint` | Socket-Adresse, unter der der Tracker seine Mempool-Metriken registriert. Standardmäßig wird `127.0.0.1:0` verwendet, womit die Handles nur intern verdrahtet werden.【F:rpp/wallet/src/config.rs†L86-L109】|

Die Workspace-Feature-Flag `vendor_electrs` aktiviert sämtliche optionalen
Abhängigkeiten (`serde`, `tokio`, `storage-firewood`, `rpp`-Runtime usw.) und
bindet die vendorten Module in `rpp-wallet` ein.【F:rpp/wallet/Cargo.toml†L8-L27】【F:rpp/wallet/src/lib.rs†L13-L27】

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
use rpp_wallet::config::{CacheConfig, ElectrsConfig, FeatureGates, NetworkSelection, TrackerConfig};
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
    },
};
```

Der zurückgelieferte `ElectrsHandles`-Container enthält den Firewood-Adapter,
den Runtime-gestützten Daemon sowie den Tracker, der den Index aktualisiert und
Skripthash-Statusabfragen bedient.【F:rpp/wallet/src/vendor/electrs/init.rs†L13-L82】

## Diff-Empfehlung

Um lokale Anpassungen sichtbar zu machen, empfiehlt sich eine Referenzkopie der entpackten Dateien:

```bash
TMP_DIR=$(mktemp -d)
unzip vendor/electrs-master.zip 'electrs-master/src/chain.rs' 'electrs-master/src/types.rs' -d "$TMP_DIR"
diff -u "$TMP_DIR"/electrs-master/src/chain.rs vendor/electrs/2024-05-20/src/chain.rs
```

Auf diese Weise bleiben Upstream-Änderungen transparent und können in zukünftigen Updates gezielt
übernommen werden.
