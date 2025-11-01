# Tooling

The pinned Rust toolchain requires the following components to be installed:

- rustfmt
- clippy

## Vendored libp2p stack checks

The integration tests rely on the vendored libp2p transport stack being
buildable with the TCP + Noise + Yamux combination. Run

```bash
cargo check -p rpp-p2p --features "noise tcp yamux"
```

to validate the stack locally. When QUIC support is enabled, also verify the
combined feature set with

```bash
cargo check -p rpp-p2p --features "noise tcp yamux quic"
```

to ensure the additional transport compiles alongside the default TCP stack.

For operational guidance on the runtime CLI—including authentication, rate limits,
and recovery procedures—consult the [`rpp-node` operator guide](../rpp_node_operator_guide.md).

## Fehlersuche

| Fehlermeldung | Ursache | Lösung |
| --- | --- | --- |
| `error: component 'rustfmt' is not installed for toolchain` | Die benötigten Komponenten der fixierten Toolchain wurden noch nicht installiert. | Installiere die fehlenden Komponenten mit `rustup component add rustfmt clippy --toolchain <toolchain>` oder nutze `rustup component add rustfmt clippy --toolchain nightly-2025-07-14`. |
| `error: toolchain 'nightly' is not installed` | Die Nightly-Toolchain ist lokal nicht vorhanden. | Installiere die Toolchain mit `rustup toolchain install nightly-2025-07-14` oder passe die `rust-toolchain.toml`-Konfiguration an. |
| `error: The 'prover-stwo' feature requires the Rust nightly toolchain.` | Das Feature `prover-stwo` wurde aktiviert, aber der Build läuft nicht mit einer Nightly-Toolchain oder ohne `RUSTC_BOOTSTRAP`. | Wechsle auf eine Nightly-Toolchain (`rustup override set nightly-2025-07-14`) oder setze vor dem Build `RUSTC_BOOTSTRAP=1`. |

<a name="config-keygen-troubleshooting"></a>

## Konfigurations- und Schlüsselgenerierung

Die folgenden Hinweise helfen bei typischen Fehlern rund um `rpp-node <modus> --dry-run` sowie die Validator-Unterbefehle wie `rpp-node validator vrf rotate`.

### Häufige Stolperfallen

- **Bestehende Dateien werden überschrieben.** `rpp-node <modus> --write-config` serialisiert die aufgelöste Konfiguration erneut auf den ursprünglichen Pfad, sobald der Loader erfolgreich war. Die Validator-Helfer wie `rpp-node validator vrf rotate` speichern Schlüsselpaare direkt über den konfigurierten Secrets-Store, ohne nach einer Bestätigung zu fragen. Erstelle daher vor erneuten Läufen Backups oder arbeite mit Kopien im Arbeitsverzeichnis.【F:rpp/node/src/lib.rs†L688-L707】【F:rpp/node/src/main.rs†L238-L276】【F:rpp/runtime/config.rs†L749-L781】
- **Ungültige Pflichtfelder führen zu Validierungsfehlern.** Nach dem Laden prüft `NodeConfig::validate`, dass essenzielle Felder wie `block_time_ms`, `max_block_transactions`, `mempool_limit`, `epoch_length`, `target_validator_count` und `max_proof_size_bytes` größer als `0` sind. Außerdem müssen optionale Strings wie `network.rpc.auth_token` und `network.rpc.allowed_origin`, falls gesetzt, nicht leer sein; das Token-Bucket-Limit unter `network.limits.per_ip_token_bucket` erfordert positive Werte. Passe die Werte an und speichere die Datei erneut, bevor du `rpp-node <modus>` (ggf. mit `--dry-run`) ausführst.【F:rpp/runtime/config.rs†L772-L910】【F:rpp/runtime/config.rs†L200-L228】【F:rpp/node/src/lib.rs†L709-L726】
- **Blueprint-Defaults liegen in `config/malachite.toml`.** `NodeConfig::load` liest die Nachbar-Datei automatisch ein, prüft die SemVer-Angabe und fällt bei fehlender Datei auf die integrierten Standardwerte zurück, bevor die Validierung startet.【F:config/malachite.toml†L1-L82】【F:rpp/runtime/config.rs†L24-L215】
- **Wallet-Konfiguration benötigt Gossip-Endpunkte ohne eingebetteten Node.** Das Wallet verlangt laut `WalletConfig::validate`, dass `gossip_endpoints` gesetzt und nicht leer sind, wenn `embedded = false`. Bei einem Fehler lösche leere Einträge oder aktiviere den eingebetteten Node (`embedded = true`).【F:rpp/runtime/config.rs†L405-L425】

### Wiederherstellungsschritte

1. **Datei auf Werkseinstellungen zurücksetzen.** Lösche die beschädigte Datei und führe `rpp-node <modus> --dry-run --write-config --config config/node.toml` (bzw. den passenden Wallet-Pfad) aus. Der Loader rendert das Standardprofil erneut und persistiert es an der angegebenen Stelle.【F:rpp/node/src/lib.rs†L688-L707】【F:rpp/node/src/lib.rs†L1713-L1740】
2. **Verzeichnisse sicherstellen.** Falls der Lauf wegen fehlender Verzeichnisse abbricht, starte den Befehl erneut: `NodeConfig::ensure_directories` legt `data/`, `keys/`, `data/p2p/` usw. automatisch an und berücksichtigt dabei den gewählten Secrets-Backend. Gleiches gilt für `WalletConfig::ensure_directories` bei der Wallet-Konfiguration.【F:rpp/node/src/lib.rs†L850-L889】【F:rpp/runtime/config.rs†L759-L769】【F:rpp/runtime/config.rs†L1139-L1181】
3. **Schlüssel neu erzeugen.** Bei beschädigten oder inkonsistenten Schlüsseln (`z. B.` VRF-Mismatch) lösche die betroffenen Dateien und rotiere sie mit `rpp-node validator vrf rotate --config config/validator.toml`. Identitäts- und Wallet-Schlüssel regeneriert der Loader automatisch, sobald du `rpp-node wallet --dry-run` (oder den entsprechenden Modus) startest; alternative Keystores nutzt anschließend `NodeConfig::load_or_generate_vrf_keypair`.【F:rpp/node/src/main.rs†L238-L317】【F:rpp/node/src/lib.rs†L850-L904】【F:rpp/crypto/mod.rs†L555-L562】【F:rpp/runtime/config.rs†L567-L574】

> 💡 Tipp: Nach manuellen Änderungen kannst du die Validierung ohne Start des Nodes testen, indem du `rpp-node <modus> --dry-run --config <bestehende-datei>` ausführst – der Lauf startet keine Pipelines, liefert aber präzise Fehlermeldungen, falls Werte ungültig sind.【F:rpp/node/src/lib.rs†L709-L726】

### Mempool-Tuning und Live-Anpassungen

- **Queue-Gewichte inspizieren.** Die RPC-Antwort von `/status/mempool` enthält jetzt das Feld `queue_weights`, sodass du mit
  `curl http://127.0.0.1:7070/status/mempool | jq '.queue_weights'` sofort siehst, wie stark Priorität vs. Gebühren gewichtet
  werden.【F:rpp/runtime/node.rs†L120-L141】【F:rpp/rpc/api.rs†L515-L563】【F:rpp/rpc/api.rs†L840-L880】
- **Limits und Gewichtung live anpassen.** Über `POST /control/mempool` kannst du den Hard-Limit-Schwellwert und die beiden
  Gewichte ohne Neustart umschalten, z. B. `curl -X POST http://127.0.0.1:7070/control/mempool -H 'Content-Type: application/json' -d '{"limit":16384,"priority_weight":0.6,"fee_weight":0.4}'`. Die Server-Seite erzwingt dabei, dass die Gewichte ≥ 0 sind und zusammen exakt 1 ergeben, sodass Konfigurationen aus `config/node.toml` konsistent bleiben.【F:config/node.toml†L3-L23】【F:rpp/runtime/config.rs†L207-L256】【F:rpp/runtime/node.rs†L120-L141】【F:rpp/rpc/api.rs†L515-L575】【F:rpp/rpc/api.rs†L840-L880】
