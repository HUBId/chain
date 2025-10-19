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

For operational guidance on the RPC CLI—including authentication, rate limits, and
recovery procedures—consult the [RPC CLI Operator Guide](../rpc_cli_operator_guide.md).

## Fehlersuche

| Fehlermeldung | Ursache | Lösung |
| --- | --- | --- |
| `error: component 'rustfmt' is not installed for toolchain` | Die benötigten Komponenten der fixierten Toolchain wurden noch nicht installiert. | Installiere die fehlenden Komponenten mit `rustup component add rustfmt clippy --toolchain <toolchain>` oder nutze `rustup component add rustfmt clippy --toolchain nightly`. |
| `error: toolchain 'nightly' is not installed` | Die Nightly-Toolchain ist lokal nicht vorhanden. | Installiere die Toolchain mit `rustup toolchain install nightly` oder passe die `rust-toolchain.toml`-Konfiguration an. |
| `error: The 'prover-stwo' feature requires the Rust nightly toolchain.` | Das Feature `prover-stwo` wurde aktiviert, aber der Build läuft nicht mit einer Nightly-Toolchain oder ohne `RUSTC_BOOTSTRAP`. | Wechsle auf eine Nightly-Toolchain (`rustup override set nightly`) oder setze vor dem Build `RUSTC_BOOTSTRAP=1`. |

<a name="config-keygen-troubleshooting"></a>

## Konfigurations- und Schlüsselgenerierung

Die folgenden Hinweise helfen bei typischen Fehlern rund um `cargo run -- generate-config` und `cargo run -- keygen`.

### Häufige Stolperfallen

- **Bestehende Dateien werden überschrieben.** Weder `generate-config` noch `keygen` fragen nach einer Bestätigung, bevor sie `config/node.toml`, `config/wallet.toml` oder Schlüsseldateien unter `keys/` neu schreiben. Lege vor erneuten Läufen ein Backup an oder verwende einen alternativen Pfad mit `--path`, wenn du bestehende Werte behalten möchtest. Die Implementierung schreibt die Dateien direkt mit `NodeConfig::save` bzw. `save_keypair`/`save_vrf_keypair` neu.【F:src/main.rs†L266-L287】【F:rpp/crypto/mod.rs†L111-L143】【F:rpp/crypto/mod.rs†L197-L215】
- **Ungültige Pflichtfelder führen zu Validierungsfehlern.** Nach dem Generieren prüft `NodeConfig::validate`, dass essenzielle Felder wie `block_time_ms`, `max_block_transactions`, `mempool_limit`, `epoch_length`, `target_validator_count` und `max_proof_size_bytes` größer als `0` sind. Außerdem müssen optionale Strings wie `rpc_auth_token` und `rpc_allowed_origin`, falls gesetzt, nicht leer sein; dasselbe gilt für `rpc_requests_per_minute` (muss > 0 sein). Passe die Werte an und speichere die Datei erneut, bevor du `cargo run -- start` ausführst.【F:rpp/runtime/config.rs†L83-L183】【F:rpp/runtime/config.rs†L200-L228】
- **Wallet-Konfiguration benötigt Gossip-Endpunkte ohne eingebetteten Node.** Das Wallet verlangt laut `WalletConfig::validate`, dass `gossip_endpoints` gesetzt und nicht leer sind, wenn `embedded = false`. Bei einem Fehler lösche leere Einträge oder aktiviere den eingebetteten Node (`embedded = true`).【F:rpp/runtime/config.rs†L405-L425】

### Wiederherstellungsschritte

1. **Datei auf Werkseinstellungen zurücksetzen.** Lösche die beschädigte Datei und führe den jeweiligen Generator erneut aus, z. B. `cargo run -- generate-config --path config/node.toml`. Dadurch werden Standardwerte geschrieben, die die Validierung bestehen.【F:src/main.rs†L266-L273】【F:rpp/runtime/config.rs†L229-L280】
2. **Verzeichnisse sicherstellen.** Falls das Kommando wegen fehlender Verzeichnisse abbricht, starte `generate-config` erneut: `NodeConfig::ensure_directories` legt `data/`, `keys/`, `data/p2p/` usw. automatisch an. Gleiches gilt für `WalletConfig::ensure_directories` bei der Wallet-Konfiguration.【F:src/main.rs†L266-L279】【F:rpp/runtime/config.rs†L110-L156】【F:rpp/runtime/config.rs†L360-L388】
3. **Schlüssel neu erzeugen.** Sollten Schlüsseldateien beschädigt oder inkonsistent sein (z. B. VRF-Mismatch), lösche die betroffenen Dateien und führe `cargo run -- keygen --path keys/node.toml --vrf-path keys/vrf.toml` erneut aus. Die Helfer sorgen für das richtige TOML-Format und erzeugen konsistente Schlüsselpaare.【F:src/main.rs†L280-L287】【F:rpp/crypto/mod.rs†L180-L241】

> 💡 Tipp: Nach manuellen Änderungen kannst du die Validierung ohne Start des Nodes testen, indem du `cargo run -- generate-config --path <bestehende-datei>` ausführst – der Befehl schreibt zwar neu, aber schlägt mit einer aussagekräftigen Fehlermeldung fehl, falls die Werte ungültig sind.

### Mempool-Tuning und Live-Anpassungen

- **Queue-Gewichte inspizieren.** Die RPC-Antwort von `/status/mempool` enthält jetzt das Feld `queue_weights`, sodass du mit
  `curl http://127.0.0.1:7070/status/mempool | jq '.queue_weights'` sofort siehst, wie stark Priorität vs. Gebühren gewichtet
  werden.【F:rpp/runtime/node.rs†L120-L141】【F:rpp/rpc/api.rs†L515-L563】【F:rpp/rpc/api.rs†L840-L880】
- **Limits und Gewichtung live anpassen.** Über `POST /control/mempool` kannst du den Hard-Limit-Schwellwert und die beiden
  Gewichte ohne Neustart umschalten, z. B. `curl -X POST http://127.0.0.1:7070/control/mempool -H 'Content-Type: application/json' -d '{"limit":16384,"priority_weight":0.6,"fee_weight":0.4}'`. Die Server-Seite erzwingt dabei, dass die Gewichte ≥ 0 sind und zusammen exakt 1 ergeben, sodass Konfigurationen aus `config/node.toml` konsistent bleiben.【F:config/node.toml†L3-L23】【F:rpp/runtime/config.rs†L207-L256】【F:rpp/runtime/node.rs†L120-L141】【F:rpp/rpc/api.rs†L515-L575】【F:rpp/rpc/api.rs†L840-L880】
