# Libp2p Netzwerk Aufgaben

## 1. Libp2p-Abhängigkeiten auf Workspace-Versionen umstellen
- **Ziel:** Nutzung der im Workspace definierten Libp2p-Versionen in `rpp-p2p`, um Versionsmanagement zu vereinfachen.
- **Arbeitsschritte:**
  1. `rpp/p2p/Cargo.toml` öffnen und lokale `vendor`-Pfade durch `workspace = true` ersetzen.
  2. Feature-Gates so anpassen, dass `noise`, `tcp`, `yamux`, `gossipsub`, `identify`, `ping` und `request-response` verfügbar bleiben.
  3. `cargo metadata` oder `cargo check -p rpp-p2p` ausführen, um die Änderungen zu validieren.

## 2. Swarm-Erstellung aus `Network::new` herauslösen
- **Ziel:** Bessere Testbarkeit und Wiederverwendbarkeit durch einen dedizierten Swarm-Builder.
- **Arbeitsschritte:**
  1. Neues Modul `rpp/p2p/src/swarm/builder.rs` anlegen und Transport-/Handshake-Konfiguration kapseln.
  2. Peerstore-, Admission- und Event-Hooks als Parameter einführen.
  3. `Network::new` und seine Aufrufer anpassen, damit sie den neuen Builder nutzen.

## 3. Strukturierte GossipSub-Payloads definieren
- **Ziel:** Typisierte Payloads für Topics `blocks`, `votes`, `proofs`, `snapshots` und `meta` bereitstellen.
- **Arbeitsschritte:**
  1. In `rpp/p2p/src/topics.rs` oder `topics/messages.rs` entsprechende Strukturen/Enums mit `serde`-/`bincode`-Derives ergänzen.
  2. Typen in `rpp/p2p/src/lib.rs` exportieren.
  3. Verpflichtende Felder dokumentieren.

## 4. Serialisierungstests für Gossip-Payloads hinzufügen
- **Ziel:** Roundtrip-Tests zur Absicherung der neuen Payload-Formate.
- **Arbeitsschritte:**
  1. Datei `rpp/p2p/tests/topic_encoding.rs` anlegen.
  2. Roundtrip-Tests für jedes Topic implementieren.
  3. Optional zusätzliche Varianten- oder Property-Tests ergänzen.

## 5. CLI um P2P- und Key-Overrides erweitern
- **Ziel:** Operator:innen erlauben, P2P- und Key-Pfade per CLI zu überschreiben.
- **Arbeitsschritte:**
  1. Flags wie `--key-path`, `--p2p-key-path`, `--p2p-listen`, `--p2p-bootstrap`, `--p2p-heartbeat`, `--p2p-gossip-enabled` in `rpp/node/src/main.rs` ergänzen.
  2. `apply_overrides` erweitern, um die neuen Flags in `NodeConfig` anzuwenden.
  3. Pfaderstellung und Validierungen sicherstellen.

## 6. P2P-Smoke-Test erstellen
- **Ziel:** Schneller deterministischer Smoke-Test mit Präfix `p2p::`.
- **Arbeitsschritte:**
  1. `tests/p2p_smoke.rs` anlegen und bestehende Test-Helfer nutzen.
  2. Mindestens einen Test mit Präfix `p2p::` definieren.
  3. Test deterministisch ohne externe Netzwerke gestalten.

## 7. Milestone A im Netzwerk-Plan aktualisieren
- **Ziel:** Deliverables und DoD-Kriterien für Milestone A dokumentieren.
- **Arbeitsschritte:**
  1. `docs/libp2p_network_plan.md` um einen Abschnitt für die Deliverables erweitern.
  2. Relevante Module referenzieren (`rpp/p2p/src/swarm/...`, `rpp/p2p/src/topics/...`, `rpp/node/src/main.rs`, `tests/p2p_smoke.rs`).
  3. Nutzung der neuen CLI-Flags und Ablageorte der Konfiguration beschreiben.
