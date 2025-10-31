# Test- und Validierungsstrategie

Diese Strategie beschreibt, wie die STWO/Plonky3-Integration vollständig überprüft wird. Sie kombiniert klassische Unit-Tests, umfangreiche Integrationstests, deterministische Rekursionsprüfungen und Performance-Analysen. Alle Schritte sind so formuliert, dass sie sowohl für das bestehende STWO-Backend als auch für das geplante Plonky3-Backend gelten.

## 1. Testebenen

### 1.1 Unit-Tests
- **Kern-Circuits**: Für jeden Circuit (`transaction`, `identity`, `state`, `pruning`, `uptime`, `consensus`, `recursive`) werden Constraints und Witness-Generatoren mit gezielten Testfällen abgedeckt. Spezialfälle (z. B. doppelte Votes im Consensus-Circuit oder negative Gebühren in Transaktionen) erhalten dedizierte Regressionstests.
- **Aggregations- und Snapshot-Helfer**: Die Hash-Pfade und StateCommitment-Snapshots in `stwo::aggregation` werden gegen deterministische Referenzvektoren getestet.
- **Hilfsstrukturen**: Parser für Witness-Daten (`types::proofs`, `plonky3::proof`) und das Serialisierungsformat `ChainProof` erhalten Roundtrip-Tests.
- **Hilfsstrukturen**: Parser für Witness-Daten (`types::proofs`, `plonky3::proof`) und das Serialisierungsformat `ChainProof` erhalten Roundtrip-Tests. Commitments für Plonky3 prüfen zusätzlich eine kanonische JSON-Kodierung, bei der Objekt-Schlüssel vor der Serialisierung sortiert werden.

### 1.2 Integrationstests
- **Wallet-Prover**: Szenarien vom Bau eines Blocks bis zum Generieren aller Teilbeweise. Enthält Varianten für Identitäts-Genesis, normale Transaktionen, Uptime- und Konsensus-Proofs sowie den rekursiven Block-Proof. Für Plonky3 werden die gleichen Szenarien mit aktiviertem Feature `backend-plonky3` ausgeführt.
- **Node-Verifier**: Tests für den Import eines Blocks, die Verifikation einzelner Proof-Kategorien und die rekursive Bestätigung der Kette. Fehlerfälle (z. B. manipulierte Witnesses) führen zu erwarteten Fehlermeldungen.
- **Synchronisation**: Cross-node-Sync-Tests (`sync`-Modul), die prüfen, dass rekursive Beweise beim Nachladen historischer Blöcke akzeptiert werden.

### 1.3 System- und Szenariotests
- **End-to-End**: Start eines lokalen Netzwerks (mindestens zwei Wallets + ein Node) mit VRF-basierter Leader-Selektion, Erzeugung von Blöcken und vollständiger Rekursionskette.
- **Migrationspfad**: Sicherstellen, dass `migration` alte Datensätze korrekt in das `ChainProof`-Format überführt und anschließend verifiziert wird.
- **Fuzzing/Property-Tests**: Einsatz von `proptest` für Witness-Parser und State-Höhen, um Grenzwerte aufzudecken.

## 2. Cross-Backend-Parität
- **Feature-Matrix**: Jeder Testfall wird sowohl mit Standard-Features (STWO) als auch mit `--no-default-features --features backend-plonky3` ausgeführt.
- **Kompatibilitäts-Vektoren**: Gemeinsame Testvektoren (bincode-Dateien) stellen sicher, dass beide Backends identische öffentliche Inputs erzeugen.
- **Regression**: Bei Fehlern in einem Backend wird der Testfall dupliziert, um Backend-spezifische Regressionen nachvollziehbar zu machen.

## 3. Performance- und Ressourcenanalyse
- **Benchmark-Suite**: Nutzung von `criterion`-Benchmarks für Prover- und Verifier-Laufzeiten; getrennt nach Circuit-Typ und Backend.
- **GPU/FFI-Tests**: Falls GPU-Beschleunigung verfügbar ist, werden zusätzliche Smoke-Tests unter aktivierter FFI durchgeführt, um Speicherlecks und Race Conditions auszuschließen.
- **Telemetrie**: Erfassen von Metriken (Proof-Dauer, Verifikationszeit, Speicherbedarf) und Export zu Prometheus für Langzeitvergleiche.

## 4. CI/CD-Integration
- **GitHub Actions Workflows**:
  - [`CI`](../.github/workflows/ci.yml): Validiert die Grafana-Dashboard-Exporte in `docs/dashboards/*.json` mithilfe von `jq`,
    um Syntaxfehler frühzeitig zu entdecken. **TODO:** Erweiterung um Format-, Lint- und Testläufe sobald Ressourcen für die
    Rust-Builds reserviert sind.
  - [`nightly-simnet`](../.github/workflows/nightly.yml): Führt eine Matrix von Simnet-Szenarien (`small_world_smoke`,
    `ring_latency_profile`) aus, analysiert die Ergebnisse mit `scripts/analyze_simnet.py` und veröffentlicht die Artefakte
    zur Regressionsanalyse. **TODO:** Automatisches Auswerten von Thresholds und Rückmelden kritischer Abweichungen.
  - [`Nightly fuzzing`](../.github/workflows/nightly-fuzz.yml): Startet `cargo fuzz` für die P2P-Handler (`handle_meta`,
    `handle_blocks`, `handle_votes`, `admission_evaluate_publish`) auf einem Nightly-Toolchain-Setup und archiviert die
    Corpora. **TODO:** Auf Wallet- und Prover-Komponenten ausweiten.
- **Manuelle Prüfpfade**:
  - `scripts/run_hybrid_mode.sh`, `scripts/run_node_mode.sh`, `scripts/run_wallet_mode.sh`: Lokale Smoke-Tests für Node- und
    Wallet-Modi, weiterhin manuell auszuführen bis eine automatisierte Umgebung bereitsteht. **TODO:** Automatisierte Ausführung
    in einer dedizierten Workflow-Umgebung.
  - `tools/simnet/scenarios/*.ron`: Zusätzliche Netzwerkszenarien können lokal per `cargo run -p simnet -- --scenario …`
    getestet werden und sind in der Roadmap als Kandidaten für eine Workflow-Erweiterung vermerkt.
- **Artefaktverwaltung**: Speicherung generierter Beispiel-Proofs und Logs zur Reproduktion fehlschlagender Runs.
- **Planungs-Backlink**: Ergänzende CI-Erweiterungen werden im [Roadmap Implementation Plan](./roadmap_implementation_plan.md)
  verfolgt, damit neue Suites konsistent dokumentiert und priorisiert werden.

## 5. Dokumentation & Review-Prozess
- **Testprotokolle**: Jeder Release-Kandidat benötigt ein Protokoll mit ausgeführten Testläufen und Ergebnissen.
- **Code-Review-Checkliste**: Enthält Prüfpunkte für Circuit-Constraints, Witness-Glaubwürdigkeit, Fehlerbehandlung und Cross-Backend-Abdeckung.
- **Onboarding-Guides**: Schritt-für-Schritt-Anleitungen für Entwickler:innen, wie Tests lokal reproduziert werden (inkl. Feature-Flags, optionaler GPU-Konfiguration und notwendigen Umgebungsvariablen).

## 6. Erweiterbarkeit
- **Neue Circuit-Typen**: Für zukünftige Circuits werden Templates bereitgestellt, die Unit-, Integration- und Benchmark-Tests standardisiert anlegen.
- **Konfigurierbare Szenarien**: YAML/TOML-basierte Testdefinitionen erlauben es, neue Ledger- und Konsensus-Konstellationen ohne Codeänderung zu definieren.
- **Automatisierte Regressionen**: Fehlgeschlagene Szenarien aus Produktion werden als reproduzierbare Tests in die Suite übernommen.

Diese Strategie stellt sicher, dass Funktionalität, Sicherheit, Performance und Interoperabilität der STWO/Plonky3-Integration kontinuierlich überprüft und dokumentiert werden.
