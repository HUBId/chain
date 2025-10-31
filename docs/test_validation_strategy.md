# Test- und Validierungsstrategie

Diese Strategie beschreibt, wie die STWO/Plonky3-Integration vollständig überprüft wird. Sie kombiniert klassische Unit-Tests, umfangreiche Integrationstests, deterministische Rekursionsprüfungen und Performance-Analysen. Alle Schritte sind so formuliert, dass sie sowohl für das bestehende STWO-Backend als auch für das geplante Plonky3-Backend gelten.

## 1. Testebenen

### 1.1 Unit-Tests
- **Kern-Circuits**: `tests/unit/circuits.rs` lädt den offiziellen STWO-Fixture-Proof und verifiziert Witness-/Proof-Roundtrips gegen den Backend-Decoder. Die Suite prüft deterministische Commitments und sorgt dafür, dass Public-Inputs unverändert bleiben.
- **Aggregations- und Snapshot-Helfer**: `tests/unit/aggregation.rs` erzeugt Poseidon-folds für deterministische Segmentlisten und validiert die Resultate gegen erwartete Hex-Digests, inklusive Stabilitätsprüfungen bei geänderter Segment-Reihenfolge.
- **Hilfsstrukturen**: `tests/unit/helpers.rs` testet JSON-Roundtrips für `ChainProof::Stwo`, prüft `expect_stwo`/`into_stwo` und stellt sicher, dass die Fixture-Daten aus `tests/common/stwo_transaction.rs` vollständig rekonstruiert werden können.

Die Unit-Suite wird über den Root-Harness `tests/unit.rs` registriert, damit Cargo beim Ausführen der Paket-Tests (`cargo test -p rpp-chain`) automatisch alle Module lädt.

### 1.2 Integrationstests
- **Wallet-Prover**: `tests/integration/wallet.rs` koppelt den offiziellen Backend-Fixture-Proof mit dem `ProofVerifierRegistry`, verifiziert Erfolgs- und Fehlpfade und prüft, dass manipulierte Public-Inputs abgelehnt werden.
- **Node-Verifier**: `tests/integration/node.rs` importiert Fixture-Beweise, erzwingt Witness-Manipulationen und erwartet präzise `ChainError::Crypto`-Antworten des Verifiers.
- **Synchronisation**: `tests/integration/sync.rs` baut eine Mini-Kette mit Dummy-Blöcken, erzeugt Rehydrierungspläne und überprüft die Konsistenz exportierter Artefakte. Gemeinsame Hilfsfunktionen werden aus `tests/support` eingebunden.

Der Harness `tests/integration.rs` sorgt für die Registrierung der Module, während `tests/common/stwo_transaction.rs` geteilte Fixtures für beide Ebenen bereitstellt.

### 1.3 System- und Szenariotests
- **End-to-End**: Start eines lokalen Netzwerks (mindestens zwei Wallets + ein Node) mit VRF-basierter Leader-Selektion, Erzeugung von Blöcken und vollständiger Rekursionskette.
- **Migrationspfad**: Sicherstellen, dass `migration` alte Datensätze korrekt in das `ChainProof`-Format überführt und anschließend verifiziert wird.
- **Fuzzing/Property-Tests**: Einsatz von `proptest` für Witness-Parser und State-Höhen, um Grenzwerte aufzudecken.

## 2. Cross-Backend-Parität
- **Feature-Matrix**: Jeder Testfall wird mit der STWO-Basis sowie mit aktiviertem `prover-stwo`-Feature validiert. `cargo xtask test-matrix` erzwingt dafür die Läufe `cargo +stable test -p rpp-chain --all-targets --locked` und `cargo +nightly-2025-07-14 test -p rpp-chain --all-targets --features prover-stwo --locked`. Erweiterte Backends (z. B. Plonky3) werden über dedizierte Suites ergänzt, sobald sie implementiert sind.
- **Kompatibilitäts-Vektoren**: Gemeinsame Testvektoren (bincode-Dateien) stellen sicher, dass beide Backends identische öffentliche Inputs erzeugen.
- **Regression**: Bei Fehlern in einem Backend wird der Testfall dupliziert, um Backend-spezifische Regressionen nachvollziehbar zu machen.

## 3. Performance- und Ressourcenanalyse
- **Benchmark-Suite**: Nutzung von `criterion`-Benchmarks für Prover- und Verifier-Laufzeiten; getrennt nach Circuit-Typ und Backend.
- **GPU/FFI-Tests**: Falls GPU-Beschleunigung verfügbar ist, werden zusätzliche Smoke-Tests unter aktivierter FFI durchgeführt, um Speicherlecks und Race Conditions auszuschließen.
- **Telemetrie**: Erfassen von Metriken (Proof-Dauer, Verifikationszeit, Speicherbedarf) und Export zu Prometheus für Langzeitvergleiche.

- **GitHub Actions Pipeline**:
  - Formatierung (`cargo fmt --all -- --check`)
  - Linting (`cargo clippy --workspace --all-targets --all-features -- -D warnings`)
  - STWO-Feature-Matrix (`cargo xtask test-matrix`), die Unit- und Integrationstests des Pakets `rpp-chain` unter stabiler und nightly Toolchain abdeckt.
  - Optionale Stufen: Benchmarks (nightly), Fuzzing (cron), Integrationstests (nightly) für weitere Backends.
- **Artefaktverwaltung**: Speicherung generierter Beispiel-Proofs und Logs zur Reproduktion fehlschlagender Runs.

## 5. Dokumentation & Review-Prozess
- **Testprotokolle**: Jeder Release-Kandidat benötigt ein Protokoll mit ausgeführten Testläufen und Ergebnissen.
- **Code-Review-Checkliste**: Enthält Prüfpunkte für Circuit-Constraints, Witness-Glaubwürdigkeit, Fehlerbehandlung und Cross-Backend-Abdeckung.
- **Onboarding-Guides**: Schritt-für-Schritt-Anleitungen für Entwickler:innen, wie Tests lokal reproduziert werden (inkl. Feature-Flags, optionaler GPU-Konfiguration und notwendigen Umgebungsvariablen).

## 6. Erweiterbarkeit
- **Neue Circuit-Typen**: Für zukünftige Circuits werden Templates bereitgestellt, die Unit-, Integration- und Benchmark-Tests standardisiert anlegen.
- **Konfigurierbare Szenarien**: YAML/TOML-basierte Testdefinitionen erlauben es, neue Ledger- und Konsensus-Konstellationen ohne Codeänderung zu definieren.
- **Automatisierte Regressionen**: Fehlgeschlagene Szenarien aus Produktion werden als reproduzierbare Tests in die Suite übernommen.

Diese Strategie stellt sicher, dass Funktionalität, Sicherheit, Performance und Interoperabilität der STWO/Plonky3-Integration kontinuierlich überprüft und dokumentiert werden.
