# Test- und Validierungsstrategie

Diese Strategie beschreibt, wie die STWO- und Plonky3-Integrationen vollständig überprüft werden. Die Plonky3-Schritte validieren den produktiven Vendor-Prover/-Verifier, messen Tamper-Resilienz und dokumentieren die Acceptance-Kriterien für Phase 2.

## 1. Testebenen

### 1.1 Unit-Tests
- **Kern-Circuits**: Für jeden Circuit (`transaction`, `identity`, `state`, `pruning`, `uptime`, `consensus`, `recursive`) werden Constraints und Witness-Generatoren mit gezielten Testfällen abgedeckt. Spezialfälle (z. B. doppelte Votes im Consensus-Circuit oder negative Gebühren in Transaktionen) erhalten dedizierte Regressionstests.
- **Aggregations- und Snapshot-Helfer**: Die Hash-Pfade und StateCommitment-Snapshots in `stwo::aggregation` werden gegen deterministische Referenzvektoren getestet.
- **Hilfsstrukturen**: Parser für Witness-Daten (`types::proofs`, `plonky3::proof`) und das Serialisierungsformat `ChainProof` erhalten Roundtrip-Tests. Commitments für Plonky3 prüfen zusätzlich eine kanonische JSON-Kodierung, bei der Objekt-Schlüssel vor der Serialisierung sortiert werden.
- **Regressions-Suites**: Die dedizierten Targets unter `tests/unit/` prüfen deterministische Witness-Kodierung (`stwo_circuits.rs`), Firewood-Merkle-Wurzeln (`firewood_roots.rs`) sowie VRF/BFT-Gewichtungen (`vrf_bft.rs`) gegen reproduzierbare Erwartungen und dienen als Guardrails für spätere Refactorings.【F:tests/unit/stwo_circuits.rs†L1-L70】【F:tests/unit/firewood_roots.rs†L1-L24】【F:tests/unit/vrf_bft.rs†L1-L83】

### 1.2 Integrationstests
- **Wallet-Prover**: Szenarien vom Bau eines Blocks bis zum Generieren aller Teilbeweise. Enthält Varianten für Identitäts-Genesis, normale Transaktionen, Uptime- und Konsensus-Proofs sowie den rekursiven Block-Proof. Für Plonky3 werden die gleichen Szenarien mit aktiviertem Feature `backend-plonky3` ausgeführt.
- **Backend-Parität**: Die Standardläufe von `scripts/test.sh` decken `default`, `stwo`, `rpp-stark` und `plonky3` ab. Für Plonky3 werden echte Proofs erzeugt, Witness-Manipulationen getestet und Commitments validiert, sodass alle Produktionsbackends dieselben Acceptance-Kriterien erfüllen.【F:scripts/test.sh†L1-L220】【F:docs/testing/plonky3_experimental_testplan.md†L1-L120】
- **Node-Verifier**: Tests für den Import eines Blocks, die Verifikation einzelner Proof-Kategorien und die rekursive Bestätigung der Kette. Fehlerfälle (z. B. manipulierte Witnesses) führen zu erwarteten Fehlermeldungen.
- **Synchronisation**: Cross-node-Sync-Tests (`sync`-Modul), die prüfen, dass rekursive Beweise beim Nachladen historischer Blöcke akzeptiert werden.
- **Pipeline-/Sync-Orchestrierung**: Die Integration-Suite unter `tests/integration/` hält End-to-End-Blockproduktion, Snapshot-/Light-Client-Pläne und Operator-RPC-Steuerung als reproduzierbare Workflows fest (`block_production.rs`, `snapshot_light_client.rs`, `operator_rpcs.rs`). Die Tests dokumentieren zugleich Start-/Stop-Orchestrierung und überspringen sich selbst, falls Binärabhängigkeiten fehlen.【F:tests/integration/block_production.rs†L1-L38】【F:tests/integration/snapshot_light_client.rs†L1-L33】【F:tests/integration/operator_rpcs.rs†L1-L45】

### 1.3 System- und Szenariotests
- **End-to-End**: Start eines lokalen Netzwerks (mindestens zwei Wallets + ein Node) mit VRF-basierter Leader-Selektion, Erzeugung von Blöcken und vollständiger Rekursionskette.
- **Migrationspfad**: Sicherstellen, dass `migration` alte Datensätze korrekt in das `ChainProof`-Format überführt und anschließend verifiziert wird.
- **Fuzzing/Property-Tests**: Einsatz von `proptest` für Witness-Parser und State-Höhen, um Grenzwerte aufzudecken.
- **Simnet-Szenarien**: Das Simulations-Framework (`tools/simnet/`) liefert Szenarien wie `ci_block_pipeline.ron`, die CI-freundlich Binärabhängigkeiten prüfen (hier: `cargo test --test integration -- --list`) und orchestrierte Artefakt-Verzeichnisse erzeugen.【F:tools/simnet/scenarios/ci_block_pipeline.ron†L1-L16】【F:tools/simnet/src/main.rs†L1-L59】

## 2. Cross-Backend-Parität
- **Feature-Matrix**: Die Standard-Matrix umfasst `default`, `stwo`, `rpp-stark` und `plonky3`; Release- und CI-Pipelines führen alle Backends verpflichtend aus.【F:.github/workflows/release.yml†L55-L120】【F:scripts/test.sh†L15-L210】
- **Kompatibilitäts-Vektoren**: Gemeinsame Testvektoren (bincode-Dateien) stellen sicher, dass beide Backends identische öffentliche Inputs erzeugen.
- **Regression**: Bei Fehlern in einem Backend wird der Testfall dupliziert, um Backend-spezifische Regressionen nachvollziehbar zu machen.

### 2.1 Plonky3-spezifische Checks
- **Ad-hoc-Läufe**: Zusätzliche Validierungen wie `cargo test --features backend-plonky3 --test plonky3_recursion` und das Simnet-Szenario `consensus-quorum-stress` ergänzen die Matrixläufe und liefern detaillierte Belege für Tamper-Rejection und Latenz-SLOs.【F:tests/plonky3_recursion.rs†L1-L360】【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】

## 3. Performance- und Ressourcenanalyse
- **Benchmark-Suite**: Nutzung von `criterion`-Benchmarks für Prover- und Verifier-Laufzeiten; getrennt nach Circuit-Typ und Backend.
- **GPU/FFI-Tests**: Falls GPU-Beschleunigung verfügbar ist, werden zusätzliche Smoke-Tests unter aktivierter FFI durchgeführt, um Speicherlecks und Race Conditions auszuschließen.
- **Telemetrie**: Erfassen von Metriken (Proof-Dauer, Verifikationszeit, Speicherbedarf) und Export zu Prometheus für Langzeitvergleiche.

## 4. CI/CD-Integration
### 4.1 Verpflichtende GitHub-Status-Checks
Halte die Branch-Protection-Regel für `main` synchron mit den unten aufgeführten Status-Namen – sobald GitHub andere Namen erwartet, schlagen Merges fehl. Die Checks spiegeln exakt die Schritte wider, die im Release-Workflow laufen und werden für jede Pull-Request-Ausführung der Validierung wiederverwendet.【F:.github/workflows/release.yml†L82-L103】

| Check-Name | Zweck | Lokale Reproduktion |
| --- | --- | --- |
| `fmt` | Rustfmt stellt konsistente Formatierung im gesamten Workspace sicher. | `cargo fmt --all -- --check` |
| `clippy` | `cargo clippy` lints alle Targets und Features mit aktivierten Warnungen als Fehler. | `cargo clippy --workspace --all-targets --all-features -- -D warnings` |
| `test` | Führt die vollständige Backend-Matrix (Default, STWO, RPP-STARK, Plonky3) über `scripts/test.sh` aus. | `./scripts/test.sh --all --unit --integration` |
| `unit-suites` | Erzwingt die deterministischen STWO/Firewood/VRF-Unit-Suites. | `cargo xtask test-unit` |
| `integration-workflows` | Überprüft Blockproduktion, Snapshot-/Light-Client-Pläne und Operator-RPC-Lifecycle. | `cargo xtask test-integration` |
| `simnet-smoke` | Führt das Simnet-Szenario `ci_block_pipeline` aus und protokolliert Artefakte. | `cargo xtask test-simnet` |

> **Hinweis:** `scripts/test.sh` setzt `RUSTFLAGS=-D warnings`, aktiviert automatisch das passende Feature-Set und wählt für STWO den gepinnten Nightly-Toolchain, damit lokale Läufe die CI-Ergebnisse widerspiegeln.【F:scripts/test.sh†L4-L8】【F:scripts/test.sh†L81-L210】

- **GitHub Actions Workflows**:
  - [`Release`](../.github/workflows/release.yml): Führt `./scripts/test.sh --all --backend default --backend stwo --backend rpp-stark --backend plonky3` aus und deckt damit die vollständige Produktionsmatrix inklusive Plonky3 ab.【F:.github/workflows/release.yml†L55-L120】
  - [`CI`](../.github/workflows/ci.yml): Ergänzt `fmt`, `clippy` und `test` um die verpflichtenden Gates `unit-suites`,
    `integration-workflows` und `simnet-smoke`. Die Jobs delegieren an `cargo xtask test-unit`, `cargo xtask test-integration`
    und `cargo xtask test-simnet`, womit alle drei Testebenen (Unit, Workflow, Simulation) automatisiert abgedeckt werden und
    Contributors dieselben Läufe lokal reproduzieren können.【F:.github/workflows/ci.yml†L63-L96】【F:xtask/src/main.rs†L1-L86】
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
  - `scripts/test.sh --backend plonky3 --unit --integration`: Reproduziert die produktive Plonky3-Testmatrix lokal (Proof-Generierung, Manipulations-Checks, Telemetrie).【F:scripts/test.sh†L15-L210】【F:docs/testing/plonky3_experimental_testplan.md†L1-L120】
- **Artefaktverwaltung**: Speicherung generierter Beispiel-Proofs und Logs zur Reproduktion fehlschlagender Runs.
- **Planungs-Backlink**: Ergänzende CI-Erweiterungen werden im [Roadmap Implementation Plan](./roadmap_implementation_plan.md)
  verfolgt, damit neue Suites konsistent dokumentiert und priorisiert werden.
- **Geplanter CI-Task**: Erweiterung der Nightly-Matrix um GPU-Profile und Hardwarevarianten für Plonky3, sobald dedizierte Runner verfügbar sind (siehe Testplan-Follow-ups).

## 5. Dokumentation & Review-Prozess
- **Testprotokolle**: Jeder Release-Kandidat benötigt ein Protokoll mit ausgeführten Testläufen und Ergebnissen.
- **Code-Review-Checkliste**: Enthält Prüfpunkte für Circuit-Constraints, Witness-Glaubwürdigkeit, Fehlerbehandlung und Cross-Backend-Abdeckung.
- **Onboarding-Guides**: Schritt-für-Schritt-Anleitungen für Entwickler:innen, wie Tests lokal reproduziert werden (inkl. Feature-Flags, optionaler GPU-Konfiguration und notwendigen Umgebungsvariablen).

## 6. Erweiterbarkeit
- **Neue Circuit-Typen**: Für zukünftige Circuits werden Templates bereitgestellt, die Unit-, Integration- und Benchmark-Tests standardisiert anlegen.
- **Konfigurierbare Szenarien**: YAML/TOML-basierte Testdefinitionen erlauben es, neue Ledger- und Konsensus-Konstellationen ohne Codeänderung zu definieren.
- **Automatisierte Regressionen**: Fehlgeschlagene Szenarien aus Produktion werden als reproduzierbare Tests in die Suite übernommen.

Diese Strategie stellt sicher, dass Funktionalität, Sicherheit, Performance und Interoperabilität der STWO/Plonky3-Integration kontinuierlich überprüft und dokumentiert werden.
