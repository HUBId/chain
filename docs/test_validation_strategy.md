# Test- und Validierungsstrategie

Diese Strategie beschreibt, wie die STWO- und Plonky3-Integrationen vollständig überprüft werden. Die Plonky3-Schritte validieren den produktiven Vendor-Prover/-Verifier, messen Tamper-Resilienz und dokumentieren die Acceptance-Kriterien für Phase 2; Phase-2-Sign-off referenziert die [Plonky3 Production Validation Checklist](testing/plonky3_experimental_testplan.md#4-production-sign-off-checklist), die als Produktions-Checkliste in die Operator-Runbooks eingebunden ist.【F:docs/testing/plonky3_experimental_testplan.md†L1-L121】

## 1. Testebenen

### 1.1 Unit-Tests
- **Kern-Circuits**: Für jeden Circuit (`transaction`, `identity`, `state`, `pruning`, `uptime`, `consensus`, `recursive`) werden Constraints und Witness-Generatoren mit gezielten Testfällen abgedeckt. Spezialfälle (z. B. doppelte Votes im Consensus-Circuit oder negative Gebühren in Transaktionen) erhalten dedizierte Regressionstests.
- **Aggregations- und Snapshot-Helfer**: Die Hash-Pfade und StateCommitment-Snapshots in `stwo::aggregation` werden gegen deterministische Referenzvektoren getestet.
- **Hilfsstrukturen**: Parser für Witness-Daten (`types::proofs`, `plonky3::proof`) und das Serialisierungsformat `ChainProof` erhalten Roundtrip-Tests. Commitments für Plonky3 prüfen zusätzlich eine kanonische JSON-Kodierung, bei der Objekt-Schlüssel vor der Serialisierung sortiert werden.
- **Regressions-Suites**: Die dedizierten Targets unter `tests/unit/` prüfen deterministische Witness-Kodierung (`stwo_circuits.rs`), Firewood-Merkle-Wurzeln (`firewood_roots.rs`), VRF/BFT-Gewichtungen (`vrf_bft.rs`) und – hinter dem Feature-Flag `backend-plonky3` – auch Plonky3-Witnesses (`plonky3_circuits.rs`) gegen reproduzierbare Erwartungen.【F:tests/unit/stwo_circuits.rs†L1-L70】【F:tests/unit/firewood_roots.rs†L1-L24】【F:tests/unit/vrf_bft.rs†L1-L83】【F:tests/unit/plonky3_circuits.rs†L1-L41】

### 1.2 Integrationstests
- **Wallet-Prover**: Szenarien vom Bau eines Blocks bis zum Generieren aller Teilbeweise. Enthält Varianten für Identitäts-Genesis, normale Transaktionen, Uptime- und Konsensus-Proofs sowie den rekursiven Block-Proof. Für Plonky3 werden die gleichen Szenarien mit aktiviertem Feature `backend-plonky3` ausgeführt.
- **Wallet-Runtime**: Die E2E-Suite ergänzt dedizierte Szenarien für Backups (`tests/wallet_backup_recovery_e2e.rs`), Watch-Only-Umschaltungen (`tests/wallet_watch_only_e2e.rs`), RBAC/mTLS-Identitätsauflösung (`tests/wallet_rbac_mtls_e2e.rs`) sowie den ZSI-Lifecycle (`tests/wallet_zsi_flow_e2e.rs`). Die Tests berücksichtigen die Feature-Flags `wallet_zsi`, `wallet_hw`, `wallet_multisig_hooks` und `wallet_rpc_mtls`, sodass die Matrix je nach Konfiguration Assertions überspringt oder anpasst, ohne dass die Coverage verloren geht. Die RBAC/mTLS-Szenarien (`tests/wallet_security.rs`, `tests/wallet_rbac_mtls_e2e.rs`) benötigen das Feature `wallet_rpc_mtls`; lokal lassen sie sich beispielsweise mit `cargo test --features wallet_rpc_mtls --test wallet_security` bzw. `cargo test --features wallet_rpc_mtls --test wallet_rbac_mtls_e2e` ausführen. Ein dedizierter CI-Job ruft zusätzlich `cargo xtask test-wallet-feature-matrix` auf, um `cargo check`/`cargo test` für die Standard-Builds sowie jede einzelne Wallet-Feature-Kombination, die Gesamtmatrix und die Wallet-Feature-Guards zu erzwingen; damit sind Default-, GUI-, ZSI-, Hardware-, Multisig-, RPC-mTLS- und kombinierte Builds lückenlos dokumentiert.【F:.github/workflows/ci.yml†L551-L564】
- **Backend-Parität**: Die Standardläufe von `scripts/test.sh` decken `default`, `stwo`, `rpp-stark` und `plonky3` ab. Für Plonky3 werden echte Proofs erzeugt, Witness-Manipulationen getestet und Commitments validiert, sodass alle Produktionsbackends dieselben Acceptance-Kriterien erfüllen.【F:scripts/test.sh†L1-L220】【F:docs/testing/plonky3_experimental_testplan.md†L1-L120】
- **Consensus-Zertifikate (Phase 2)**: Die Suite `tests/consensus/consensus_certificate_tampering.rs` erzeugt gezielt verdrehte VRF-Outputs sowie manipulierte Quorum-Bitmap- und Signatur-Roots und erwartet, dass beide Backends (`--backend stwo`, `--backend plonky3`) `verify_consensus` mit einem Fehler abbrechen. Die `#[cfg]`-Blöcke koppeln die Szenarien automatisch an die Feature-Matrix der CI, sodass jeder Matrixlauf die Phase‑2-Abnahmekriterien für Tamper-Rejection prüft.【F:tests/consensus/consensus_certificate_tampering.rs†L1-L156】【F:scripts/test.sh†L176-L257】
- **Node-Verifier**: Tests für den Import eines Blocks, die Verifikation einzelner Proof-Kategorien und die rekursive Bestätigung der Kette. Fehlerfälle (z. B. manipulierte Witnesses) führen zu erwarteten Fehlermeldungen.
- **Synchronisation**: Cross-node-Sync-Tests (`sync`-Modul), die prüfen, dass rekursive Beweise beim Nachladen historischer Blöcke akzeptiert werden.
- **Pipeline-/Sync-Orchestrierung**: Die Integration-Suite unter `tests/integration/` hält End-to-End-Blockproduktion, Snapshot-/Light-Client-Pläne, Manipulationsschutz (`manipulation_protection.rs`) und Operator-RPC-Steuerung als reproduzierbare Workflows fest. Die Tests dokumentieren zugleich Start-/Stop-Orchestrierung und überspringen sich selbst, falls Binärabhängigkeiten fehlen.【F:tests/integration/block_production.rs†L1-L38】【F:tests/integration/snapshot_light_client.rs†L1-L33】【F:tests/integration/manipulation_protection.rs†L1-L105】【F:tests/integration/operator_rpcs.rs†L1-L45】
- **Admission-WORM-Failure**: `tests/compliance/worm_export_failure.rs` setzt den Stub-Speicher auf Read-only, triggert die Admission-RPC `/p2p/admission/policies`, überprüft den Logeintrag „failed to append admission audit log“ und verlangt, dass der Prometheus-Zähler `worm_export_failures_total` hochzählt. Die CI-Stufe `worm-export-smoke` ruft den Test neben `cargo xtask test-worm-export` auf; die Nightly-Stufe `worm-export` spiegelt das Verhalten.【F:tests/compliance/worm_export_failure.rs†L1-L226】【F:.github/workflows/ci.yml†L378-L386】【F:.github/workflows/nightly.yml†L21-L31】

### 1.3 System- und Szenariotests
- **End-to-End**: Start eines lokalen Netzwerks (mindestens zwei Wallets + ein Node) mit VRF-basierter Leader-Selektion, Erzeugung von Blöcken und vollständiger Rekursionskette.
- **Migrationspfad**: Sicherstellen, dass `migration` alte Datensätze korrekt in das `ChainProof`-Format überführt und anschließend verifiziert wird.
- **Fuzzing/Property-Tests**: Einsatz von `proptest` für Witness-Parser und State-Höhen, um Grenzwerte aufzudecken. Ergänzend
  laufen `cargo fuzz`-Targets für P2P-Decoder, Wallet-RPC (`wallet_rpc`), das ZSI-Lifecycle-Handling (`zsi_lifecycle`) sowie den
  STWO/Plonky3-Beweisparser (`stwo_circuit_loader`). Lokal lassen sich die Läufe über `cargo fuzz run wallet_rpc` bzw.
  `cargo fuzz run zsi_lifecycle` im Wallet-Crate und `cargo fuzz run stwo_circuit_loader` unter `prover/fuzz` reproduzieren.
  Für den RPP-STARK-Backendpfad sind separate Fuzz-Builds hinterlegt; kurze Repros (32 Iterationen, 5 s Timeout) lassen sich mit
  `cargo fuzz run handle_meta --features backend-rpp-stark -- -runs=32 -timeout=5` aus `rpp/p2p` sowie
  `cargo fuzz run wallet_rpc --features backend-rpp-stark -- -runs=32 -timeout=5` aus `rpp/wallet` starten, um die STARK-
  spezifischen Decoderwege auf Build- und API-Regressionsfreiheit zu prüfen.
- **Simnet-Szenarien**: Das Simulations-Framework (`tools/simnet/`) bündelt `ci_block_pipeline.ron`, `ci_state_sync_guard.ron` und den Phase‑2-Stresslauf `consensus_quorum_stress.ron`. Die ersten beiden orchestrieren Integrationstests (Blockproduktion, Snapshot-/Light-Client-Sync, Manipulationsschutz); der dritte injiziert VRF-/Quorum-Manipulationen und misst Prover/Verifier-Latenzen inklusive CSV-/JSON-Summaries.【F:tools/simnet/scenarios/ci_block_pipeline.ron†L1-L16】【F:tools/simnet/scenarios/ci_state_sync_guard.ron†L1-L36】【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:tools/simnet/src/main.rs†L1-L86】

### 1.4 Feature-Matrix & Laufzeiten

Die GitHub-Actions-Matrix in `.github/workflows/ci.yml` und `nightly.yml` fährt vier Feature-Sets über `cargo xtask`: Standard (`default`), Produktionslauf (`--no-default-features --features prod,prover-stwo`), ein Plonky3-Build (`--features prod,prover-stwo,backend-plonky3`) sowie die wallet-spezifischen Varianten `wallet_gui` und `wallet_zsi,wallet_hw,wallet_multisig_hooks,wallet_rpc_mtls`. Der erste Cold-Start des Standard-Laufs benötigt in der Container-Umgebung rund 85 Sekunden bis alle Abhängigkeiten gebaut sind; ein erneuter Start verkürzt sich auf ~11 Sekunden, weil die Artefakte im Cargo-Target-Cache verbleiben.【F:.github/workflows/ci.yml†L635-L918】【F:.github/workflows/nightly.yml†L1-L86】【f3105d†L1-L5】【f3e57e†L1-L5】

Eine tabellarische Übersicht der unterstützten Storage-Hashing-Varianten (`branch_factor_256`, `ethhash`, `io-uring`) und zk-Backends samt der CI-Jobs, die sie abdecken, steht unter [`docs/development/testing_matrix.md`](development/testing_matrix.md) bereit.

| Feature-Set | Reproduktionsbefehl | Erwartete Dauer (Cold / Warm) |
| --- | --- | --- |
| `default` | `cargo xtask test-unit` / `test-integration` / `test-simnet` | ~85 s / ~11 s |
| `prod,prover-stwo` | `XTASK_NO_DEFAULT_FEATURES=1 XTASK_FEATURES="prod,prover-stwo" cargo xtask <command>` | ~90 s / ~15 s (wie Default, zusätzliche Proof-Binaries) |
| `prod,prover-stwo,backend-plonky3` | `XTASK_NO_DEFAULT_FEATURES=1 XTASK_FEATURES="prod,prover-stwo,backend-plonky3" cargo xtask <command>` | ~95 s / ~20 s (zusätzliche Plonky3-Module) |
| `wallet_gui` | `XTASK_FEATURES="wallet_gui" cargo xtask <command>` | ~88 s / ~13 s (GUI-Build, keine Proof-Änderung) |
| `wallet_zsi,wallet_hw,wallet_multisig_hooks,wallet_rpc_mtls` | `XTASK_FEATURES="wallet_zsi,wallet_hw,wallet_multisig_hooks,wallet_rpc_mtls" cargo xtask <command>` | ~92 s / ~16 s (zusätzliche Wallet-Security-Module) |

Die Feature-Flags werden von `xtask` automatisch übernommen und damit sowohl in CI als auch lokal konsistent ausgewertet.【F:xtask/src/main.rs†L1-L91】

## Phase 2 – Test Suites abgeschlossen

Die Phase‑2-Abnahme bestätigt, dass alle drei `cargo xtask`-Läufe automatisiert und reproduzierbar grün sind. Die Jobs sind in [`CI`](../.github/workflows/ci.yml) und [`nightly-simnet`](../.github/workflows/nightly.yml) dokumentiert und liefern geprüfte Artefakte.

- **`unit-suites`** startet `cargo xtask test-unit` über die Feature-Matrix `default`, `prod,prover-stwo`, `prod,prover-stwo,backend-plonky3`, `wallet_gui` sowie `wallet_zsi,wallet_hw,wallet_multisig_hooks,wallet_rpc_mtls`. Der kombinierte Lauf benötigt ~12 Minuten (Warm ~6 Minuten), archiviert deterministische Witness- und VRF-Ergebnisse für Auditor:innen und prüft die ZSI-Renewal-Regression explizit im Wallet-Sicherheits-Bundle. Jede Variante hängt ein redaktiertes Artefaktpaket (`unit-suites-<variant>`) via `scripts/ci/collect_test_artifacts.sh` an, damit Reviewer:innen die Logs herunterladen können, ohne dass Secrets im Klartext landen.【F:.github/workflows/ci.yml†L635-L700】【F:xtask/src/main.rs†L102-L157】【F:tests/zsi_renewal.rs†L1-L165】【F:scripts/ci/collect_test_artifacts.sh†L1-L55】
- **`integration-workflows`** führt `cargo xtask test-integration` für dieselbe Matrix aus. Die Matrix dauert ~18 Minuten (Warm ~9 Minuten), deckt Blockproduktion, Snapshot-/Light-Client-Sync sowie Manipulationsschutzfälle ab und lädt die redaktierten `integration-workflows-<variant>`-Artefakte hoch.【F:.github/workflows/ci.yml†L768-L830】【F:scripts/ci/collect_test_artifacts.sh†L1-L55】
- **`simnet-smoke`** betreibt `cargo xtask test-simnet` mit allen Simulationsszenarien für alle Feature-Sets. Der Lauf benötigt ~22 Minuten (Warm ~11 Minuten), legt JSON-/CSV-Summaries als Artefakte (`simnet-regression`) im Actions-Tab ab und ergänzt sanitised Log-Bundles (`simnet-smoke-<variant>`).【F:.github/workflows/ci.yml†L864-L918】【F:scripts/ci/collect_test_artifacts.sh†L1-L55】
- **Nightly `validation` & `simnet`** replizieren die Matrix täglich (`cargo xtask test-all`) und laden das Paket `simnet-nightly` hoch, das die vollständigen Summaries für Prüfzwecke enthält (~35 Minuten + ~15 Minuten).【F:.github/workflows/nightly.yml†L88-L124】【F:.github/workflows/nightly.yml†L148-L183】

Mit diesen Jobs gelten die Blueprint-Definition-of-Done-Kriterien für Unit-, Integrations- und Simulationsabdeckung als erfüllt.

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
| `tests-default` | Führt die Standard-Feature-Matrix über `scripts/test.sh` aus. | `./scripts/test.sh --backend default --unit --integration` |
| `tests-stwo` | Deckt den STWO-Backend-Lauf mit Nightly-Toolchain ab. | `./scripts/test.sh --backend stwo --unit --integration` |
| `tests-rpp-stark` | Validiert den RPP-STARK-Backendpfad samt Regressionen. | `./scripts/test.sh --backend rpp-stark --unit --integration` |
| `snapshot-cli` | Verifiziert die Snapshot-Backup-/Restore-Skripte und die CLI-Artefakte. | `cargo test --test storage_snapshot` |
| `observability-snapshot` | Prüft die Snapshot-/Timetoke-Metriken via Prometheus-Scrape und Dashboard-Snapshots. | `cargo xtask test-observability` |
| `simnet-admission` | Simuliert Gossip-Backpressure und Admission-Policies mit dem Simnet-Szenario `gossip-backpressure`. | `cargo run -p simnet -- --scenario tools/simnet/scenarios/gossip_backpressure.ron` |
| `rpc-admission-audit` | Prüft den Dual-Control-Guard der Admission-RPC und stellt sicher, dass beide Genehmigungen im Audit-Log landen. | `cargo test -p rpp-chain --locked --test admission` |
| `unit-suites` | Erzwingt die deterministischen STWO/Firewood/VRF-Unit-Suites. | `cargo xtask test-unit` |
| `integration-workflows` | Überprüft Blockproduktion, Snapshot-/Light-Client-Pläne und Operator-RPC-Lifecycle. | `cargo xtask test-integration` |
| `simnet-smoke` | Führt alle drei Simnet-Szenarien (`ci_block_pipeline`, `ci_state_sync_guard`, `consensus_quorum_stress`) aus und protokolliert Artefakte inkl. Tamper-Checks. | `cargo xtask test-simnet` |
| `runtime-smoke` | Startet Node-, Wallet- und Hybrid-Modus seriell via `scripts/run_*_mode.sh`, prüft `/health/*` sowie `/metrics` und lädt Logs/Metriken als Artefakte hoch. | `cargo build --bin rpp-node && ./scripts/run_node_mode.sh` / `run_wallet_mode.sh` / `run_hybrid_mode.sh` |

> **Hinweis:** `scripts/test.sh` setzt `RUSTFLAGS=-D warnings`, aktiviert automatisch das passende Feature-Set und wählt für STWO den gepinnten Nightly-Toolchain, damit lokale Läufe die CI-Ergebnisse widerspiegeln.【F:scripts/test.sh†L4-L8】【F:scripts/test.sh†L81-L210】

- **GitHub Actions Workflows**:
  - [`Release`](../.github/workflows/release.yml): Führt `./scripts/test.sh --all --backend default --backend stwo --backend rpp-stark --backend plonky3` aus und deckt damit die vollständige Produktionsmatrix inklusive Plonky3 ab.【F:.github/workflows/release.yml†L55-L120】
- [`CI`](../.github/workflows/ci.yml): Ergänzt `fmt`, `clippy` und die
    Backend-Matrix um die verpflichtenden Gates `snapshot-cli`, `observability-snapshot`,
    `simnet-admission`, `unit-suites`, `integration-workflows`, `simnet-smoke` sowie `runtime-smoke`.
    Die Stufen validieren die Snapshot-Backup-/Restore-Skripte (`cargo test --test storage_snapshot`),
    die Prometheus-basierten Observability-Scrapes (`cargo xtask test-observability`), das
    Admission-Szenario (`cargo run -p simnet -- --scenario tools/simnet/scenarios/gossip_backpressure.ron`)
    und die klassischen xtask-/Smoke-Läufe. `worm-export-smoke` führt zusätzlich den
    Compliance-Test `cargo test --test compliance --features integration -- worm_export_failure_emits_metric_and_log`
    gegen den Nur-Lese-Stub aus, bevor `runtime-smoke` `rpp-node` baut, die drei
    Betriebsmodi seriell, prüft die Health-/Metrics-Endpunkte und archiviert Logs/Metriken je Modus.
    Die Jobs delegieren an `cargo xtask test-unit`, `cargo xtask test-integration`, `cargo xtask test-simnet`
    und die `scripts/run_*_mode.sh`-Wrapper, womit alle Testebenen (Unit, Workflow, Simulation,
    Observability, Admission, WORM-Compliance, Runtime-Smoke) automatisiert abgedeckt werden und Contributors dieselben
    Läufe lokal reproduzieren können.【F:.github/workflows/ci.yml†L185-L452】【F:xtask/src/main.rs†L68-L107】【F:tests/storage_snapshot.rs†L1-L73】【F:tests/observability/snapshot_timetoke_metrics.rs†L1-L219】【F:tools/simnet/scenarios/gossip_backpressure.ron†L1-L16】
  - [`nightly-simnet`](../.github/workflows/nightly.yml): Startet täglich `cargo xtask test-simnet` mit dem Production-
    Feature-Set (`prod,prover-stwo,backend-plonky3`), wertet alle JSON-Summaries über `scripts/analyze_simnet.py` aus und
    lädt ein Tarball mit Logs, JSON- und CSV-Reports hoch. Abweichungen bei P2P-Latenzen oder akzeptierten VRF-/Quorum-
    Manipulationen führen zu einem roten Workflow-Status.
  - [`Nightly fuzzing`](../.github/workflows/nightly-fuzz.yml): Startet `cargo fuzz` für die P2P-Handler
    (`handle_meta`, `handle_blocks`, `handle_votes`, `admission_evaluate_publish`), die Wallet-RPC-Decoder (`wallet_rpc`,
    `zsi_lifecycle`) sowie den STWO/Plonky3-Beweisparser (`stwo_circuit_loader`) auf einem Nightly-Toolchain-Setup,
    archiviert die Corpora und schreibt minimierte Repro-Eingaben bei Fehlersignalen nach
    `ci-artifacts/fuzz-failures/<bereich>/<target>-minimized`.
    
### Reproducing fuzz regressions

1. Lade das Artefakt `nightly-fuzz-failures` aus dem fehlgeschlagenen Workflow und entpacke es im Repository-Stamm (`tar -xzf nightly-fuzz-failures.tar.gz`).
2. Wechsle ins passende Fuzzer-Verzeichnis (`rpp/p2p`, `rpp/wallet` oder `prover/fuzz`).
3. Starte den betroffenen Target mit dem minimierten Input und einem Run-Limit: z. B. `cargo fuzz run handle_meta ../ci-artifacts/fuzz-failures/p2p/handle_meta-minimized -runs=1` oder `cargo fuzz run wallet_rpc ../../ci-artifacts/fuzz-failures/wallet/wallet_rpc-minimized -runs=1`.
4. Optional kann derselbe Pfad als `-exact_artifact_path` genutzt werden, um angepasste Repro-Dateien direkt zu überschreiben (`cargo fuzz run ... -- -exact_artifact_path=../ci-artifacts/fuzz-failures/...`).
- **Manuelle Prüfpfade**:
  - `scripts/run_hybrid_mode.sh`, `scripts/run_node_mode.sh`, `scripts/run_wallet_mode.sh`: Lokale Smoke-Tests für Node- und
    Wallet-Modi. Die GitHub-Actions-Stufe `runtime-smoke` automatisiert diese Läufe, prüft die Health-Endpunkte (`/health/live`,
    `/health/ready`), sammelt Metriken (`/metrics`) und lädt Log-/Metrik-Artefakte (`artifacts/runtime-smoke/<mode>.*`) hoch. Zur
    Reproduktion lokal zuerst `cargo build --bin rpp-node` ausführen und anschließend die Modi seriell starten, z. B.:

    ```bash
    mkdir -p artifacts/runtime-smoke
    for mode in node wallet hybrid; do
      log="artifacts/runtime-smoke/${mode}.log"
      metrics="artifacts/runtime-smoke/${mode}.metrics"
      port=7070
      if [[ "${mode}" == "wallet" ]]; then
        port=9090
      fi
      timeout --signal=TERM 150 scripts/run_${mode}_mode.sh >"${log}" 2>&1 &
      pid=$!
      for suffix in live ready; do
        success=0
        for attempt in $(seq 1 150); do
          if curl --fail --silent "http://127.0.0.1:${port}/health/${suffix}" >/dev/null; then
            success=1
            break
          fi
          sleep 1
        done
        if [[ ${success} -ne 1 ]]; then
          echo "health check ${suffix} timed out for ${mode}" >&2
          exit 1
        fi
      done
      curl --fail --silent --show-error "http://127.0.0.1:${port}/metrics" >"${metrics}"
      kill -TERM "${pid}" && wait "${pid}"
    done
    ```
    Die CI-Stufe übernimmt diese Schritte vollautomatisch und bricht bei fehlerhaften Health- oder Metrik-Antworten mit einer
    aussagekräftigen Fehlermeldung ab.【F:.github/workflows/ci.yml†L185-L316】
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
