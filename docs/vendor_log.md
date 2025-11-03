# Vendor-Integrationsprotokoll

## Abhängigkeitsüberblick – Builder-, Trie- und Telemetrie-Crates (2025-03-19)

| Crate | Version | Firewood-Komponente(n) | Verwendung |
|-------|---------|-------------------------|------------|
| typed-builder | 0.22.0 | `firewood` (DB- und Revisionsmanager-Konfiguration) | Generiert Builder-APIs für `DbConfig`, `ConfigManager` und `RevisionManagerConfig`, die die Datenbank- und Revisionsverwaltung parametrisieren.【F:firewood/Cargo.toml†L36-L65】【F:firewood/src/db.rs†L20-L78】【F:firewood/src/manager.rs†L13-L118】
| hash-db | 0.16.0 | `firewood` (Ethhash-Kompatibilitätstests), `firewood-triehash` (Trie-Berechnungen) | Stellt das `Hasher`-Trait für die Ethereum-kompatiblen Trie-Implementierungen bereit, die in den Merkle-Tests sowie beim Berechnen von Trie-Wurzeln genutzt werden.【F:firewood/Cargo.toml†L60-L65】【F:triehash/Cargo.toml†L11-L25】【F:firewood/src/merkle/tests/ethhash.rs†L4-L179】【F:triehash/src/lib.rs†L26-L117】
| rlp | 0.6.1 (`firewood`, `firewood-storage`), 0.6 (`firewood-triehash`) | `firewood` (Tests), `firewood-storage` (Ethhash-Hasher), `firewood-triehash` (Trie-Serialisierung) | Serialisiert Trie-Knoten und Hash-Präbilder im Ethereum-Format; `firewood-storage` verwendet RLP beim Hashen von Trie-Knoten, während `firewood-triehash` RLP-Streams für die Wurzelberechnung aufbaut.【F:firewood/Cargo.toml†L60-L65】【F:storage/Cargo.toml†L34-L64】【F:triehash/Cargo.toml†L11-L25】【F:storage/src/hashers/ethhash.rs†L14-L120】【F:triehash/src/lib.rs†L26-L117】
| opentelemetry | =0.30.0 | `firewood-benchmark` | Bindet Telemetrie-Scope und Spans in das Benchmark-Binärprogramm ein, um Laufzeitdaten an einen OTLP-Collector zu exportieren.【F:benchmark/Cargo.toml†L23-L63】【F:benchmark/src/main.rs†L15-L160】
| opentelemetry-otlp | =0.30.0 | `firewood-benchmark` | Liefert den OTLP-Span-Exporter inklusive gRPC-/Timeout-Konfiguration für das Telemetrie-Reporting des Benchmarks.【F:benchmark/Cargo.toml†L23-L63】【F:benchmark/src/main.rs†L15-L160】
| opentelemetry-proto | =0.30.0 | `firewood-benchmark` | Bringt die Protobuf-Typen für den OTLP-Exporter mit und wird gemeinsam mit `opentelemetry-otlp` geladen.【F:benchmark/Cargo.toml†L23-L63】
| opentelemetry_sdk | =0.30.0 | `firewood-benchmark` | Konfiguriert den Telemetrie-Resource-Kontext, der mit den exportierten Spans verschickt wird.【F:benchmark/Cargo.toml†L23-L63】【F:benchmark/src/main.rs†L15-L160】
| askama | 0.14.0 | `firewood-fwdctl` | Rendert den Textbericht `DBStatsReport`, der nach einem Konsistenz-Check ausgegeben wird.【F:fwdctl/Cargo.toml†L30-L52】【F:fwdctl/src/check.rs†L4-L160】

Folgeschritte:

* Nächste PRs sollen die oben genannten Crates in `vendor/` spiegeln und anschließend die `[patch]`-Einträge in `cargo/config.toml` ergänzen, damit Offline-Builds die lokalen Quellen referenzieren.

## Geplanter Backend-Vendor – STWO (2025-10-21)

* Mehr-PR-Prozess: STWO-Integration wird über mehrere PRs mit einem Diff-Limit von ca. 25 000 geänderten Zeilen gestaffelt.
* Toolchain-Vorgabe: Das vendorte Backend benötigt die Nightly-Toolchain `nightly-2025-07-14` laut `prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/rust-toolchain.toml`.
* Toolchain-Übersicht:
  * Pinned Nightly bleibt Pflicht für Workspace-Operationen im STWO-Baum wie `cargo +nightly-2025-07-14 test -p prover-stwo`, `cargo +nightly-2025-07-14 check --offline -p prover-stwo(-simd)` oder `scripts/test.sh --backend stwo`, weil Upstream-Funktionen (`#![feature(...)]`) weiterhin nötig sind.
  * Das Release-Verfahren setzt dagegen auf die Stable-Toolchain: `.github/workflows/release.yml` installiert `stable` und ruft `./scripts/build_release.sh` auf, das die gleichen Flags lokal erzwingt.
* Quellenreferenz: Ausgangspunkt ist das Archiv `prover/prover_stwo_backend/stwo-dev.zip`, welches den Workspace 0.1.1 inklusive aller Mitglieder bereitstellt.
* Runtime-Gating: Validator- und Hybrid-Läufe brechen nun sofort mit einem Hinweis auf das fehlende Feature ab, wenn der Build ohne `--features prod,prover-stwo` (oder `prover-stwo-simd`) erfolgt. Produktions-Builds sollten daher `./scripts/build_release.sh --target <triple>` verwenden; das Skript erzwingt `--locked --package rpp-node --bins --profile release --no-default-features --features prod,prover-stwo` und verweigert `prover-mock`.
* Verifikation vor Deployments: Nach dem Build `cargo +nightly-2025-07-14 run -p rpp-node --bin validator --no-default-features --features prod,prover-stwo -- --dry-run` ausführen. Der Lauf muss ohne den neuen Fehler „requires the `prover-stwo` feature“ zurückkehren, andernfalls ist das Backend nicht aktiv.

#### Import – constraint-framework-Staging (2025-10-17)

* `prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/constraint-framework/` enthält nun die vollständigen Quellen (u. a. `expr/`, `prover/`, `info.rs`, `logup.rs`) aus dem Workspace-Archiv.
* `scripts/vendor_stwo/update_manifest.py` aktualisiert `manifest/chunks.json`, die Prüfsummenliste `manifest/final_file_list.txt` sowie das Log `logs/update_manifest.log` für den neuen Staging-Bestand.
* Prover-Module, die auf dem Framework aufsetzen: die Komponenten-Implementierungen in `crates/examples/src/blake/`, `crates/examples/src/poseidon/` und `crates/examples/src/wide_fibonacci/` nutzen `FrameworkComponent`, LogUp-Generatoren und Relation-Tracker aus dem Framework zur Zeugen-Erzeugung.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/crates/examples/src/blake/mod.rs†L14-L156】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/crates/examples/src/poseidon/mod.rs†L25-L351】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/crates/examples/src/wide_fibonacci/mod.rs†L11-L246】

#### Import – core (Felder, Kanal, Proof) (2025-10-17)

* `prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/lib.rs` sowie der Kernbaum (`core/`) wurden für Felddarstellungen (`fields/`), Fiat-Shamir-Kanäle (`channel/`), Kompositionsrestriktionen und Hilfsstrukturen (`constraints.rs`, `fraction.rs`, `utils.rs`, `test_utils.rs`) und die Proof-Erzeugung (`proof.rs`, `proof_of_work.rs`, `verifier.rs`, `queries.rs`) übernommen.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/lib.rs†L1-L108】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/fields/mod.rs†L1-L302】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/channel/mod.rs†L1-L134】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/proof.rs†L1-L219】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/verifier.rs†L1-L131】
* Die begleitenden Benchmarks (`crates/stwo/benches/`) stehen nun zur Verfügung, inklusive README und Messszenarien für Feldarithmetik, FFTs und Merkle-Bäume, sodass lokale Performance-Baselines erstellt werden können.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/README.md†L1-L44】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/field.rs†L1-L125】
* Manifest-Checksumme und Log wurden über `scripts/vendor_stwo/update_manifest.py --source-dir prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging ...` neu erzeugt; die aktualisierte Prüfliste spiegelt alle importierten Dateien wider.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/final_file_list.txt†L1-L60】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/logs/update_manifest.log†L1-L9】
* Nächste Schritte: Die verbleibenden `core`-Teilbäume (`pcs/`, `poly/` inkl. `poly/circle/`, sowie `vcs/`) werden in einem Folge-PR nachgezogen; ohne sie bleiben Referenzen in `verifier.rs` und `constraints.rs` auf unverfügbare Module bestehen.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/verifier.rs†L5-L26】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/constraints.rs†L4-L8】

#### Import – core (FFT, PCS, Poly, VCS) (2025-10-17)

* Der verbleibende Kernbaum wurde komplettiert: FFT-Routinen (`core/fft.rs`), Kreis- und Linienpolynome (`core/poly/` inkl. `poly/circle/`), das Polynomial-Commitment (`core/pcs/`) sowie die Merkle-VCS-Varianten (`core/vcs/`) stehen nun in der Staging-Kopie zur Verfügung.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/fft.rs†L1-L94】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/poly/line.rs†L1-L228】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/pcs/mod.rs†L1-L113】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/vcs/mod.rs†L1-L14】
* Die zugehörigen AIR-Komponenten (`core/air/accumulation.rs`, `core/air/components.rs`) und Kreis-Geometrien (`core/circle.rs`) wurden aus dem Archiv gespiegelt, sodass alle Referenzen aus `constraints.rs` und `verifier.rs` nun auf vorhandene Implementierungen zeigen.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/air/accumulation.rs†L1-L120】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/air/components.rs†L1-L120】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/circle.rs†L1-L248】
* `scripts/vendor_stwo/update_manifest.py` wurde erneut ausgeführt; `manifest/chunks.json`, die Prüfsummenliste `manifest/final_file_list.txt` sowie das Log `logs/update_manifest.log` enthalten die neuen Stände und dokumentieren den Abschluss des `core`-Baums.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/chunks.json†L1-L6】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/final_file_list.txt†L1-L77】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/logs/update_manifest.log†L10-L18】
* Damit ist der `core`-Teil des STWO-Workspaces vollständig vendort; Folgearbeiten können sich auf höhere Protokollschichten konzentrieren.

#### Import – prover & tracing (2025-10-17)

* Die STWO-Prover-Schichten (`prover/air/`, `channel/`, `lookups/`, `pcs/`, `poly/`, `vcs/` sowie `fri.rs`, `line.rs`, `secure_column.rs`) und das begleitende Tracing-Modul wurden aus dem Archiv in die Staging-Kopie übernommen; alle Referenzen aus `mod.rs` verweisen nun auf vorhandene Dateien.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/mod.rs†L1-L40】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/air/mod.rs†L1-L152】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/tracing/mod.rs†L1-L76】
* Die vorhandenen Criterion-Benchmarks (`fri.rs`, `lookups.rs`, `pcs.rs`, `quotients.rs`) decken die neuen Module bereits ab und dienen weiterhin als Performance-Baseline für FRI-Faltung, Lookup-Argumente und Quotienten-Auswertung.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/fri.rs†L1-L38】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/lookups.rs†L1-L34】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/pcs.rs†L1-L34】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/quotients.rs†L1-L36】
* Manifest und Log wurden erneut via `scripts/vendor_stwo/update_manifest.py` erzeugt; die aktualisierte Prüfliste enthält nun sämtliche `prover/`- und `tracing/`-Dateien, während das Log den Lauf dokumentiert.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/final_file_list.txt†L1-L120】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/chunks.json†L1-L6】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/logs/update_manifest.log†L1-L12】
* Das SIMD-Backend ist nun komplett vendort: `prover/backend/simd/fft/` (IFFT/RFFT) und `prover/backend/simd/lookups/` (GKR/MLE) wurden aus dem Archiv übernommen, sodass alle Exporte aus `simd/mod.rs` auf vorhandene Implementierungen zeigen.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/backend/simd/fft/mod.rs†L1-L128】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/backend/simd/lookups/mod.rs†L1-L18】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/backend/mod.rs†L11-L24】
* `scripts/vendor_stwo/update_manifest.py` wurde erneut ausgeführt; die Prüfsummenliste enthält nun die neuen SIMD-Dateien und das Manifest-Log dokumentiert den Abschluss des SIMD-Vendorings.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/final_file_list.txt†L2-L21】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/logs/update_manifest.log†L10-L12】

#### Import – prover backend (CPU) (2025-10-17)

* Der Backend-Stamm wurde um das CPU-Backend ergänzt: `mod.rs`, `secure_column.rs` sowie `cpu/` (inkl. `accumulation.rs`, `blake2s.rs`, `circle.rs`, `fri.rs`, `grind.rs`, `lookups/`, `poseidon252.rs`, `quotients.rs`) sind nun in der Staging-Kopie vorhanden.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/backend/mod.rs†L1-L52】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/backend/secure_column.rs†L1-L120】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/backend/cpu/mod.rs†L1-L79】
* Hinweis (Update 2025-10-17T12:07Z): Der damals noch fehlende SIMD-Zweig wurde inzwischen vollständig vendort; siehe obenstehenden Eintrag zum SIMD-Backend für Details.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/backend/simd/fft/mod.rs†L1-L128】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/backend/simd/lookups/mod.rs†L1-L18】
* `scripts/vendor_stwo/update_manifest.py` wurde erneut ausgeführt, wodurch `manifest/final_file_list.txt` um die neuen Backend-Dateien ergänzt und das Update-Log erweitert wurde.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/final_file_list.txt†L1-L120】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/logs/update_manifest.log†L1-L13】

#### Offline-Build-Validierung – prover-stwo & prover-stwo-simd (2025-10-21)

* Erfolgreiche Läufe von `cargo +nightly-2025-07-14 check --offline -p prover-stwo` und `cargo +nightly-2025-07-14 check --offline -p prover-stwo-simd` verifizieren die Integration auf der vendorten Toolchain.
* Die Logausgaben sind unter `prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/logs/cargo_check_prover-stwo.log` bzw. `prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/logs/cargo_check_prover-stwo-simd.log` abgelegt und dokumentieren die Nightly-Toolchain `nightly-2025-07-14` entsprechend der bestehenden Toolchain-Vorgabe.

#### Abschluss – Manifest & Integritätsberichte (2025-10-17)

* Der Abschlusslauf von `scripts/vendor_stwo/update_manifest.py` (2025-10-17T14:11Z) bestätigt den finalen Staging-Bestand; `manifest/chunks.json` bleibt leer, `manifest/final_file_list.txt` erfasst alle 212 Dateien, und das Update-Log dokumentiert die aktuellen Warn-/Info-Einträge.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/chunks.json†L1-L5】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/final_file_list.txt†L1-L212】【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/logs/update_manifest.log†L34-L42】
* `scripts/vendor_stwo/verify_extracted_files.py` bestätigt erneut eine fehlerfreie Übereinstimmung; der konsolidierte Bericht `manifest/integrity_report.json` hält den `pass`-Status sowie die aktualisierten Zählwerte fest.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/integrity_report.json†L1-L15】
* Ergänzend fasst `manifest/integrity_summary.json` die aktualisierten Prüfsummen (u. a. `Cargo.toml`, `src/lib.rs`, Update-Log) zusammen und dokumentiert die vollständige Dateiabdeckung des Staging-Baums.【F:prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/integrity_summary.json†L1-L52】

### Initiale Artefaktplanung (2025-10-17)

* Segmentierung: `prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/manifest/chunk_plan.json` beschreibt neun Zielsegmente (pro Workspace-Ordner ein Eintrag) und hält die Segmentgrenze bei 50 MiB. Grundlage ist das entpackte Archiv `prover/prover_stwo_backend/stwo-dev.zip`; alle Crate-Verzeichnisse bleiben deutlich unterhalb der Grenze.
* Manifest-Initialisierung: Ein Lauf von `scripts/vendor_stwo/update_manifest.py` gegen den leeren Zielbaum erzeugte ein leeres `manifest/chunks.json` sowie eine leere `manifest/final_file_list.txt` zur Vorbereitung der Folgeimporte.
* Log-Ablage: Das Manifest-Log liegt unter `prover/prover_stwo_backend/vendor/stwo-dev/0.1.1/logs/update_manifest.log` und dokumentiert den Initiallauf ohne erkannte Segmente.

## Batch 1 – Fundamentale Utility-Crates (2025-09-23)

| Crate | Version(en) | Zielverzeichnis | Notizen |
|-------|-------------|-----------------|---------|
| anyhow | 1.0.100 | `vendor/anyhow/1.0.100/` | Archiv `anyhow-master-1.zip` entpackt; enthält Tests und Build-Skripte. |
| thiserror | 1.0.69, 2.0.16 | `vendor/thiserror/<version>/` | Crates als `.crate`-Archive von crates.io geladen; beide Major-Versionen für Abhängigkeiten bereitgestellt. |
| thiserror-impl | 1.0.69, 2.0.16 | `vendor/thiserror-impl/<version>/` | Zugehörige Proc-Macro-Crates separat abgelegt. |
| serde | 1.0.225 | `vendor/serde/1.0.225/` | Offizielles crates.io-Archiv genutzt. |
| serde_core | 1.0.225 | `vendor/serde_core/1.0.225/` | Bestandteil des Serde-Workspaces, für Lockfile-Auflösung erforderlich. |
| serde_derive | 1.0.225 | `vendor/serde_derive/1.0.225/` | Proc-Macro-Crate inklusive Build-Skripten integriert. |
| serde_json | 1.0.145 | `vendor/serde_json/1.0.145/` | Archiv `json-master-1.zip` verifiziert, Version bestätigt. |

Weitere Schritte:

* `.cargo/config.toml` vorbereiten, um die neuen Vendor-Pfade als `source` oder via `[patch.crates-io]` einzubinden.
* Nachziehen transitiver Abhängigkeiten (`itoa`, `ryu`, `memchr` etc.) im nächsten Batch.
* Nach erfolgreicher Einbindung `cargo check` ausführen, sobald alle benötigten Crates lokal verfügbar sind.

## Batch 2 – Async-Web-Stack (2025-09-24)

| Crate | Version(en) | Zielverzeichnis | Notizen |
|-------|-------------|-----------------|---------|
| axum | 0.8.4 | `vendor/axum/0.8.4/` | Archiv `axum-main-1.zip` entpackt; Workspace umfasst `axum-core` und `axum-macros` für Pfadabhängigkeiten. |

## Batch 3 – Numerische Utilities (2025-09-25)

| Crate | Version(en) | Zielverzeichnis | Notizen |
|-------|-------------|-----------------|---------|
| malachite | 0.4.18 | `vendor/malachite/0.4.18/src/` | Komplettes Git-Checkout als Quelle genutzt; Workspace benötigt Pfad auf das `src`-Unterverzeichnis. |

### Offline-Validierung (2025-10-14)

* Temporäre Auskommentierungen in `cargo/config.toml` entfernt; sämtliche `malachite*`-Pfade sind nun aktiv eingebunden.
* Abschluss-Checks (`cargo metadata --offline`, `cargo check --offline -p rpp-chain -p rpp-node -p rpp-sim`) durchgeführt und unter `logs/vendor_cargo_metadata_20250214.log` bzw. `logs/vendor_cargo_check_20250214.log` abgelegt (50 k Upload-Limit weiterhin beachten – Logs bei Bedarf lokal inspizieren).
* `cargo check` bricht aktuell in `malachite-base` wegen des stabil noch nicht verfügbaren `char::MIN`-APIs ab; Fehlerdetails sind im Log dokumentiert und dienen als Ausgangspunkt für den nächsten Fix.

## Strategie-Update – Mehrstufige Vendor-Planung (2025-10-14)

* Diff-Limit pro PR: ca. 2 000 geänderte Zeilen, damit Code-Reviews handhabbar bleiben.

## Plonky3 Backend Dependencies (2026-02-18)

* Toolchain: Der Prover-Workspace nutzt weiterhin `nightly-2025-07-14` gemäß `prover/rust-toolchain.toml`; Builds auf Stable (`1.79`) bleiben auf den Node-/Workspace-Teilen beschränkt.【F:prover/rust-toolchain.toml†L1-L5】【F:prover/Cargo.toml†L1-L8】
* CPU-Pfad: Alle `p3-*`-Kerne stammen von crates.io in Version `0.3.0`, ergänzt um das git-Pin `p3-multilinear-util@80803612ff4b`, sodass die Plonky3-Primitiven reproduzierbar gelockt sind.【F:docs/third_party/plonky3_deps.json†L30-L217】
* GPU-Option: Aktiviert durch `plonky3-gpu` beziehen wir `gpu-alloc@0.6.0` und `gpu-descriptor@0.3.2` aus crates.io; der Repository-Helper `GpuResources` hält die Initialisierung minimal.【F:docs/third_party/plonky3_gpu_deps.json†L21-L37】【F:prover/plonky3_backend/src/gpu.rs†L1-L37】
* Lizenz- und Pin-Nachweise sind in `docs/third_party/plonky3_deps.json` und `docs/third_party/plonky3_gpu_deps.json` abgelegt, sodass Offline-Prüfungen ohne erneuten crates.io-Abruf möglich sind.【F:docs/third_party/plonky3_deps.json†L1-L307】【F:docs/third_party/plonky3_gpu_deps.json†L1-L325】
* Segmentgröße: höchstens drei Crates pro Batch, um innerhalb des Diff-Limits zu bleiben.
* Folgeaufgaben: Umsetzung der noch offenen Vendor-Schritte gemäß Abschnitt „Folgeaktionen“ im Abhängigkeits-Kompatibilitätsbericht.

## Aktualisierung – Malachite-Workspace (2025-10-17)

* Alle Teilcrates (`malachite`, `malachite-base`, `malachite-float`, `malachite-nz`, `malachite-q`) erhielten frische Segment-Manifestdateien über `scripts/vendor_malachite/update_manifest.py`. Die neuen `chunks.json`-Stände verweisen auf geprüfte `.part000`-Segmente mit aktualisierten Zeitstempeln.
* Die Datei-Manifestlisten (`manifest/final_file_list.txt`) wurden für sämtliche Crates neu berechnet; die Einträge enthalten SHA-256, Byte-Länge und Relativpfad und schließen die Log- und Manifestartefakte ein.
* Für jede Quelle liegt nun ein `manifest/reference_hashes.json` mit aktuellen Prüfsummen des `src/`-Baums vor, sodass die Integritätsprüfung ohne erneuten Download referenziert werden kann.
* `scripts/vendor_malachite/verify_extracted_files.py --package <crate> --version 0.4.18` meldet für alle genannten Crates `pass`; die entsprechenden Artefakte (`manifest/integrity_report.json`, `logs/integrity_report.txt`) wurden aktualisiert.

### Refresh – Malachite 0.4.18 (2025-10-21)

* `scripts/vendor_malachite/test_segments.sh` lief erneut mit `MALACHITE_KEEP_CHUNKS=1` und holte sämtliche `.part000`-Segmente nach; die aktualisierten `chunks.json`-Dateien dokumentieren nun indexierte Chunks samt Prüfsummen und Zeitstempeln für jeden Teilcrate.【F:vendor/malachite/0.4.18/manifest/chunks.json†L1-L16】【F:vendor/malachite-base/0.4.18/manifest/chunks.json†L1-L16】【F:vendor/malachite-nz/0.4.18/manifest/chunks.json†L1-L16】【F:vendor/malachite-q/0.4.18/manifest/chunks.json†L1-L16】【F:vendor/malachite-float/0.4.18/manifest/chunks.json†L1-L16】
* Die Datei- und Referenzmanifeste wurden synchron neu erzeugt: `manifest/final_file_list.txt` listet nun auch die rekonstruierten `.crate`-Archive sowie alle Segment-Chunks, und `manifest/reference_hashes.json` enthält frische SHA-256-Tabellen des `src/`-Baums pro Crate.【F:vendor/malachite/0.4.18/manifest/final_file_list.txt†L1-L20】【F:vendor/malachite-base/0.4.18/manifest/final_file_list.txt†L1-L20】【F:vendor/malachite-nz/0.4.18/manifest/final_file_list.txt†L1-L20】【F:vendor/malachite-q/0.4.18/manifest/final_file_list.txt†L1-L20】【F:vendor/malachite-float/0.4.18/manifest/reference_hashes.json†L1-L11】
* `malachite-base` kompiliert wieder auf Stable: sämtliche Verwendungen von `char::MIN` wurden durch den expliziten Literal `"\u{0}"` ersetzt, und die Begleittests prüfen nun den erwarteten Startpunkt des ASCII-Spektrums.【F:vendor/malachite-base/0.4.18/src/chars/random.rs†L74-L116】【F:vendor/malachite-base/0.4.18/src/chars/exhaustive.rs†L29-L41】【F:vendor/malachite-base/0.4.18/src/test_util/generators/random.rs†L112-L117】【F:vendor/malachite-base/0.4.18/tests/chars/constants.rs†L1-L19】
* Die Integritätsberichte wurden aktualisiert und attestieren eine vollständige Übereinstimmung zwischen Referenz- und Vendor-Baum (`Overall result: PASS` für alle Crates).【F:vendor/malachite/0.4.18/logs/integrity_report.txt†L1-L9】【F:vendor/malachite-base/0.4.18/logs/integrity_report.txt†L1-L9】【F:vendor/malachite-nz/0.4.18/logs/integrity_report.txt†L1-L9】【F:vendor/malachite-q/0.4.18/logs/integrity_report.txt†L1-L9】【F:vendor/malachite-float/0.4.18/logs/integrity_report.txt†L1-L9】
* Offline-Checks bleiben wegen doppelter `libp2p-ping`-Pakete blockiert; die Fehlermeldungen sind zwecks Nachvollziehbarkeit unter `logs/cargo_metadata_offline.log` und `logs/cargo_check_offline.log` archiviert.【F:logs/cargo_metadata_offline.log†L1-L4】【F:logs/cargo_check_offline.log†L1-L4】

## Integritätsüberblick – Malachite-Workspace (2025-10-16)

* Konsolidierter Sammelbericht: `vendor/malachite/0.4.18/manifest/integrity_summary.json` fasst Kern-Prüfsummen (u. a. `Cargo.toml`, `Cargo.lock`, `README.md`) sowie den Status aller Segmentdateien der Subkrates zusammen.
* Die Übersicht deckt `malachite`, `malachite-base`, `malachite-float`, `malachite-nz` und `malachite-q` ab und ergänzt fehlende Integritätsberichte mit Platzhaltern zur schnellen Nachverfolgung.

### Archivierte Logauszüge (Update-Manifest)

```text
[malachite]      [2025-10-14T20:09:17Z] Segment malachite-0.4.18.part000 verified (sha256=4a6ecab92657eb234bfe98abd0b17920772c6b14ce69256950142e2eb36d000b)
[malachite-base] [2025-10-15T10:31:10Z] Segment malachite-0.4.18.part000 is missing on disk (length=822554)
[malachite-float][2025-10-16T13:55:22Z] Segment malachite-float-0.4.18.part000 is missing on disk (length=623265)
[malachite-nz]   [2025-10-16T09:27:03Z] Segment malachite-nz-0.4.18.part000 is missing on disk (length=2426976)
[malachite-q]    [2025-10-16T09:42:08Z] Segment malachite-q-0.4.18.part000 omitted; binary chunks stored externally
```

## Segment-Testlauf – Malachite 0.4.18 (2025-10-16)

Das neue Sammelskript [`scripts/vendor_malachite/test_segments.sh`](../scripts/vendor_malachite/test_segments.sh) lädt fehlende Segmente nach, fügt sie zu `.crate`-Archiven zusammen und verifiziert die entpackten Quellen. Ein kompletter Lauf ergab folgende Protokolle:

| Crate | Download-Log | Merge-Log | Verifikation |
|-------|--------------|-----------|--------------|
| malachite | `vendor/malachite/0.4.18/logs/download_segments_malachite_0_4_18.log` | `vendor/malachite/0.4.18/logs/merge_segments_malachite_0_4_18.log` | ✅ (`integrity_report.txt`) |
| malachite-base | `vendor/malachite-base/0.4.18/logs/download_segments_malachite_base_0_4_18.log` | `vendor/malachite-base/0.4.18/logs/merge_segments_malachite_base_0_4_18.log` | ❌ – fehlende Dateien im Workspace (`integrity_report.txt`) |
| malachite-nz | `vendor/malachite-nz/0.4.18/logs/download_segments_malachite_nz_0_4_18.log` | `vendor/malachite-nz/0.4.18/logs/merge_segments_malachite_nz_0_4_18.log` | ❌ – fehlende Dateien im Workspace (`integrity_report.txt`) |
| malachite-q | `vendor/malachite-q/0.4.18/logs/download_segments_malachite_q_0_4_18.log` | `vendor/malachite-q/0.4.18/logs/merge_segments_malachite_q_0_4_18.log` | ❌ – fehlende Dateien im Workspace (`integrity_report.txt`) |
| malachite-float | `vendor/malachite-float/0.4.18/logs/download_segments_malachite_float_0_4_18.log` | `vendor/malachite-float/0.4.18/logs/merge_segments_malachite_float_0_4_18.log` | ❌ – fehlende Dateien im Workspace (`integrity_report.txt`) |

Hinweis: Die negativen Verifikationsresultate spiegeln den aktuellen Importstand wider – große Teile der Subkrates fehlen im Vendor-Baum noch. Die Segmente und `.crate`-Archive wurden erfolgreich erstellt und können für weitere Diff-PRs wiederverwendet werden.

Zur Vermeidung von Binärdateien im Repository entfernt das Sammelskript die
heruntergeladenen `.part*`-Segmente sowie die rekonstruierten `.crate`-Archive
nach jeder Ausführung automatisch. Wer die Artefakte lokal behalten möchte,
setzt `MALACHITE_KEEP_CHUNKS=1` vor dem Start.

Zur Einhaltung der Upload-Grenzen enthalten die neuen `integrity_report.txt`-Dateien je Status maximal 50 Beispielpfade; ausführliche Stichproben und Zählwerte können den kompakten JSON-Berichten unter `vendor/<crate>/0.4.18/manifest/integrity_report.json` entnommen werden.
