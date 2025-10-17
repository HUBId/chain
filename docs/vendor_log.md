# Vendor-Integrationsprotokoll

## Geplanter Backend-Vendor – STWO (2025-10-21)

* Mehr-PR-Prozess: STWO-Integration wird über mehrere PRs mit einem Diff-Limit von ca. 25 000 geänderten Zeilen gestaffelt.
* Toolchain-Vorgabe: Das vendorte Backend benötigt die Nightly-Toolchain `nightly-2025-07-14` laut `vendor/stwo-dev/rust-toolchain.toml`.
* Quellenreferenz: Ausgangspunkt ist das Archiv `rpp/zk/prover_stwo_backend/stwo-dev.zip`, welches den Workspace 0.1.1 inklusive aller Mitglieder bereitstellt.

#### Import – constraint-framework-Staging (2025-10-17)

* `vendor/stwo-dev/0.1.1/staging/crates/constraint-framework/` enthält nun die vollständigen Quellen (u. a. `expr/`, `prover/`, `info.rs`, `logup.rs`) aus dem Workspace-Archiv.
* `scripts/vendor_stwo/update_manifest.py` aktualisiert `manifest/chunks.json`, die Prüfsummenliste `manifest/final_file_list.txt` sowie das Log `logs/update_manifest.log` für den neuen Staging-Bestand.
* Prover-Module, die auf dem Framework aufsetzen: die Komponenten-Implementierungen in `crates/examples/src/blake/`, `crates/examples/src/poseidon/` und `crates/examples/src/wide_fibonacci/` nutzen `FrameworkComponent`, LogUp-Generatoren und Relation-Tracker aus dem Framework zur Zeugen-Erzeugung.【F:rpp/zk/prover_stwo_backend/vendor/stwo-dev/0.1.1/crates/examples/src/blake/mod.rs†L14-L156】【F:rpp/zk/prover_stwo_backend/vendor/stwo-dev/0.1.1/crates/examples/src/poseidon/mod.rs†L25-L351】【F:rpp/zk/prover_stwo_backend/vendor/stwo-dev/0.1.1/crates/examples/src/wide_fibonacci/mod.rs†L11-L246】

#### Import – core (Felder, Kanal, Proof) (2025-10-17)

* `vendor/stwo-dev/0.1.1/staging/crates/stwo/src/lib.rs` sowie der Kernbaum (`core/`) wurden für Felddarstellungen (`fields/`), Fiat-Shamir-Kanäle (`channel/`), Kompositionsrestriktionen und Hilfsstrukturen (`constraints.rs`, `fraction.rs`, `utils.rs`, `test_utils.rs`) und die Proof-Erzeugung (`proof.rs`, `proof_of_work.rs`, `verifier.rs`, `queries.rs`) übernommen.【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/lib.rs†L1-L108】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/fields/mod.rs†L1-L302】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/channel/mod.rs†L1-L134】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/proof.rs†L1-L219】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/verifier.rs†L1-L131】
* Die begleitenden Benchmarks (`crates/stwo/benches/`) stehen nun zur Verfügung, inklusive README und Messszenarien für Feldarithmetik, FFTs und Merkle-Bäume, sodass lokale Performance-Baselines erstellt werden können.【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/README.md†L1-L44】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/field.rs†L1-L125】
* Manifest-Checksumme und Log wurden über `scripts/vendor_stwo/update_manifest.py --source-dir vendor/stwo-dev/0.1.1/staging ...` neu erzeugt; die aktualisierte Prüfliste spiegelt alle importierten Dateien wider.【F:vendor/stwo-dev/0.1.1/manifest/final_file_list.txt†L1-L60】【F:vendor/stwo-dev/0.1.1/logs/update_manifest.log†L1-L9】
* Nächste Schritte: Die verbleibenden `core`-Teilbäume (`pcs/`, `poly/` inkl. `poly/circle/`, sowie `vcs/`) werden in einem Folge-PR nachgezogen; ohne sie bleiben Referenzen in `verifier.rs` und `constraints.rs` auf unverfügbare Module bestehen.【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/verifier.rs†L5-L26】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/constraints.rs†L4-L8】

#### Import – core (FFT, PCS, Poly, VCS) (2025-10-17)

* Der verbleibende Kernbaum wurde komplettiert: FFT-Routinen (`core/fft.rs`), Kreis- und Linienpolynome (`core/poly/` inkl. `poly/circle/`), das Polynomial-Commitment (`core/pcs/`) sowie die Merkle-VCS-Varianten (`core/vcs/`) stehen nun in der Staging-Kopie zur Verfügung.【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/fft.rs†L1-L94】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/poly/line.rs†L1-L228】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/pcs/mod.rs†L1-L113】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/vcs/mod.rs†L1-L14】
* Die zugehörigen AIR-Komponenten (`core/air/accumulation.rs`, `core/air/components.rs`) und Kreis-Geometrien (`core/circle.rs`) wurden aus dem Archiv gespiegelt, sodass alle Referenzen aus `constraints.rs` und `verifier.rs` nun auf vorhandene Implementierungen zeigen.【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/air/accumulation.rs†L1-L120】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/air/components.rs†L1-L120】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/core/circle.rs†L1-L248】
* `scripts/vendor_stwo/update_manifest.py` wurde erneut ausgeführt; `manifest/chunks.json`, die Prüfsummenliste `manifest/final_file_list.txt` sowie das Log `logs/update_manifest.log` enthalten die neuen Stände und dokumentieren den Abschluss des `core`-Baums.【F:vendor/stwo-dev/0.1.1/manifest/chunks.json†L1-L6】【F:vendor/stwo-dev/0.1.1/manifest/final_file_list.txt†L1-L77】【F:vendor/stwo-dev/0.1.1/logs/update_manifest.log†L10-L18】
* Damit ist der `core`-Teil des STWO-Workspaces vollständig vendort; Folgearbeiten können sich auf höhere Protokollschichten konzentrieren.

#### Import – prover & tracing (2025-10-17)

* Die STWO-Prover-Schichten (`prover/air/`, `channel/`, `lookups/`, `pcs/`, `poly/`, `vcs/` sowie `fri.rs`, `line.rs`, `secure_column.rs`) und das begleitende Tracing-Modul wurden aus dem Archiv in die Staging-Kopie übernommen; alle Referenzen aus `mod.rs` verweisen nun auf vorhandene Dateien.【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/mod.rs†L1-L40】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/air/mod.rs†L1-L152】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/tracing/mod.rs†L1-L76】
* Die vorhandenen Criterion-Benchmarks (`fri.rs`, `lookups.rs`, `pcs.rs`, `quotients.rs`) decken die neuen Module bereits ab und dienen weiterhin als Performance-Baseline für FRI-Faltung, Lookup-Argumente und Quotienten-Auswertung.【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/fri.rs†L1-L38】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/lookups.rs†L1-L34】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/pcs.rs†L1-L34】【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/benches/quotients.rs†L1-L36】
* Manifest und Log wurden erneut via `scripts/vendor_stwo/update_manifest.py` erzeugt; die aktualisierte Prüfliste enthält nun sämtliche `prover/`- und `tracing/`-Dateien, während das Log den Lauf dokumentiert.【F:vendor/stwo-dev/0.1.1/manifest/final_file_list.txt†L1-L120】【F:vendor/stwo-dev/0.1.1/manifest/chunks.json†L1-L6】【F:vendor/stwo-dev/0.1.1/logs/update_manifest.log†L1-L12】
* Die Backend-Unterverzeichnisse `prover/backend/cpu/` und `prover/backend/simd/` fehlen weiterhin; `mod.rs` verweist noch auf diese Pfade, die in einem späteren Import nachgezogen werden müssen.【F:vendor/stwo-dev/0.1.1/staging/crates/stwo/src/prover/mod.rs†L9-L24】

### Initiale Artefaktplanung (2025-10-17)

* Segmentierung: `vendor/stwo-dev/0.1.1/manifest/chunk_plan.json` beschreibt neun Zielsegmente (pro Workspace-Ordner ein Eintrag) und hält die Segmentgrenze bei 50 MiB. Grundlage ist das entpackte Archiv `rpp/zk/prover_stwo_backend/stwo-dev.zip`; alle Crate-Verzeichnisse bleiben deutlich unterhalb der Grenze.
* Manifest-Initialisierung: Ein Lauf von `scripts/vendor_stwo/update_manifest.py` gegen den leeren Zielbaum erzeugte ein leeres `manifest/chunks.json` sowie eine leere `manifest/final_file_list.txt` zur Vorbereitung der Folgeimporte.
* Log-Ablage: Das Manifest-Log liegt unter `vendor/stwo-dev/0.1.1/logs/update_manifest.log` und dokumentiert den Initiallauf ohne erkannte Segmente.

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
* Segmentgröße: höchstens drei Crates pro Batch, um innerhalb des Diff-Limits zu bleiben.
* Folgeaufgaben: Umsetzung der noch offenen Vendor-Schritte gemäß Abschnitt „Folgeaktionen“ im Abhängigkeits-Kompatibilitätsbericht.

## Aktualisierung – Malachite-Workspace (2025-10-17)

* Alle Teilcrates (`malachite`, `malachite-base`, `malachite-float`, `malachite-nz`, `malachite-q`) erhielten frische Segment-Manifestdateien über `scripts/vendor_malachite/update_manifest.py`. Die neuen `chunks.json`-Stände verweisen auf geprüfte `.part000`-Segmente mit aktualisierten Zeitstempeln.
* Die Datei-Manifestlisten (`manifest/final_file_list.txt`) wurden für sämtliche Crates neu berechnet; die Einträge enthalten SHA-256, Byte-Länge und Relativpfad und schließen die Log- und Manifestartefakte ein.
* Für jede Quelle liegt nun ein `manifest/reference_hashes.json` mit aktuellen Prüfsummen des `src/`-Baums vor, sodass die Integritätsprüfung ohne erneuten Download referenziert werden kann.
* `scripts/vendor_malachite/verify_extracted_files.py --package <crate> --version 0.4.18` meldet für alle genannten Crates `pass`; die entsprechenden Artefakte (`manifest/integrity_report.json`, `logs/integrity_report.txt`) wurden aktualisiert.

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
