# Malachite 0.4.18 Vendor Notes

- **Offizielle Download-URL:** https://crates.io/api/v1/crates/malachite/0.4.18/download
- **Geplante Segmentgröße:** 50 MiB (52 428 800 Byte) pro Chunk (`CHUNK_SEGMENT_SIZE_BYTES`)

## Chunk-Plan-Skript

Das Skript [`scripts/vendor_malachite/chunk_plan.sh`](../../../scripts/vendor_malachite/chunk_plan.sh) erstellt auf Basis eines heruntergeladenen Archivs einen Chunk-Plan, der die oben genannte Segmentgröße nicht überschreitet.

```bash
# Beispiel
./scripts/vendor_malachite/chunk_plan.sh /pfad/zum/malachite-0.4.18.crate
```

Standardmäßig wird der Plan als JSON unter `vendor/malachite/0.4.18/manifest/chunk_plan.json` geschrieben. Die Segmentgröße lässt sich über die Umgebungsvariable `CHUNK_SEGMENT_SIZE_BYTES` anpassen. Der aktuell gültige Plan liegt unter [`manifest/chunk_plan.json`](manifest/chunk_plan.json).

## Manifest-Update und Verifizierung

Mit dem Skript [`scripts/vendor_malachite/update_manifest.py`](../../../scripts/vendor_malachite/update_manifest.py) werden die heruntergeladenen Segmente inspiziert und deren Metadaten in `manifest/chunks.json` geschrieben. Der Vorgang berechnet alle Segment-Hashes neu, aktualisiert bestehende Einträge und protokolliert die Ergebnisse zusätzlich unter `vendor/malachite/0.4.18/logs/update_manifest.log`.

```bash
# Manifest aktualisieren (Standardpfade verwenden)
./scripts/vendor_malachite/update_manifest.py
```

Weichen gespeicherter Hash und Dateigröße von den Manifest-Werten ab, löscht das Skript die betroffene Segmentdatei und beendet sich mit Exit-Code `3`. Damit kann ein nachgelagerter Download-Prozess automatisch ausgelöst werden.

## Segment-Testlauf & Logausgabe

Für einen vollständigen Integritäts-Check über alle Subkrates steht das Sammelskript [`scripts/vendor_malachite/test_segments.sh`](../../../scripts/vendor_malachite/test_segments.sh) bereit. Es ruft nacheinander `download_segments.sh`, `merge_segments.sh` und `verify_extracted_files.py` für jede Teilcrate auf.

```bash
./scripts/vendor_malachite/test_segments.sh
```

Der Durchlauf erzeugt pro Crate dedizierte Logdateien. Für `malachite` befinden sie sich unter:

- `logs/download_segments_malachite_0_4_18.log` – Segment-Download und Manifestabgleich.
- `logs/merge_segments_malachite_0_4_18.log` – Zusammenführung zum `.crate`-Archiv.
- `logs/integrity_report.txt` – Ergebnisbericht der Quelldatei-Verifikation.

Nach Abschluss entfernt das Sammelskript automatisch die während des Laufs
heruntergeladenen `.part*`-Segmente sowie das temporär erzeugte `.crate`,
damit keine Binärdateien im Repository verbleiben. Wer die Artefakte lokal
behalten möchte, kann den Lauf mit `MALACHITE_KEEP_CHUNKS=1` ausführen.

Die Prüfberichte werden bewusst gekürzt, um Upload-Limits einzuhalten: pro Status (z. B. "missing in vendor") listet `integrity_report.txt` höchstens 50 Beispielpfade. Die vollständigen Zählwerte und Stichproben stehen im JSON-Gegenstück [`manifest/integrity_report.json`](manifest/integrity_report.json).

### Struktur von `chunks.json`

Die Manifest-Datei enthält allgemeine Metadaten sowie ein Feld `segments`, das eine Liste aller Segmentobjekte umfasst. Jedes Segment besitzt mindestens die folgenden Informationen:

- `segment_name`: Der Name des Segments auf dem Dateisystem.
- `index`: Der numerische Index des Segments (beginnend bei `0`).
- `size_bytes`: Tatsächliche Dateigröße in Byte.
- `sha256`: Der berechnete SHA-256-Hash der Segmentdatei.
- `timestamp`: Zeitpunkt der letzten erfolgreichen Verifikation im UTC-Format (`YYYY-MM-DDTHH:MM:SSZ`).

Ergänzend werden `chunk_name`, `offset`, `length`, `downloaded_at` und `status` gepflegt, damit die Segmentinformationen mit dem Chunk-Plan sowie dem Download-Prozess abgeglichen werden können.

## PR-Abfolge

Um die Review-Last überschaubar zu halten, sollte jeder Pull Request für diese Vendor-Aktualisierung maximal rund 50 000 Diff-Zeilen umfassen. Das höhere Limit reflektiert die abgestimmte Review-Kapazität des Teams, das für diese Serie zusätzliche Zeitfenster reserviert hat. Der Gesamtimport wird dazu in fünf aufeinanderfolgende Teil-PRs zerlegt, die den Malachite-Workspace von außen nach innen aufbauen:

1. **metakrate** – Workspace-Manifeste, gemeinsame Lizenzdateien und Hilfsskripte.
2. **malachite-base** – Kern-Bibliothek mit booleschen Utilities und allgemeinen Zahlentypen.
3. **malachite-nz** – Nicht-negative Ganzzahlen inkl. Tests und Beispielprogramme.
4. **malachite-q** – Rationale Zahlen und zugehörige Tests.
5. **malachite-float** – Fließkommazahlen, Benchmarks und Integration in das Workspace-Manifest.

Vor dem ersten Teil-PR wird das Chunk-Plan-Skript [`chunk_plan.sh`](../../../scripts/vendor_malachite/chunk_plan.sh) einmalig gegen das frisch heruntergeladene Crate-Archiv ausgeführt. Dadurch steht ein stabiler Zuschnitt der Binärsegmente für alle nachfolgenden PRs fest. Nach jedem Teil-PR, der neue Dateien unter `chunks/` oder `manifest/` anlegt oder verändert, ist anschließend das Manifest über [`update_manifest.py`](../../../scripts/vendor_malachite/update_manifest.py) zu aktualisieren. Bei reinem Code-Import ohne neue Segmente genügt ein Lauf unmittelbar vor dem finalen PR, um sämtliche Hashes zu verifizieren.

| Teil-PR              | Zielverzeichnis (relativ zu `vendor/malachite/0.4.18/src/`) | Segment(e) laut `manifest/chunks.json` | Inhaltlicher Block |
|----------------------|------------------------------------------------------------|----------------------------------------|--------------------|
| 1 – metakrate        | `.` (Workspace-Wurzel, `Cargo.toml`, `README.md`, `katex-header.html`) | `chunk_000` (Metadatenwurzel)         | Grundlegende Workspace-Metadaten und Hilfsassets |
| 2 – malachite-base   | `src/malachite-base/src/booleans`, `src/malachite-base/src/integer`    | `chunk_000` (`src/malachite-base/…`)   | Basisfunktionen, boolesche Utilities und ganzzahlige Typen |
| 3 – malachite-nz     | `src/malachite-nz/src`                                        | `chunk_000` (`src/malachite-nz/…`)     | Nicht-negative Ganzzahlen inkl. Tests `tests/natural/arithmetic A–C` |
| 4 – malachite-q      | `src/malachite-q/src`                                         | `chunk_000` (`src/malachite-q/…`)      | Rationale Zahlen, Parser sowie `tests/rational` |
| 5 – malachite-float  | `src/malachite-float/src`, `tests/float`                      | `chunk_000` (`src/malachite-float/…`)  | Fließkommazahlen, Benchmarks und Integrationstests |
