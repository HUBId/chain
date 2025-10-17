# Malachite NZ 0.4.18 Vendor Notes

- **Offizielle Download-URL:** https://crates.io/api/v1/crates/malachite-nz/0.4.18/download
- **Segmentgröße:** 50 MiB (52 428 800 Byte) pro Chunk (`CHUNK_SEGMENT_SIZE_BYTES`)
- **Segment-Dateinamenschema:** `malachite-nz-0.4.18.part{index:03d}`

## Chunk-Plan-Skript

Das Skript [`scripts/vendor_malachite/chunk_plan.sh`](../../../scripts/vendor_malachite/chunk_plan.sh) dient zur Berechnung des
Chunk-Plans. Für `malachite-nz` sollte der Ausgabepfad explizit auf das passende Verzeichnis gesetzt werden:

```bash
./scripts/vendor_malachite/chunk_plan.sh \
  /pfad/zum/malachite-nz-0.4.18.crate \
  vendor/malachite-nz/0.4.18/manifest/chunk_plan.json
```

Die Segmentgröße wird standardmäßig über die Umgebungsvariable `CHUNK_SEGMENT_SIZE_BYTES` gesteuert und beträgt für diesen Import
50 MiB. Der aktuelle Plan liegt unter [`manifest/chunk_plan.json`](manifest/chunk_plan.json).

## Manifest-Update und Verifizierung

Zur Aktualisierung der Segment-Metadaten verwenden wir das Skript
[`scripts/vendor_malachite/update_manifest.py`](../../../scripts/vendor_malachite/update_manifest.py). Da die Standardparameter
auf den `malachite`-Workspace zeigen, sind für `malachite-nz` explizite Pfade erforderlich:

```bash
./scripts/vendor_malachite/update_manifest.py \
  --plan vendor/malachite-nz/0.4.18/manifest/chunk_plan.json \
  --manifest vendor/malachite-nz/0.4.18/manifest/chunks.json \
  --chunks-dir vendor/malachite-nz/0.4.18/chunks \
  --log-file vendor/malachite-nz/0.4.18/logs/update_manifest.log \
  --segment-template 'malachite-nz-0.4.18.part{index:03d}'
```

Das Skript prüft vorhandene Segmente, verifiziert deren SHA-256-Hashes und aktualisiert den Eintrag in
[`manifest/chunks.json`](manifest/chunks.json). Fehlende oder korrupte Dateien werden protokolliert, damit ein anschließender
Downloadprozess erneut ausgeführt werden kann. Nach jedem Lauf steht der vollständige Status im Log
[`logs/update_manifest.log`](logs/update_manifest.log).

### Struktur von `chunks.json`

Jeder Eintrag im Feld `segments` enthält mindestens folgende Attribute:

- `segment_name`: Dateiname des Segments.
- `index`: Segmentindex (beginnend bei `0`).
- `chunk_name`: Referenz auf den Chunk-Plan-Eintrag (`chunk_000`, `chunk_001`, …).
- `offset` / `length`: Byte-Offset im Ursprungsarchiv sowie Segmentlänge.
- `size_bytes` und `sha256`: Ergebnisse der letzten erfolgreichen Verifikation (falls verfügbar).
- `timestamp`: Zeitpunkt der letzten Aktualisierung im UTC-Format.
- `status`: Aktueller Zustand (`verified`, `missing`, `deleted`).

## Upstream-Unterlagen

Folgende Dateien wurden zusätzlich zum bisherigen Quellcode importiert:

- Upstream-README unter [`docs/upstream/README.md`](docs/upstream/README.md).
- Asset-Dateien im Verzeichnis [`images/`](images/).
- Werkzeuge und Metadaten: [`extra-tests.py`](extra-tests.py), [`katex-header.html`](katex-header.html),
  [`rustfmt.toml`](rustfmt.toml), [`build.rs`](build.rs), `.cargo_vcs_info.json`, `.gitignore`, `Cargo.toml`, `Cargo.toml.orig`
  sowie `Cargo.lock`.

## Segmentübersicht

Der aktuelle Chunk-Plan besteht aus einem einzelnen Segment:

| Chunk | Segmentdatei                      | Länge (Byte) | Status laut Manifest |
|-------|-----------------------------------|--------------|----------------------|
| 000   | `malachite-nz-0.4.18.part000`     | 2 426 976    | `missing`            |

Weitere Segmente werden bei Bedarf durch einen erneuten Lauf des Chunk-Plan-Skripts erzeugt und über das Manifest verwaltet.

## Automatisierter Segment-Test

Mit [`scripts/vendor_malachite/test_segments.sh`](../../../scripts/vendor_malachite/test_segments.sh) lassen sich Download (`download_segments.sh`), Merge (`merge_segments.sh`) und Verifikation (`verify_extracted_files.py`) für alle Subkrates in einem Durchlauf ausführen:

```bash
./scripts/vendor_malachite/test_segments.sh
```

Für `malachite-nz` entstehen dabei folgende Protokolle unter [`logs/`](logs/):

- `download_segments_malachite_nz_0_4_18.log`
- `merge_segments_malachite_nz_0_4_18.log`
- `integrity_report.txt`

Nach dem Lauf werden alle heruntergeladenen `.part*`-Segmente und das
temporär erstellte `.crate` automatisch gelöscht, sodass keine Binärdateien
im Repository landen. Wer die Dateien zu Analysezwecken behalten möchte,
setzt `MALACHITE_KEEP_CHUNKS=1` vor dem Aufruf.

Die Prüfberichte werden bewusst gekürzt, um Upload-Limits einzuhalten: pro Status (z. B. "missing in vendor") listet `integrity_report.txt` höchstens 50 Beispielpfade. Die vollständigen Zählwerte und Stichproben stehen im JSON-Gegenstück [`manifest/integrity_report.json`](manifest/integrity_report.json).
