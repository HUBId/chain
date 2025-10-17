# STWO 0.1.1 Vendor Snapshot

Dieses Verzeichnis enthält die von StarkWare veröffentlichten Quellen der STWO-Version `0.1.1`.
Alle Dateien stammen unverändert aus dem Upstream-Archiv `stwo-dev.zip` und werden in
Segmenten in dieses Repository importiert.

## Segment-Workflow

Damit Code-Reviews handhabbar bleiben, darf jeder Import-PR höchstens 25.000 geänderte
Zeilen umfassen. Der empfohlene Ablauf für einen neuen Upstream-Drop lautet:

1. **Segmentplanung:** Teile das Upstream-Archiv in logische Pakete (z. B. Kernbibliothek,
   Beispiele, Hilfsskripte), deren jeweiliger Diff unterhalb der 25 k-Grenze bleibt.
2. **Importreihenfolge:**
   - Basis-Infrastruktur (`.cargo`, `WORKSPACE`, `Cargo.toml`, gemeinsame Skripte).
   - Kern-Crates (`crates/stwo`, `crates/air-utils`, `crates/constraint-framework`).
   - Ergänzende Crates (`crates/std-shims`, `crates/examples`) und restliche Assets.
3. **Integrations-Commit:** Nach dem letzten Segment folgt ein abschließender Commit,
   der die lokale `Cargo.toml` aktualisiert und eventuelle Anpassungen für das
   Einbinden in die RPP-Buildumgebung enthält.
4. **Validierung:** Führe `cargo check -p stwo-official` innerhalb des
   Projekts aus, sobald alle Segmente gemergt sind.

Weitere Hinweise zur Pflege der Vendor-Snapshots sind im Wurzelverzeichnis dieser
Vendor-Struktur dokumentiert.

Das vollständige Upstream-README befindet sich in
[`README.upstream.md`](README.upstream.md).

## Hilfsskripte

Zur Pflege des Vendor-Drops stehen im Repository drei Helfer zur Verfügung:

1. [`scripts/vendor_stwo/extract.sh`](../../../../../../scripts/vendor_stwo/extract.sh)
   entpackt das Upstream-Archiv `vendor/stwo-dev/stwo-dev.zip` in ein Staging-Verzeichnis.
2. Nach dem manuellen Kopieren der benötigten Teilmodule in die jeweiligen Segment-Commits
   prüft [`scripts/vendor_stwo/verify_extracted_files.py`](../../../../../../scripts/vendor_stwo/verify_extracted_files.py)
   optional, ob die abgelegten Dateien den Hashes im Staging-Bereich entsprechen.
3. Abschließend erzeugt [`scripts/vendor_stwo/update_manifest.py`](../../../../../../scripts/vendor_stwo/update_manifest.py)
   die Dateien `manifest/chunks.json` und `manifest/final_file_list.txt` mit frischen SHA-256-Hashes
   der Segmentpakete bzw. der finalen Quellbäume.

Der empfohlene Ablauf lautet somit: **Entpacken → Segmentweise ins Repository kopieren → Manifest aktualisieren**.
