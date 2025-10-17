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
