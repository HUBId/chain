# Malachite 0.4.18 Vendor Notes

- **Offizielle Download-URL:** https://crates.io/api/v1/crates/malachite/0.4.18/download
- **Geplante Segmentgröße:** 50 MiB (52 428 800 Byte) pro Chunk (`CHUNK_SEGMENT_SIZE_BYTES`)

## Chunk-Plan-Skript

Das Skript [`scripts/vendor_malachite/chunk_plan.sh`](../../../scripts/vendor_malachite/chunk_plan.sh) erstellt auf Basis eines heruntergeladenen Archivs einen Chunk-Plan, der die oben genannte Segmentgröße nicht überschreitet.

```bash
# Beispiel
./scripts/vendor_malachite/chunk_plan.sh /pfad/zum/malachite-0.4.18.crate
```

Standardmäßig wird der Plan als JSON unter `vendor/malachite/0.4.18/manifest/chunk_plan.json` geschrieben. Die Segmentgröße lässt sich über die Umgebungsvariable `CHUNK_SEGMENT_SIZE_BYTES` anpassen.

## Manifest-Update und Verifizierung

Mit dem Skript [`scripts/vendor_malachite/update_manifest.py`](../../../scripts/vendor_malachite/update_manifest.py) werden die heruntergeladenen Segmente inspiziert und deren Metadaten in `manifest/chunks.json` geschrieben. Der Vorgang berechnet alle Segment-Hashes neu, aktualisiert bestehende Einträge und protokolliert die Ergebnisse zusätzlich unter `vendor/malachite/0.4.18/logs/update_manifest.log`.

```bash
# Manifest aktualisieren (Standardpfade verwenden)
./scripts/vendor_malachite/update_manifest.py
```

Weichen gespeicherter Hash und Dateigröße von den Manifest-Werten ab, löscht das Skript die betroffene Segmentdatei und beendet sich mit Exit-Code `3`. Damit kann ein nachgelagerter Download-Prozess automatisch ausgelöst werden.

### Struktur von `chunks.json`

Die Manifest-Datei enthält allgemeine Metadaten sowie ein Feld `segments`, das eine Liste aller Segmentobjekte umfasst. Jedes Segment besitzt mindestens die folgenden Informationen:

- `segment_name`: Der Name des Segments auf dem Dateisystem.
- `index`: Der numerische Index des Segments (beginnend bei `0`).
- `size_bytes`: Tatsächliche Dateigröße in Byte.
- `sha256`: Der berechnete SHA-256-Hash der Segmentdatei.
- `timestamp`: Zeitpunkt der letzten erfolgreichen Verifikation im UTC-Format (`YYYY-MM-DDTHH:MM:SSZ`).

Ergänzend werden `chunk_name`, `offset`, `length`, `downloaded_at` und `status` gepflegt, damit die Segmentinformationen mit dem Chunk-Plan sowie dem Download-Prozess abgeglichen werden können.
