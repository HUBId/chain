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
