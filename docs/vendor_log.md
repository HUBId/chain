# Vendor-Integrationsprotokoll

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

## Strategie-Update – Mehrstufige Vendor-Planung (2025-10-14)

* Diff-Limit pro PR: ca. 2 000 geänderte Zeilen, damit Code-Reviews handhabbar bleiben.
* Segmentgröße: höchstens drei Crates pro Batch, um innerhalb des Diff-Limits zu bleiben.
* Folgeaufgaben: Umsetzung der noch offenen Vendor-Schritte gemäß Abschnitt „Folgeaktionen“ im Abhängigkeits-Kompatibilitätsbericht.

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
