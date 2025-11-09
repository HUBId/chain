# Phase‑3 Evidence Bundle Manifest

Dieses Manifest dient als Inhaltsverzeichnis für das Nightly-Artefakt
`phase3-evidence-<timestamp>.tar.gz` und zeigt, welche Nachweise für die
Audits der Snapshot- und WORM-Kontrollen bereitstehen. Die Bundles werden
über `cargo xtask collect-phase3-evidence` erzeugt; das Kommando sammelt
Dashboards, Alerts, Audit-Logs, Policy-Backups sowie WORM- und
Checksum-Reports und legt ein `manifest.json` mit den kategorisierten
Einträgen im Ausgabeverzeichnis ab.【F:xtask/src/main.rs†L2038-L2108】

## Snapshot-Verifier-Nachweise

| Artefakt | Speicherort | Beschreibung & Prüfung |
| --- | --- | --- |
| `snapshot-verify-report.json` | Release-Artefakt `snapshot-verifier-<target>` unter `dist/artifacts/<target>/` sowie CI-Smoke `snapshot-verifier-smoke`. | Aggregierter Report über alle Manifest-Prüfungen. Entsteht in den Release-Jobs `Build <target>` und im CI-Job `snapshot-verifier` durch `cargo xtask snapshot-verifier`. Validierung erfolgt via `cargo xtask verify-report --report <pfad>`, das den Report gegen `docs/interfaces/snapshot_verify_report.schema.json` prüft.【F:.github/workflows/release.yml†L120-L171】【F:.github/workflows/ci.yml†L369-L387】【F:xtask/src/main.rs†L220-L468】 |
| `snapshot-verify-report.json.sha256` | Upload im Release-Artefakt `snapshot-verifier-<target>` sowie im Smoke-Artefakt `snapshot-verifier-smoke`. | Enthält den SHA256-Hash des Aggregat-Reports. Hash wird beim Smoke-Lauf erstellt und zusammen mit dem Report hochgeladen; der Wert fließt ins Freigabeprotokoll ein. Für lokale Gegenproben `sha256sum <report>` ausführen und mit der `.sha256` vergleichen.【F:.github/workflows/release.yml†L150-L171】【F:xtask/src/main.rs†L304-L344】 |
| Einzelreports `*-verify.json` (optional) | `dist/artifacts/<target>/` pro Release-Target. | Einzelmanifest-Berichte aus `scripts/build_release.sh`. Bei Bedarf dem Bundle hinzufügen und mit dem Aggregat vergleichen, um Signaturen und Segmentzählungen zu verifizieren.【F:scripts/build_release.sh†L273-L348】 |

**Prüfschritte:**
1. Report und Hash aus dem passenden Artefakt herunterladen.
2. `cargo xtask verify-report --report <pfad>` ausführen, um Schema und
   Erfolgsstatus (`"all_passed": true`) zu bestätigen.【F:xtask/src/main.rs†L360-L448】
3. `sha256sum <report>` laufen lassen und mit der gespeicherten
   `snapshot-verify-report.json.sha256` vergleichen.
4. Ergebnisse im Übergabe- bzw. Auditprotokoll dokumentieren.

## WORM-Export-Logs & Signaturen

| Artefakt | Speicherort | Beschreibung & Prüfung |
| --- | --- | --- |
| Export-Logs (`*.jsonl`, `*.json`, `retention.meta`) | CI-Artefakt `worm-export-smoke` (`target/worm-export-smoke/`), Nightly-Artefakt gleichen Namens sowie `logs/` im Repository. | Enthalten die protokollierten Admission-Änderungen, Retention-Metadaten und Exportpfade des Stubs. Werden von `cargo xtask test-worm-export` erzeugt und in CI/Nightly hochgeladen.【F:.github/workflows/ci.yml†L354-L387】【F:.github/workflows/nightly.yml†L10-L36】【F:xtask/src/main.rs†L640-L742】 |
| `worm-export-summary.json` | Bestandteil des Artefakts `worm-export-smoke`. | Aggregiert die signierten Audit-Einträge, weist `signature_valid` aus und referenziert die exportierten Dateien. Bei der Evidence-Sammlung werden Summary und Logdateien in die Kategorie „WORM export evidence“ kopiert.【F:xtask/src/main.rs†L640-L742】【F:xtask/src/main.rs†L2343-L2373】 |
| Signaturdateien (`*.sha256`, `snapshot-key.hex`) | Teil des Smoke-Artefakts `snapshot-verifier-smoke` bzw. `worm-export-smoke`. | Dokumentieren die verwendeten Schlüssel und Prüfsummen für Snapshot- und WORM-Belege. Beim Audit lokale Hashprüfung (`sha256sum`) durchführen und Schlüsselmaterial vertraulich behandeln.【F:xtask/src/main.rs†L216-L344】【F:xtask/src/main.rs†L2343-L2373】 |

**Prüfschritte:**
1. Nightly- oder CI-Artefakt `worm-export-smoke` herunterladen und
   `worm-export-summary.json` öffnen.
2. `entries[].signature.signature_valid` und Retention-Metadaten
   kontrollieren. Bei Abweichungen den entsprechenden Export-Log prüfen.
3. Falls Signaturdateien vorliegen, Hashwerte (`*.sha256`) mit den
   exportierten JSONs vergleichen und die verwendeten Schlüssel gegen das
   Operator-Protokoll abgleichen.
4. Audit-Ergebnisse im Evidence-Bundle-Manifest (`manifest.json`)
   nachführen.

## Pflege & Verfügbarkeit

- **CI-Artefakte:** `snapshot-verifier-smoke` und `worm-export-smoke`
  stehen im Actions-Tab als 30‑Tage-Artefakte bereit. Nightly-Jobs
  erstellen zusätzlich vollständige Bundles mit identischen Strukturen.
- **Langzeitablage:** Für Releases werden die Artefakte im jeweiligen
  Tag (`snapshot-verifier-<target>`, `artifacts-<target>`) archiviert und
  im Freigabeprotokoll referenziert.【F:.github/workflows/release.yml†L120-L171】
- **Review-Prozess:** Vor Audits `cargo xtask collect-phase3-evidence`
  lokal ausführen oder das aktuelle Nightly-Artefakt herunterladen, um
  das `manifest.json` zu prüfen. Fehlende Einträge werden dort unter
  `missing` aufgeführt und müssen vor dem Audit geschlossen werden.【F:xtask/src/main.rs†L2038-L2108】【F:xtask/src/main.rs†L2343-L2373】
