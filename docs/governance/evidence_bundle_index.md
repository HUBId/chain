# Phase‑3 Evidence Bundle Manifest

Dieses Manifest dient als Inhaltsverzeichnis für das Nightly-Artefakt
`phase3-evidence-<timestamp>.tar.gz` und zeigt, welche Nachweise für die
Audits der Snapshot- und WORM-Kontrollen bereitstehen. Die Bundles werden
über `cargo xtask collect-phase3-evidence` erzeugt; das Kommando sammelt
Dashboards, Alerts, Audit-Logs, Policy-Backups sowie WORM-/Retention-
Reports, Snapshot-Signaturen und Checksum-Reports und legt ein
`manifest.json` mit den kategorisierten Einträgen im
Ausgabeverzeichnis ab.【F:xtask/src/main.rs†L4090-L4364】

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
| Export-Logs (`*.jsonl`, `*.json`, `retention.meta`) | CI-Artefakt `worm-export-smoke` (`target/worm-export-smoke/`), Nightly-Artefakt gleichen Namens sowie `logs/` im Repository. | Enthalten die protokollierten Admission-Änderungen, Retention-Metadaten und Exportpfade des Stubs. Werden von `cargo xtask test-worm-export` erzeugt und in CI/Nightly hochgeladen.【F:.github/workflows/ci.yml†L354-L387】【F:.github/workflows/nightly.yml†L19-L58】【F:xtask/src/main.rs†L640-L742】 |
| `worm-export-summary.json` | Bestandteil des Artefakts `worm-export-smoke`. | Aggregiert die signierten Audit-Einträge, weist `signature_valid` aus und referenziert die exportierten Dateien. Bei der Evidence-Sammlung werden Summary und Logdateien in die Kategorie „WORM export evidence“ kopiert.【F:xtask/src/main.rs†L640-L742】【F:xtask/src/main.rs†L3676-L3717】 |
| `worm-retention-report.json` | `target/compliance/worm-retention/` im Evidence-Bundle sowie Nightly-Artefakt `worm-export-smoke`. | Ergebnis von `cargo xtask worm-retention-check`: fasst überprüfte Summaries, Audit-Logs, Retention-Metadaten und etwaige Verstöße zusammen. Der Nightly-Job bricht bei verwaisten oder manipulierten Einträgen ab, der Report landet in der Kategorie „WORM export evidence“.【F:xtask/src/main.rs†L3527-L3879】【F:.github/workflows/nightly.yml†L19-L58】 |

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

## Snapshot-Signaturen & Schlüssel

| Artefakt | Speicherort | Beschreibung & Prüfung |
| --- | --- | --- |
| `snapshot-key.hex` | `target/snapshot-verifier-smoke/` bzw. Evidence-Kategorie `snapshot-signatures`. | Enthält den öffentlichen Schlüssel, mit dem `chunks.json` signiert wurde. Für Audits kann derselbe Schlüssel mit `snapshot-verify` oder `cargo xtask snapshot-verifier` genutzt werden.【F:xtask/src/main.rs†L200-L344】【F:xtask/src/main.rs†L4388-L4438】 |
| `snapshots/manifest/*.sig` | `target/snapshot-verifier-smoke/snapshots/manifest/`. | Detached Signaturen für die Manifest-Dateien. `cargo xtask collect-phase3-evidence` kopiert sie in die Kategorie „Snapshot manifest signatures“, sodass Signaturprüfungen im Bundle nachvollziehbar bleiben.【F:xtask/src/main.rs†L200-L344】【F:xtask/src/main.rs†L4388-L4438】 |

**Prüfschritte:**
1. `snapshot-key.hex` und das passende `chunks.json.sig` aus dem Bundle
   entnehmen.
2. Manifest (`chunks.json`) sowie Signatur mit `snapshot-verify`
   validieren oder lokal `cargo xtask snapshot-verifier` ausführen.
3. Ergebnisse und Schlüsselreferenzen im Auditprotokoll festhalten.

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
  `missing` aufgeführt und müssen vor dem Audit geschlossen werden.【F:xtask/src/main.rs†L4090-L4175】【F:xtask/src/main.rs†L4388-L4463】
