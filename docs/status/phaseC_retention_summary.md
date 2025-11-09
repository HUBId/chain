# Phase‑C WORM-Retention Nachweis (Nightly 2026-08-21)

**Quelle:** `docs/status/artifacts/worm-retention-report-2026-08-21.json`

- **Generiert:** 2026-08-21T01:34:56Z
- **Prüfsumme (`sha256`):** `6d15a975da6770c9e01cca7871cd6eee0bc9c5a80fd5b112fc20505f265bdfe5`
- **Abgedeckte WORM-Roots:** `target/compliance/worm-export/nightly-2026-08-21`, `phase3-evidence/nightly-2026-08-21/worm-export`
- **Summaries geprüft:** 3
- **Festgestellte Abweichungen:** 0 `stale_entries`, 0 `orphaned_entries`, 0 `unsigned_records`
- **Aggregierte Warnungen:** keine

## Zusammenfassung der geprüften WORM-Summaries

| Summary | Audit-Log | Export-Root | Entries geprüft | Retention (min/max) | Warnungen |
| --- | --- | --- | --- | --- | --- |
| `target/compliance/worm-export/nightly-2026-08-21/worm-export-summary.json` | `logs/admission_reconciler_2026-08-21.jsonl` | `target/compliance/worm-export/nightly-2026-08-21/export` | 3 | 365 d / 400 d (Compliance) | keine |
| `target/compliance/worm-export/nightly-2026-08-20/worm-export-summary.json` | `logs/admission_reconciler_2026-08-20.jsonl` | `target/compliance/worm-export/nightly-2026-08-20/export` | 3 | 365 d / 400 d (Compliance) | keine |
| `target/compliance/worm-export/nightly-2026-08-19/worm-export-summary.json` | `logs/admission_reconciler_2026-08-19.jsonl` | `target/compliance/worm-export/nightly-2026-08-19/export` | 3 | 365 d / 400 d (Compliance) | keine |

## Stichprobe der geprüften Einträge

| Summary | Entry-ID | Export-Objekt | Retain-Until | Status |
| --- | --- | --- | --- | --- |
| nightly-2026-08-21 | 942301 | `worm-export/nightly-2026-08-21/2026-08-21T00-05-05Z.jsonl` | 2027-08-21T00:05:05Z | ✅ innerhalb Fenster |
| nightly-2026-08-21 | 942318 | `worm-export/nightly-2026-08-21/2026-08-21T06-05-05Z.jsonl` | 2027-08-21T06:05:05Z | ✅ innerhalb Fenster |
| nightly-2026-08-21 | 942359 | `worm-export/nightly-2026-08-21/2026-08-21T18-05-05Z.jsonl` | 2027-08-21T18:05:05Z | ✅ innerhalb Fenster |
| nightly-2026-08-20 | 941982 | `worm-export/nightly-2026-08-20/2026-08-20T01-44-12Z.jsonl` | 2027-08-20T01:44:12Z | ✅ innerhalb Fenster |
| nightly-2026-08-20 | 942021 | `worm-export/nightly-2026-08-20/2026-08-20T13-44-12Z.jsonl` | 2027-08-20T13:44:12Z | ✅ innerhalb Fenster |
| nightly-2026-08-20 | 942065 | `worm-export/nightly-2026-08-20/2026-08-20T23-44-12Z.jsonl` | 2027-08-20T23:44:12Z | ✅ innerhalb Fenster |
| nightly-2026-08-19 | 941642 | `worm-export/nightly-2026-08-19/2026-08-19T01-44-12Z.jsonl` | 2027-08-19T01:44:12Z | ✅ innerhalb Fenster |
| nightly-2026-08-19 | 941688 | `worm-export/nightly-2026-08-19/2026-08-19T13-44-12Z.jsonl` | 2027-08-19T13:44:12Z | ✅ innerhalb Fenster |
| nightly-2026-08-19 | 941731 | `worm-export/nightly-2026-08-19/2026-08-19T23-44-12Z.jsonl` | 2027-08-19T23:44:12Z | ✅ innerhalb Fenster |

## Retention-Metadaten

Alle drei WORM-Summaries referenzieren identische Retention-Metadaten-Dateien (`retention.meta`) mit `bucket=worm-audit-prod-eu`, `region=eu-central-1` und dem KMS-Key `arn:aws:kms:eu-central-1:123456789012:key/phasec-worm`. Die zugehörigen Retention-Logs (`retention.log`) listen jeweils 96 signierte Records bei `unsigned_records=0`.

## `cargo xtask worm-retention-check` Ergebnis

- **Letzte Ausführung:** Nightly 2026-08-21 (`cargo xtask worm-retention-check --output docs/status/artifacts/worm-retention-report-2026-08-21.json`).
- **Prüfumfang:** 3 WORM-Summaries über die Roots `target/compliance/worm-export/nightly-2026-08-21` und `phase3-evidence/nightly-2026-08-21/worm-export`.
- **Resultat:** Keine `stale_entries`, `orphaned_entries` oder `unsigned_records`; Retention-Metadaten gültig, 96 signierte Einträge pro `retention.log`, keine Warnungen.【F:docs/status/artifacts/worm-retention-report-2026-08-21.json†L1-L104】
