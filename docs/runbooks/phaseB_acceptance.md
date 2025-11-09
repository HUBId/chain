# Phase‑B Acceptance Checklist

Diese Checkliste sammelt alle Nachweise, die für die Abnahme der Phase‑B-Stagingphase
benötigt werden. Sämtliche Punkte erwarten verlinkte Belege – typischerweise die täglich
versionierten Artefakte aus dem `staging-soak`-Job, ergänzende Dashboards oder Tickets.

## Artefaktliste

### Tägliche Staging-Soak-Berichte
- [ ] **Snapshot-Health-Report archiviert.** `cargo xtask staging-soak` legt den aktuellen
      `snapshot-health-report.json` unter `logs/staging-soak/<YYYY-MM-DD>/<timestamp>/`
      ab. Prüfe, dass alle Sessions ohne Anomalien gelistet sind und verlinke den Report im
      Acceptance-Log.
- [ ] **Timetoke-SLO-Report gesichert.** Der gleiche Lauf erzeugt `timetoke-slo-report.md`.
      Der Markdown-Report muss die Erfolgsquote sowie die Latenz-SLOs dokumentieren.
      Verknüpfe den gültigen Report mit dem Phase‑B-Review.
- [ ] **Admission-Reconciliation nachweisbar.** Der tägliche `admission-reconciliation.json`
      weist nach, dass Runtime-, Disk- und Audit-Snapshots deckungsgleich sind. Hinterlege
      den Report gemeinsam mit einer Ticket-/Alert-Referenz, falls Drift festgestellt wurde.
- [ ] **Staging-Soak-Summary hinterlegt.** `summary.json` fasst alle Checks zusammen und
      enthält die aggregierten Flags (`snapshot.ok`, `timetoke.ok`, `admission.ok`, `errors`).
      Hinterlege den neuesten grün markierten Summary-Eintrag als Nachweis.

### Dual-Control-Workflow
- [ ] **Integrationstest-Logs verlinkt.** Hinterlege den Actions-Run des CI-Jobs
      `rpc-admission-audit` inklusive Step-Logs für `cargo test -p rpp-chain --locked --test admission`,
      damit Reviewer:innen den Durchlauf von `tests/network/admission_dual_control.rs` nachvollziehen können.【F:.github/workflows/ci.yml†L367-L376】【F:tests/network/admission_dual_control.rs†L1-L55】
- [ ] **Audit-Einträge im Evidence-Log.** Exportiere die JSONL-Scheibe (`GET /p2p/admission/audit?limit=<n>`) direkt nach einer
      freigegebenen Änderung und verlinke sie gemeinsam mit dem Pending-/Approve-Flow, sodass beide Freigaben und die
      WORM-signierten Metadaten im Abnahmeprotokoll landen.【F:docs/network/admission.md†L60-L121】【F:rpp/p2p/src/policy_log.rs†L45-L194】

## Exit-Kriterien

Phase B gilt als erfolgreich abgeschlossen, wenn alle Artefakte oben verlinkt sind und
zusätzlich folgende Bedingungen erfüllt werden:

- ✅ **Nightly-Gate 14 Tage grün.** Der Gate `staging-soak` im Nightly-Workflow
  [`.github/workflows/nightly.yml`](../../.github/workflows/nightly.yml) muss 14
  aufeinanderfolgende Läufe ohne SLO-Verletzungen liefern – `summary.json` meldet
  `"ok": true` und `staging_soak_report.json` bestätigt Snapshot-/Timetoke-SLO-Compliance.
  Dokumentiere Zeitraum, Artefaktpfade und Report-Link im Acceptance-Protokoll.
- ✅ **Keine SLO-Verletzungen.** In den 14 Tagen dürfen weder Snapshot-Anomalien noch
  Timetoke-SLO- oder Admission-Drifts auftreten. Etwaige Alerts müssen innerhalb des Zeitraums
  geschlossen sein.
- ✅ **Artefakte versioniert verfügbar.** Die oben genannten JSON/Markdown-Dateien müssen in
  der Evidence-Sammlung oder als angehängte CI-Artefakte referenzierbar sein, sodass Reviewer:innen
  den Verlauf nachvollziehen können.

Sobald alle Kriterien erfüllt sind und die Nachweise konsistent verlinkt wurden, kann Phase B
formal abgenommen werden.
