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

## Exit-Kriterien

Phase B gilt als erfolgreich abgeschlossen, wenn alle Artefakte oben verlinkt sind und
zusätzlich folgende Bedingungen erfüllt werden:

- ✅ **14 Tage grün.** Der `staging-soak`-Workflow (siehe
  [`.github/workflows/nightly.yml`](../../.github/workflows/nightly.yml)) liefert mindestens
  14 aufeinanderfolgende Summary-Dateien mit `"ok": true`. Dokumentiere den Zeitraum sowie
  die Artefaktpfade im Acceptance-Protokoll.
- ✅ **Keine SLO-Verletzungen.** In den 14 Tagen dürfen weder Snapshot-Anomalien noch
  Timetoke-SLO- oder Admission-Drifts auftreten. Etwaige Alerts müssen innerhalb des Zeitraums
  geschlossen sein.
- ✅ **Artefakte versioniert verfügbar.** Die oben genannten JSON/Markdown-Dateien müssen in
  der Evidence-Sammlung oder als angehängte CI-Artefakte referenzierbar sein, sodass Reviewer:innen
  den Verlauf nachvollziehen können.

Sobald alle Kriterien erfüllt sind und die Nachweise konsistent verlinkt wurden, kann Phase B
formal abgenommen werden.
