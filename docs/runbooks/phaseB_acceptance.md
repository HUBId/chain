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
      - 📎 CI-Artefakt: [Actions-Run `staging-soak`](https://github.com/<org>/<repo>/actions/runs/<run-id>#artifact:snapshot-health-report)
- [ ] **Timetoke-SLO-Report gesichert.** Der gleiche Lauf erzeugt `timetoke-slo-report.md`.
      Der Markdown-Report muss die Erfolgsquote sowie die Latenz-SLOs dokumentieren.
      Verknüpfe den gültigen Report mit dem Phase‑B-Review und referenziere das
      [Timetoke-Failover-Runbook](./timetoke_failover.md) als Eskalationspfad
      für aufgetretene Verstöße.【F:docs/runbooks/timetoke_failover.md†L1-L140】
      - 📎 Metrics-Report: [Timetoke-SLO-Artefakt](https://github.com/<org>/<repo>/actions/runs/<run-id>#artifact:timetoke-slo-report)
- [ ] **Admission-Reconciliation nachweisbar.** Der tägliche `admission-reconciliation.json`
      weist nach, dass Runtime-, Disk- und Audit-Snapshots deckungsgleich sind. Hinterlege
      den Report gemeinsam mit einer Ticket-/Alert-Referenz, falls Drift festgestellt wurde.
      - 📎 Evidence-Log: [Admission-Reconciliation Export](https://storage.example.invalid/phase-b/admission-reconciliation-<date>.json)
- [ ] **Staging-Soak-Summary hinterlegt.** `summary.json` fasst alle Checks zusammen und
      enthält die aggregierten Flags (`snapshot.ok`, `timetoke.ok`, `admission.ok`, `errors`).
      Hinterlege den neuesten grün markierten Summary-Eintrag als Nachweis.
      - 📎 Zusammenfassung: [Summary-Artefakt](https://github.com/<org>/<repo>/actions/runs/<run-id>#artifact:staging-soak-summary)

### Dual-Control-Workflow
- [ ] **Integrationstest-Logs verlinkt.** Hinterlege den Actions-Run des CI-Jobs
      `rpc-admission-audit` inklusive Step-Logs für `cargo test -p rpp-chain --locked --test admission`,
      damit Reviewer:innen den Durchlauf von `tests/network/admission_dual_control.rs` nachvollziehen können.【F:.github/workflows/ci.yml†L367-L376】【F:tests/network/admission_dual_control.rs†L1-L55】
      - 📎 CI-Log: [Actions-Run `rpc-admission-audit`](https://github.com/<org>/<repo>/actions/runs/<run-id>)
- [ ] **Audit-Einträge im Evidence-Log.** Exportiere die JSONL-Scheibe (`GET /p2p/admission/audit?limit=<n>`) direkt nach einer
      freigegebenen Änderung und verlinke sie gemeinsam mit dem Pending-/Approve-Flow, sodass beide Freigaben und die
      WORM-signierten Metadaten im Abnahmeprotokoll landen.【F:docs/network/admission.md†L60-L121】【F:rpp/p2p/src/policy_log.rs†L45-L194】
      - 📎 Audit-Artefakt: [Evidence-Export](https://storage.example.invalid/phase-b/admission-audit-<timestamp>.jsonl)
- [ ] **Runbooks verlinkt.** Hänge die aktualisierten
      [Admission-First-Action-Listen](./admission.md#first-action-checklisten)
      sowie den Incident-Pfad aus dem
      [Incident-Response-Playbook](./incident_response.md#dual-approval-eskalationen)
      an das Acceptance-Log, damit On-Call-Rotationen die Abläufe abrufen können.【F:docs/runbooks/admission.md†L17-L88】【F:docs/runbooks/incident_response.md†L74-L118】
      - 📎 Runbook-Abschnitte: [Admission First Action](./admission.md#first-action-checklisten), [Incident Response Escalation](./incident_response.md#dual-approval-eskalationen)

### Replay-Telemetrie & CLI
- [ ] **Replay-Telemetrie aktiv.** Dokumentiere, dass der Replay-Stream `snapshot_replay_*`
      im Observability-Stack sichtbar ist und Metriken/Alerts innerhalb der SLO-Schwellenwerte
      bleiben. Verlinke Dashboard-/Report-Screenshots aus dem Evidence-Paket.
      - 📎 Metrik-Bericht: [Grafana Export](https://grafana.example.invalid/d/<dashboard-id>?viewPanel=<panel-id>)
- [ ] **Replay-CLI-Checks protokolliert.** Hinterlege eine Session-Aufzeichnung von
      `rpp-node snapshot replay status` inklusive Exit-Code und Log-Ausschnitt sowie den zugehörigen
      CLI-Recorder-Upload aus dem Acceptance-Repo.
      - 📎 CLI-Transcript: [Replay-CLI Mitschnitt](https://storage.example.invalid/phase-b/replay-cli-<timestamp>.log)

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
- ✅ **Dual-Control-Tests bestanden.** Der CI-Job `rpc-admission-audit` muss mit grünem Status und vollständiger Artefaktsammlung (`tests/network/admission_dual_control.rs`) dokumentiert sein, inklusive Referenz auf das Evidence-Log.
- ✅ **Replay-Telemetrie & CLI aktiv.** Dashboard-Exports weisen Replay-Metriken nach, und die
  CLI-Session (`rpp-node snapshot replay status`) bestätigt erfolgreiche Runs ohne Fehlercodes.
- ✅ **Dokumentations-Updates verlinkt.** Alle Runbooks, Roadmap- und Weekly-Abschnitte mit Phase‑B-
  Belegen sind aktualisiert und im Acceptance-Log referenziert.【F:docs/roadmap_implementation_plan.md†L1-L120】【F:docs/status/weekly.md†L1-L120】
- ✅ **Artefakte versioniert verfügbar.** Die oben genannten JSON/Markdown-/Logdateien müssen in
  der Evidence-Sammlung oder als angehängte CI-Artefakte referenzierbar sein, sodass Reviewer:innen
  den Verlauf nachvollziehen können.

Sobald alle Kriterien erfüllt sind und die Nachweise konsistent verlinkt wurden, kann Phase B
formal abgenommen werden.

## Transparenz & Backlinks

- Verweise die abgeschlossene Checkliste im
  [Roadmap Implementation Plan](../roadmap_implementation_plan.md#phase-2-exit-criteria-arbeitsstand),
  damit das Projekttracking den Abschluss dokumentiert.【F:docs/roadmap_implementation_plan.md†L65-L121】
- Ergänze im [Weekly Status Report](../status/weekly.md#phase-2-fortschritt-kalenderwoche-382025)
  einen Hinweis auf die erfüllte Phase‑B-Checkliste einschließlich Links zu den Artefakten und
  Sign-off-Dokumenten.【F:docs/status/weekly.md†L1-L120】

## Reviewer-Unterschriften

| Rolle | Name | Datum | Unterschrift |
| --- | --- | --- | --- |
| Compliance Review | | | |
| Operations Review | | | |
| Security Review | | | |
