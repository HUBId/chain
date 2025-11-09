# Phase‑C Acceptance Checklist

Phase C bündelt die Betriebskontrollen für Langzeit-Retention, Evidenz-
Integrität sowie Chaos-Drills der Snapshot-Pipeline. Die folgenden Punkte
müssen vor dem Sign-off erfüllt und mit verlinkten Artefakten (Nightly-
Reports, Tickets, Runbooks) dokumentiert sein.

## Control Coverage

### WORM Retention Integrity

- [x] **Nightly-Report geprüft.** Der aktuelle `worm_retention_report.json`
      (Actions-Artefakt `worm-export-smoke`) zeigt keine offenen
      `stale_entries`, `unsigned_entries` oder `retention_violations`.
      Abweichungen sind im Incident-Log dokumentiert und durch Gegenproben via
      `cargo xtask worm-retention-check --report <pfad>` adressiert. Nachweis:
      [Phase‑C WORM-Retention Nachweis (Nightly 2026-08-21)](../status/phaseC_retention_summary.md).
      Verweise auf das Incident-Playbook
      ([„WORM-Retention-Check schlägt fehl“](./incident_response.md#worm-retention-check-schlägt-fehl))
      müssen beigefügt sein.
- [ ] **Telemetry-Panel grün.** Dashboard
      [`Compliance Overview`](../dashboards/compliance_overview.json) zeigt
      `increase(worm_retention_checks_total[24h]) ≥ 1` und
      `increase(worm_retention_failures_total[24h]) = 0`. Bei Abweichungen liegt
      ein Pager-Eintrag (Alert „WormRetentionNightlyFailure“ bzw.
      „WormRetentionNightlyMissing“) samt Incident-Referenz vor.
- [ ] **Bucket- und Schlüssel-Review abgeschlossen.** Storage Engineering hat
      die betroffenen WORM-Buckets (Region, Lifecycle-Policy, KMS-Key) gegen die
      Vorgaben im [WORM-Runbook](./worm_export.md) geprüft und etwaige Changes
      im Change-Log dokumentiert.

### Evidence Bundle Integrity

- [ ] **Manifest vollständig.** `phase3-evidence-<timestamp>/manifest.json`
      weist keine offenen `missing`-Einträge auf und führt für jede Datei einen
      `sha256`-Eintrag (`files[*].sha256`). Nach dem Lauf von
      `cargo xtask collect-phase3-evidence` ist die Manifest-Prüfsumme (Konsole)
      zu notieren und mit dem `manifest.json` im Bundle abzugleichen.
      Verlinke den passenden Abschnitt im
      [Evidence Bundle Index](../governance/evidence_bundle_index.md).
- [ ] **Integritätsscan bestanden.** `cargo xtask collect-phase3-evidence`
      validiert `manifest.json` gegen
      `docs/governance/phase3_evidence_manifest.schema.json` und vergleicht die
      `sha256`-Hashes mit den kopierten Dateien. Abweichungen führen zu einem
      Abbruch mit Fehlermeldung – der Lauf darf nur mit "phase3 evidence bundle
      created" und angezeigter Manifest-Prüfsumme enden.
- [ ] **Nightly-Reproduktion bestanden.** Ein manueller Lauf von
      `cargo xtask collect-phase3-evidence --output-dir <tmp>` spiegelt den
      Nightly-Inhalt; Abweichungen wurden im Incident-Log referenziert und
      geschlossen.
- [x] **Phase‑C-Artefakte enthalten.** Der WORM-Retention-Report liegt unter
      `worm-export/.../worm-retention-report.json`, die Snapshot-Manifestsignaturen
      unter `snapshot-signatures/`, und Chaos- bzw. Partition-Reports unter
      `chaos-reports/` innerhalb des Bundles vor. Fehlende Artefakte sind zu
      dokumentieren und nachzuliefern. Konsolidierter Status: Abschnitt
      „Phase‑C Kontrollen (Nightly)“ im Weekly-Report prüfen; ⚠️/❌ markierte
      Zeilen erfordern eine Nachlieferung (erneuter `cargo xtask
      worm-retention-check` bzw. Chaos-Drill) bevor der Check als bestanden
      gilt. Nachweis: Evidence-Bundle `phase3-evidence/nightly-2026-08-21/phase3-evidence-2026-08-21T09-00-42Z.tar.gz`
      listet SLO-Summary, Replay-Telemetrie, WORM-Retention-Report und Chaos-Report
      mit konsistenten SHA256-Werten im Manifest.【F:docs/status/weekly.md†L1-L50】【F:scripts/update_nightly_status.py†L1-L360】【F:docs/status/artifacts/phase3_evidence_bundle_2026-08-21.json†L2-L29】

### Admission Policy Reconciliation

- [x] **Admission-Reconciliation läuft grün.** Nightly-Reports bestätigen, dass
      der Policy-Drift-Check ohne Abweichungen läuft; verlinke die jüngste
      Telemetrie sowie den Audit-Export (`admission-reconciler` ➜
      `drift_detected=false`).【F:logs/admission_reconciler_2026-08-21.jsonl†L1-L3】【F:logs/admission_reconciliation_audit_2026-08-21.jsonl†L1-L1】
      Referenz: [Nightly Reports](../../nightly_status.md).

### Snapshot Chaos / Partition Drill

- [ ] **Nightly-Drill erfolgreich.** `snapshot_partition_report.json`
      (Artefakt `snapshot-partition`) hält `resume_latency_seconds` ≤ 120 s
      und `retry_chunks` ≤ 25 fest. Bei Überschreitungen liegen Incident-Eintrag
      und Recovery-Protokoll gemäß [Failover-Runbook](./network_snapshot_failover.md)
      vor.
- [ ] **Observability-Abgleich.** Prometheus/Grafana-Panels (`snapshot_stream_lag_seconds`,
      `snapshot_chunk_checksum_failures_total`) wurden für den Drill exportiert
      und mit dem Report abgeglichen. Der Report wird automatisch als
      `chaos-reports/snapshot_partition_report.json` ins Phase‑C-Bundle kopiert;
      prüfe bei manuellen Läufen die hinterlegte Prüfsumme im Manifest.
- [ ] **Chaos-Metriken sichtbar.** Dashboard
      [`Snapshot Resilience`](../dashboards/snapshot_resilience.json) zeigt
      `increase(snapshot_chaos_runs_total[7d]) ≥ 1` sowie
      `increase(snapshot_chaos_failures_total[7d]) = 0`. Alerts
      „SnapshotChaosNightlyFailure“/„SnapshotChaosNightlyMissing“ sind entweder
      geschlossen oder mit Incident-Verweis dokumentiert.

### Snapshot/Timetoke Replay SLO Monitoring

- [x] **Snapshot/Timetoke SLO ≥ 14 Tage erfüllt.** Der konsolidierte Export
      [`docs/status/phaseC_slo_summary.md`](../status/phaseC_slo_summary.md)
      (Beobachtungszeitraum 2026-08-08 – 2026-08-21) dokumentiert, dass alle
      Snapshot-Health-Checks und Timetoke-Replay-SLOs im aktuellen 14‑Tage-
      Zeitraum ohne Grenzwertverletzungen bestanden wurden (Snapshot-Sessions
      vollständig verifiziert, Erfolgsquote ≥ 99 %, Latenzen innerhalb der
      definierten p50/p95/p99-Ziele). Abweichungen müssen über das Incident-Log
      adressiert und erneut über den Export bestätigt werden.
- [x] **Replay-Defense-Telemetrie geprüft.** `timetoke_replay_success_rate` und
      `timetoke_replay_stalled_final{threshold}` werden über Dashboard/Report
      abgerufen; `rpp-node snapshot replay status` bestätigt die finalen Kennzahlen
      (Erfolgsrate, Stalled-Detector). Nachweis im Incident-/Audit-Log, Stand
      2026‑08‑19.

## Exit Criteria

- [x] **WORM-Verifikation sign-off.** Die jüngste `worm-retention-report.json`
      ist im Phase‑C-Evidence-Bundle hinterlegt und durch Storage Engineering
      per Gegenprobe (`cargo xtask worm-retention-check`) abgezeichnet. Das
      Audit-Ticket enthält den Link zum Report sowie die Bestätigung, dass alle
      Abweichungen laut Incident-Log geschlossen wurden. Nachweis: [Phase‑C
      WORM-Retention Nachweis (Nightly 2026-08-21)](../status/phaseC_retention_summary.md).
- [ ] **Evidence-Bundle freigegeben.** Das aktuelle Paket
      `phase3-evidence-<timestamp>` liegt im Artefakt-Archiv, Manifest und
      Prüfsumme wurden im Audit-Ticket dokumentiert und der
      [Evidence Bundle Index](../governance/evidence_bundle_index.md) verweist
      auf die Phase‑C-Artefakte (`worm-export/`, `snapshot-signatures/`,
      `chaos-reports/`).
- [ ] **Chaos-Test-Auswertung dokumentiert.** Die Ergebnisse des jüngsten
      `snapshot_partition_report.json` (Nightly oder manueller Drill) wurden mit
      Prometheus-/Grafana-Exports abgeglichen und im Incident-Log referenziert.
      Recovery-Maßnahmen aus etwaigen Abweichungen sind geschlossen, bevor der
      Sign-off erfolgt.
- [x] **Incident-Playbook aktualisiert und verteilt.** Das aktualisierte
      [Incident Response Playbook](./incident_response.md#phase-c-kontrollen)
      wurde durch Compliance, Release Engineering und Security reviewed,
      im On-Call-Handbuch verlinkt und an die Rotationen kommuniziert
      (Changelog/Ticket oder Trainingsprotokoll anhängen). Review vom
      21. Aug 2026 bestätigt die finalen Verweise auf Evidence-Bundle und
      Nightly-Artefakte.【F:docs/runbooks/incident_response.md†L201-L254】
- [ ] **Audit-Ticket geschlossen.** Das zentrale Phase‑C-Audit-Ticket enthält
      Links zu allen oben genannten Artefakten, inklusive Nightly-Runs und
      lokaler Gegenproben.
