# Phase‑C Acceptance Checklist

Phase C bündelt die Betriebskontrollen für Langzeit-Retention, Evidenz-
Integrität sowie Chaos-Drills der Snapshot-Pipeline. Die folgenden Punkte
müssen vor dem Sign-off erfüllt und mit verlinkten Artefakten (Nightly-
Reports, Tickets, Runbooks) dokumentiert sein.

## Control Coverage

### WORM Retention Integrity

- [ ] **Nightly-Report geprüft.** Der aktuelle `worm_retention_report.json`
      (Actions-Artefakt `worm-export-smoke`) zeigt keine offenen
      `stale_entries`, `unsigned_entries` oder `retention_violations`.
      Abweichungen sind im Incident-Log dokumentiert und durch Gegenproben via
      `cargo xtask worm-retention-check --report <pfad>` adressiert. Verweise
      auf das Incident-Playbook
      ([„WORM-Retention-Check schlägt fehl“](./incident_response.md#worm-retention-check-schlägt-fehl))
      müssen beigefügt sein.
- [ ] **Bucket- und Schlüssel-Review abgeschlossen.** Storage Engineering hat
      die betroffenen WORM-Buckets (Region, Lifecycle-Policy, KMS-Key) gegen die
      Vorgaben im [WORM-Runbook](./worm_export.md) geprüft und etwaige Changes
      im Change-Log dokumentiert.

### Evidence Bundle Integrity

- [ ] **Manifest vollständig.** `phase3-evidence-<timestamp>/manifest.json`
      weist keine offenen `missing`-Einträge auf; `verify.log` bestätigt, dass
      Hash- und Signaturprüfungen erfolgreich waren. Verlinke den passenden
      Abschnitt im [Evidence Bundle Index](../governance/evidence_bundle_index.md).
- [ ] **Nightly-Reproduktion bestanden.** Ein manueller Lauf von
      `cargo xtask collect-phase3-evidence --output-dir <tmp>` spiegelt den
      Nightly-Inhalt; Abweichungen wurden im Incident-Log referenziert und
      geschlossen.

### Snapshot Chaos / Partition Drill

- [ ] **Nightly-Drill erfolgreich.** `snapshot_partition_report.json`
      (Artefakt `snapshot-partition`) hält `resume_latency_seconds` ≤ 120 s
      und `retry_chunks` ≤ 25 fest. Bei Überschreitungen liegen Incident-Eintrag
      und Recovery-Protokoll gemäß [Failover-Runbook](./network_snapshot_failover.md)
      vor.
- [ ] **Observability-Abgleich.** Prometheus/Grafana-Panels (`snapshot_stream_lag_seconds`,
      `snapshot_chunk_checksum_failures_total`) wurden für den Drill exportiert
      und mit dem Report abgeglichen.

## Exit Criteria

- [ ] **Incident-Playbook aktualisiert und verteilt.** Das aktualisierte
      [Incident Response Playbook](./incident_response.md#phase-c-kontrollen)
      wurde durch Compliance, Release Engineering und Security reviewed,
      im On-Call-Handbuch verlinkt und an die Rotationen kommuniziert
      (Changelog/Ticket oder Trainingsprotokoll anhängen).
- [ ] **Audit-Ticket geschlossen.** Das zentrale Phase‑C-Audit-Ticket enthält
      Links zu allen oben genannten Artefakten, inklusive Nightly-Runs und
      lokaler Gegenproben.
