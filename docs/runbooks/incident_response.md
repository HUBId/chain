# Incident Response Playbook

Dieses Playbook ergänzt das [On-Call-Handbuch](./oncall.md) und die
[Phase‑3 Acceptance Checklist](./phase3_acceptance.md), wenn ein Incident eine
sofortige Reaktion auf Snapshot-Checksummen, Admission-Drift oder Dual-Control-
Genehmigungen verlangt. Jede Sektion beginnt mit einer "First Action"-Checkliste,
die die wichtigsten CLI-Aufrufe, Dashboards und Audit-Trails verlinkt, damit
Auditor:innen die Dokumentation lückenlos nachverfolgen können.

Für Replay-Störungen in der Timetoke-Pipeline verweist dieses Playbook auf das
[Timetoke-Failover-Runbook](./timetoke_failover.md), das Detection-Signale,
Recovery-Schritte und Troubleshooting-Tipps für die Wiederanbindung der
Snapshot-Kette bündelt.

## Timetoke Replay Stall

### First Action Checklist

- [ ] **Alert bestätigen:** Quittiere `TimetokeReplayLatencySLOBreach` oder `TimetokeReplayStalled` und vermerke die Alert-ID im Incident-Log.
- [ ] **Dashboards sichern:** Exportiere die Prometheus- oder Grafana-Panels für `timetoke_replay_duration_ms` und `timetoke_replay_success_total`.
- [ ] **CLI-Verifikation:** Führe `cargo xtask report-timetoke-slo --metrics-log <pfad>` oder den passenden Prometheus-Aufruf aus und hänge den Output an das Ticket.
- [ ] **Exporter-Health:** Prüfe `systemctl status timetoke-exporter` (oder den zuständigen Supervisor) und sichere Journal-Einträge.

### Nächste Schritte

1. Vergleiche die Alert-Timestamps mit aktuellen Deployments oder Konfigurationsänderungen in der Replay-Pipeline.
2. Folge den Failover-Schritten im [Timetoke-Failover-Runbook](./timetoke_failover.md), falls Replays weiterhin ausstehen oder sich die Latenz nicht normalisiert.
3. Dokumentiere Workarounds, Recovery-Schritte und verlinkte Dashboards im Incident-Log, bevor du den Dienst wieder in die Acceptance-Pipeline einbindest.

## Einsatzvorbereitung

1. Aktualisiere das Incident-Ticket mit Uhrzeit, Alert-ID und Host, bevor du eine
   der Checklisten startest.
2. Öffne das zentrale Incident-Log (Standard: `oncall/incident_log.md`) und
   protokolliere jeden Schritt aus den Checklisten.
3. Halte RPC-Token und Validator-Konfigurationspfad bereit, sodass CLI-Befehle
   (`rpp-node ...`) ohne erneute Authentifizierung ausgeführt werden können.

## Snapshot-Checksum-Fehler

Eine Warnung wie `snapshot chunk validation failed` oder ein Anstieg von
`snapshot_chunk_checksum_failures_total{kind="checksum_mismatch"}` signalisiert
lokale Korruption. Folge diesen Erstmaßnahmen, bevor du Streams neu startest oder
Peer-Wechsel einleitest.

### First Action Checklist

- [ ] **CLI:** Erfasse den Session-Status über
      [`rpp-node validator snapshot status`](./network_snapshot_failover.md#step-1--verify-control-plane-health)
      und sichere den Output im Incident-Log.
- [ ] **Dashboards:** Öffne die [Snapshot- & Light-Client-Metriken](../observability/pipeline.md#snapshot--light-client-sync-metrics)
      und exportiere die Panels für `snapshot_stream_lag_seconds`,
      `snapshot_bytes_sent_total` sowie `light_client_chunk_failures_total`.
- [ ] **Audit-Log:** Exportiere die `snapshot_validator`-Warnungen mit
      `journalctl -u rpp-node -t snapshot_validator` und hänge den Export an die
      Artefaktensammlung für die
      [Phase‑3-Beweislage](./phase3_acceptance.md#snapshot-slis--replay-evidenz).

### Nächste Schritte

1. Prüfe das lokale Manifest und Chunk-Verzeichnis wie in der
   [Background Chunk Validation](../network/snapshots.md#background-chunk-validation)
   beschrieben. Ersetze beschädigte Dateien aus einem sauberen Snapshot oder
   fordere einen frischen Export beim Peer an.
2. Nutze das [Failover-Runbook](./network_snapshot_failover.md) für Resume-
   Versuche oder Peer-Wechsel. Wiederhole die Checkliste nach jedem Eingriff.
3. Dokumentiere Recovery, neue Checksummen sowie Dashboard-Screenshots im
   Incident-Log und verknüpfe sie mit dem entsprechenden Phase‑3-Checklisteneintrag.

## Tier-Policy-Drift erkennen

Policy-Drift-Alerts (`rpp.node.admission.policy_drift_detected_total`) deuten auf
Abweichungen zwischen Live-Policies, Persistenz und Audit-Log hin. Sichere die
Belege, bevor du Änderungen akzeptierst oder zurückrollst.

### First Action Checklist

- [ ] **CLI:** Ziehe den aktuellen Stand mit
      [`GET /p2p/admission/policies`](../runbooks/observability.md#admission-audit-abfragen)
      oder `rpp-node validator admission backups download` und lege den Dump im
      Incident-Log ab.
- [ ] **Dashboards:** Kontrolliere die Admission-Metriken im
      [Pipeline-Dashboard](../observability/pipeline.md#snapshot--light-client-sync-metrics)
      sowie spezifische Drift-Panels (`policy_drift_detected_total`) gemäß dem
      [Admission-Runbook](./admission.md#reconciliation-checks).
- [ ] **Audit-Log:** Paginierte Exporte aus
      [`GET /p2p/admission/audit`](../runbooks/observability.md#admission-audit-abfragen)
      sichern, um fehlende oder widersprüchliche Einträge hervorzuheben.

### Nächste Schritte

1. Vergleiche Policy-Dumps mit dem auf Disk konfigurierten Pfad
   (`network.admission.policy_path`) und führe bei Abweichungen einen Restore
   über die [Backup-CLI](./admission.md#backups-and-restores) durch.
2. Hält Drift trotz Restore an, stoppe Admission-Änderungen und eskaliere an das
   Security-Team mit Hinweis auf die betroffenen Audit-Einträge.
3. Verknüpfe Dumps, Audit-Exports und Dashboard-Screenshots mit der
   [Phase‑3-Checkliste](./phase3_acceptance.md#tier-admission-persistenz--audit).

## Dual-Approval-Eskalationen

Fehlende Zweitfreigaben bei `POST /p2p/admission/policies` oder Restore-Vorgängen
lösen Audit-Alerts aus und erfordern unmittelbare Abstimmung mit den
Genehmigenden. Nutze die folgenden Schritte, um Nachweise zu sichern und den
Rollback vorzubereiten.

### First Action Checklist

- [ ] **CLI:** Wiederhole die Anfrage mit `--dry-run` oder `--approval`-Flags über
      die [Admission-CLI](./admission.md#dual-approval-workflow), um die fehlende
      Rolle zu identifizieren und die Payload im Incident-Log zu speichern.
- [ ] **Dashboards:** Überwache `rpp.node.admission.approval_missing_total` und
      verwandte Panels in den [Admission-Dashboards](../observability/pipeline.md#snapshot--light-client-sync-metrics)
      für weitere Fehlversuche.
- [ ] **Audit-Log:** Ziehe den entsprechenden Eintrag via
      [`GET /p2p/admission/audit?offset=0&limit=50`](../runbooks/observability.md#admission-audit-abfragen)
      sowie das zugehörige Ticket/Change-Request-Protokoll.

### Nächste Schritte

1. Fordere die fehlende Rolle zur Freigabe auf oder veranlasse einen
   [Backup-Restore mit vollständigen Approvals](./admission.md#backups-and-restores),
   falls die Änderung unzulässig ist.
2. Aktualisiere das Incident-Log mit dem endgültigen Audit-Eintrag (Erfolg oder
   Rollback) und hinterlege eine Kopie in der Phase‑3-Artefaktensammlung.
3. Eskaliere an das Governance/GRC-Team, wenn wiederholt Freigaben fehlen oder
   die Audit-Log-Kette unterbrochen erscheint.
