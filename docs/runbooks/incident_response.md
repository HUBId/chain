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

### Pending/Freigabe/Ablehnung/Wiederherstellung

Stütze dich auf die vier Incident-Listen aus dem [Admission-Runbook](./admission.md#first-action-checklisten), wenn
die Eskalation konkret eine Pending-Queue, Freigabe, Ablehnung oder einen
Restore betrifft:

- [ ] **Pending-Approval:** `rpp-node validator admission pending list/show`
      laufen lassen, Diff/Screenshots ins Incident-Log legen und das Security-
      Team aktiv informieren.
- [ ] **Freigabe:** Vor der Approve-Entscheidung den Policy-Status prüfen
      (`admission status`), die Freigabe dokumentieren und Policies erneut
      exportieren.
- [ ] **Ablehnung:** Ablehnungsgrund via CLI im JSON-Format sichern, Alerts
      checken und Governance/Requester:innen informieren.
- [ ] **Wiederherstellung:** Audit-Slice und Backup erheben, Restore via CLI
      mit Dual-Approval durchführen, anschließend Signatur-Verify ausführen.

### Nächste Schritte

1. Fordere die fehlende Rolle zur Freigabe auf oder veranlasse einen
   [Backup-Restore mit vollständigen Approvals](./admission.md#backups-and-restores),
   falls die Änderung unzulässig ist.
2. Aktualisiere das Incident-Log mit dem endgültigen Audit-Eintrag (Erfolg oder
   Rollback) und hinterlege eine Kopie in der Phase‑3-Artefaktensammlung.
3. Eskaliere an das Governance/GRC-Team, wenn wiederholt Freigaben fehlen oder
   die Audit-Log-Kette unterbrochen erscheint.

## Snapshot-Verifier schlägt fehl

Release-Pipelines stoppen, sobald `cargo xtask snapshot-verifier` oder der
GitHub-Job `snapshot-verifier` Abweichungen im Aggregat-Report melden. Sammle
unmittelbar Belege und eskaliere gemäß folgender Kette:

**Eskalationskette & Ansprechpartner:innen**

1. **Release On-Call** (`#releng-oncall`, Telefon `+49 30 1234 5678`) – bestätigt
   die Fehlermeldung und blockiert weitere Promote-Jobs.
2. **Release Engineering Lead** (Mara Schulz, mara.schulz@example.com) –
   koordiniert Neuversuche und entscheidet über Rollback/Hotfix.
3. **Compliance Liaison** (Ishan Patel, ishpatel@example.com) – informiert Audit
   und prüft, ob Freigabefenster verschoben werden müssen.
4. **Security Duty** (sec-duties@example.com) – bewertet, ob Integrität der
   Snapshot-Artefakte kompromittiert ist und initiiert forensische Sicherung.

**Sofortmaßnahmen & CLI-Kommandos**

- [ ] Wiederhole die Aggregation lokal mit
      `cargo xtask snapshot-verifier` und sichere das Verzeichnis
      `target/snapshot-verifier-smoke/` als Zip-Anhang.
- [ ] Prüfe den produktiven Report mit
      `cargo xtask verify-report --report dist/artifacts/<target>/snapshot-verify-report.json`
      gegen das Schema `docs/interfaces/snapshot_verify_report.schema.json`.
- [ ] Führe `rpp-node validator snapshot verify --config <pfad>` gegen das
      zuletzt veröffentlichte Bundle aus, um Chunk-Abweichungen auszuschließen.

**Logs, Alerts & Artefakte**

- Exportiere die CI-Logs des Jobs `snapshot-verifier` (Actions → Job → "Download
  all logs") und hänge sie dem Incident-Log an.
- Sichere `target/snapshot-verifier-smoke/snapshot-verify-report.json` plus
  `.sha256`, sowie den neuesten Release-Report unter
  `dist/artifacts/<target>/snapshot-verify-report.json`.
- Dokumentiere Prometheus-Graph & Alert-Timeline von
  `SnapshotVerifierFailure` (`alerts/compliance_controls.yaml`).
- Hinterlege die CLI-Ausgaben (`stdout`/`stderr`) der oben genannten Kommandos
  im Incident-Log und im Phase‑A/Phase‑3 Evidenzordner.

## WORM-Export fehlerhaft

Ein Fehler im WORM-Pfad gefährdet die revisionssichere Audit-Trail-Aufbewahrung.
Typische Signale sind rote Nightly-Checks (`worm-export-smoke`) oder der Alert
`WormExportNightlyFailure`. Handhabe den Vorfall nach dieser Kette:

**Eskalationskette & Ansprechpartner:innen**

1. **Compliance On-Call** (`#compliance-oc`, Telefon `+49 30 9876 5432`) –
   stoppt Archiv-Freigaben und erfasst die ersten Artefakte.
2. **Storage Engineering** (Lead: Jin Park, jin.park@example.com) – analysiert
   Exporter-Logs und behebt Pipeline-/S3-Konfigurationsfehler.
3. **Network Operations** (net-ops@example.com) – überprüft Admission-Backups
   und stellt temporäre Backups bereit.
4. **Security Duty** (sec-duties@example.com) – bewertet Auswirkungen auf die
   Unveränderbarkeit und initiiert zusätzliche Logging/Retention-Checks.

**Sofortmaßnahmen & CLI-Kommandos**

- [ ] Führe `cargo xtask test-worm-export` aus und archiviere
      `target/worm-export-smoke/` mitsamt `worm-export-summary.json`.
- [ ] Sammle die Laufzeit-Logs aus dem Validator (`journalctl -u rpp-node --grep
      "worm export"`) sowie das Admission-Audit via
      `rpp-node validator admission backups download`.
- [ ] Falls das Produktivsystem betroffen ist, pausiere Exporte kurzfristig über
      den Betriebs-Workflow (z. B. `systemctl stop rpp-node`) nach Rücksprache mit
      Compliance und dokumentiere Uhrzeit sowie Ticket.

**Logs, Alerts & Artefakte**

- Lade die Nightly-Logs/Artefakte des Jobs `worm-export-smoke` herunter.
- Sichere die mit `test-worm-export` erzeugten Dateien (`audit.jsonl`,
  `worm/`, `retention.meta`, `worm-export-summary.json`).
- Dokumentiere den Alert-Verlauf `WormExportNightlyFailure` sowie die Metrik
  `worm_export_failures_total` in Prometheus/Grafana.
- Erfasse jede manuelle Stop/Start-Aktion des Validators (z. B.
  `systemctl stop|start rpp-node`) mit Timestamp im Incident-Log.
